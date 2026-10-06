// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	collectorSchema = "prufyx.io/kubeconfig-api-observation/v1alpha1"
	indexSchema     = "prufyx.io/kubeconfig-api-observation-index/v1alpha1"
	requestTimeout  = 30 * time.Second
	crdPageBudget   = 120 * time.Second
)

// Options is the complete collection authority. Contexts and environment
// names are caller declarations; their raw values never enter output files.
type Options struct {
	OutputRoot                    string
	Kubeconfig                    string
	Contexts                      []string
	IncludePodStatusImages        bool
	IncludeComponentConfiguration bool
	ComponentConfigurationProfile string
	AllowPartial                  bool
	AcknowledgeExecRisk           bool
	ExecEnv                       []string
	Kubectl                       string
	Now                           func() time.Time
	Random                        io.Reader
	kubeconfigSnapshot            []byte
}

type Collector struct{ Runner Runner }

type omission struct{ Name, Code, Reason string }

type contextIndex struct {
	Directory        string `json:"directory"`
	ContextHash      string `json:"contextHash"`
	CollectionStatus string `json:"collectionStatus"`
	OmissionCount    int    `json:"omissionCount"`
}

type query struct {
	name string
	args []string
}

var baseQueries = []query{
	{"server-version.json", []string{"get", "--raw=/version"}},
	{"node-profiles.json", []string{"get", "nodes", "--chunk-size=200", "-o", "json"}},
	{"deployment-images.json", []string{"get", "deployments.apps", "--all-namespaces", "--chunk-size=200", "-o", "json"}},
	{"daemonset-images.json", []string{"get", "daemonsets.apps", "--all-namespaces", "--chunk-size=200", "-o", "json"}},
	{"statefulset-images.json", []string{"get", "statefulsets.apps", "--all-namespaces", "--chunk-size=200", "-o", "json"}},
	{"replicaset-images.json", []string{"get", "replicasets.apps", "--all-namespaces", "--chunk-size=200", "-o", "json"}},
	{"job-images.json", []string{"get", "jobs.batch", "--all-namespaces", "--chunk-size=200", "-o", "json"}},
	{"cronjob-images.json", []string{"get", "cronjobs.batch", "--all-namespaces", "--chunk-size=200", "-o", "json"}},
	{"replicationcontroller-images.json", []string{"get", "replicationcontrollers", "--all-namespaces", "--chunk-size=200", "-o", "json"}},
	{"aggregated-apis.json", []string{"get", "apiservices.apiregistration.k8s.io", "--chunk-size=200", "-o", "json"}},
	{"mutating-webhooks.json", []string{"get", "mutatingwebhookconfigurations.admissionregistration.k8s.io", "--chunk-size=200", "-o", "json"}},
	{"validating-webhooks.json", []string{"get", "validatingwebhookconfigurations.admissionregistration.k8s.io", "--chunk-size=200", "-o", "json"}},
	{"admission-policy-surface.json", []string{"get", "validatingadmissionpolicies.admissionregistration.k8s.io", "--chunk-size=200", "-o", "json"}},
	{"admission-policy-bindings.json", []string{"get", "validatingadmissionpolicybindings.admissionregistration.k8s.io", "--chunk-size=200", "-o", "json"}},
	{"storage-surface.json", []string{"get", "storageclasses.storage.k8s.io", "--chunk-size=200", "-o", "json"}},
	{"csi-driver-surface.json", []string{"get", "csidrivers.storage.k8s.io", "--chunk-size=200", "-o", "json"}},
	{"runtime-classes.json", []string{"get", "runtimeclasses.node.k8s.io", "--chunk-size=200", "-o", "json"}},
	{"core-api-versions.json", []string{"get", "--raw=/api"}},
	{"grouped-api-versions.json", []string{"get", "--raw=/apis"}},
}

// Collect writes one private directory per declared context. It returns only
// bounded status messages; kubeconfig, context, kubectl argv and API bytes are
// never written to stdout or stderr.
func (c Collector) Collect(ctx context.Context, opts Options, stdout, stderr io.Writer) (string, int) {
	if err := validateOptions(&opts); err != nil {
		fmt.Fprintln(stderr, err)
		return "", 2
	}
	defer wipeKubeconfigBytes(opts.kubeconfigSnapshot)
	if c.Runner == nil {
		c.Runner = ExecRunner{Binary: opts.Kubectl}
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(opts.Random, key); err != nil {
		fmt.Fprintln(stderr, "Failed to create the per-run context pseudonym key.")
		return "", 2
	}
	now := opts.Now().UTC().Truncate(time.Second)
	runDir, err := os.MkdirTemp(opts.OutputRoot, "kubeconfig-api-snapshot-"+now.Format("20060102T150405Z")+".")
	if err != nil {
		fmt.Fprintln(stderr, "Cannot create private observation directory.")
		return "", 2
	}
	if err := os.Chmod(runDir, 0o700); err != nil {
		_ = os.RemoveAll(runDir)
		fmt.Fprintln(stderr, "Cannot make the observation directory private.")
		return "", 2
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(runDir)
		}
	}()
	snapshot, removeSnapshot, err := createKubeconfigSnapshot(opts.kubeconfigSnapshot)
	if err != nil {
		fmt.Fprintln(stderr, "Cannot create a private kubeconfig snapshot.")
		return "", 2
	}
	snapshotRemoved := false
	defer func() {
		if !snapshotRemoved {
			_ = removeSnapshot()
		}
	}()
	opts.Kubeconfig = snapshot
	env, err := collectorEnvironment(snapshot, opts.ExecEnv)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return "", 2
	}

	adapter, err := loadAdapterAssets(opts.ComponentConfigurationProfile)
	if err != nil {
		fmt.Fprintln(stderr, "Embedded component adapter contract is invalid.")
		return "", 2
	}
	indexes := make([]contextIndex, 0, len(opts.Contexts))
	histogram := map[string]int{}
	totalOmissions, totalReads, failedReads := 0, 0, 0

	for i, contextName := range opts.Contexts {
		dirName := fmt.Sprintf("%03d", i)
		dir := filepath.Join(runDir, dirName)
		if err := os.Mkdir(dir, 0o700); err != nil {
			fmt.Fprintln(stderr, "Cannot create private context directory.")
			return "", 2
		}
		ctxHash := contextDigest(key, contextName)
		fmt.Fprintf(stdout, "Context %s (%s)\n", dirName, ctxHash)
		omissions := []omission{}
		configuration := []any{}
		componentOmissions := []any{}
		certManagerSeen := false
		var discoveredGroups map[string]bool

		for _, q := range baseQueries {
			totalReads++
			root, _, code := c.read(ctx, env, opts, contextName, q.args)
			if code != "" {
				failedReads++
				addOmission(&omissions, q.name, code)
				histogram[code]++
				if isWorkload(q.name) && opts.IncludeComponentConfiguration {
					componentOmissions = append(componentOmissions, componentFailure(q.name, code))
				}
				continue
			}

			if isWorkload(q.name) {
				payload, err := projectWorkload(root, adapter, opts.ComponentConfigurationProfile, now)
				if err != nil {
					addOmission(&omissions, q.name, "projection_filter_rejected")
					histogram["projection_filter_rejected"]++
					if opts.IncludeComponentConfiguration {
						componentOmissions = append(componentOmissions, componentFailure(q.name, "projection_filter_rejected"))
					}
					continue
				}
				images, _ := payload["publicImages"].([]any)
				if images == nil {
					images = []any{}
				}
				if err := writeJSON(filepath.Join(dir, q.name), images); err != nil {
					fmt.Fprintln(stderr, "Cannot write private projected output.")
					return "", 2
				}
				if opts.IncludeComponentConfiguration {
					configuration, componentOmissions = addWorkloadConfiguration(configuration, componentOmissions, payload, q.name)
					for _, image := range images {
						if at(image, "componentId") == "pkg:oci/cert-manager/cert-manager" {
							certManagerSeen = true
						}
					}
				}
				continue
			}

			projected, err := project(q.name, root)
			if err != nil {
				addOmission(&omissions, q.name, "projection_filter_rejected")
				histogram["projection_filter_rejected"]++
				continue
			}
			if q.name == "grouped-api-versions.json" {
				discoveredGroups = groupSet(projected)
			}
			if err := writeJSON(filepath.Join(dir, q.name), projected); err != nil {
				fmt.Fprintln(stderr, "Cannot write private projected output.")
				return "", 2
			}
		}

		if opts.IncludePodStatusImages {
			totalReads++
			if c.capturePodStatus(ctx, env, opts, contextName, dir, adapter, &omissions, histogram) {
				failedReads++
			}
		}
		totalReads++
		if c.captureCRDs(ctx, env, opts, contextName, dir, &omissions, histogram) {
			failedReads++
		}

		if opts.IncludeComponentConfiguration {
			if certManagerSeen {
				reads, failures := c.captureCertManager(ctx, env, opts, contextName, dir, discoveredGroups, &omissions, histogram, &configuration, &componentOmissions)
				totalReads += reads
				failedReads += failures
			}
			surface := aggregateComponents(adapter, opts.ComponentConfigurationProfile, configuration, componentOmissions)
			if err := writeJSON(filepath.Join(dir, "component-configuration-surface.json"), surface); err != nil {
				fmt.Fprintln(stderr, "Cannot write component surface.")
				return "", 2
			}
		}

		if err := writeOmissions(filepath.Join(dir, "omissions.tsv"), omissions); err != nil {
			fmt.Fprintln(stderr, "Cannot write omission report.")
			return "", 2
		}
		status := "complete_for_declared_surface"
		if len(omissions) > 0 {
			status = "partial_for_declared_surface"
		}
		if err := writeJSON(filepath.Join(dir, "snapshot-metadata.json"), observationMetadata(now, ctxHash, status, len(omissions), opts, adapter)); err != nil {
			fmt.Fprintln(stderr, "Cannot write observation metadata.")
			return "", 2
		}
		if err := writeManifest(dir); err != nil {
			fmt.Fprintln(stderr, "Cannot write context manifest.")
			return "", 2
		}
		indexes = append(indexes, contextIndex{dirName, ctxHash, status, len(omissions)})
		totalOmissions += len(omissions)
	}

	if err := removeSnapshot(); err != nil {
		fmt.Fprintln(stderr, "Cannot remove the private kubeconfig snapshot.")
		return "", 2
	}
	snapshotRemoved = true
	if err := writeJSON(filepath.Join(runDir, "index.json"), map[string]any{
		"schema": indexSchema, "generatedAt": now.Format(time.RFC3339), "contexts": indexes,
	}); err != nil {
		fmt.Fprintln(stderr, "Cannot write observation index.")
		return "", 2
	}
	if err := writeManifest(runDir); err != nil {
		fmt.Fprintln(stderr, "Cannot write run manifest.")
		return "", 2
	}
	complete = true
	fmt.Fprintf(stdout, "Created local API observation directory: %s\n", runDir)
	fmt.Fprintf(stdout, "Verify context files with: (cd %s && shasum -a 256 -c MANIFEST.sha256)\n", runDir)
	fmt.Fprintf(stderr, "Failure histogram: kubernetes_api_read_failed=%d strict_json_rejected=%d projection_filter_rejected=%d pipeline_failed=%d\n", failedReads, histogram["strict_json_rejected"], histogram["projection_filter_rejected"], histogram["pipeline_failed"])
	if totalReads > 0 && failedReads == totalReads {
		fmt.Fprintln(stderr, "WARNING: all declared API reads failed; check the reviewed kubeconfig endpoint, authentication, and read-only RBAC.")
	}
	if totalOmissions > 0 && !opts.AllowPartial {
		fmt.Fprintf(stderr, "The observation is partial: %d declared reads were unavailable or invalid.\n", totalOmissions)
		return runDir, 6
	}
	if totalOmissions > 0 {
		fmt.Fprintf(stderr, "WARNING: partial observation accepted by --allow-partial; omission count: %d.\n", totalOmissions)
	}
	return runDir, 0
}

func (c Collector) read(ctx context.Context, env []string, opts Options, contextName string, args []string) (any, CommandResult, string) {
	return c.readWithTimeout(ctx, env, opts, contextName, args, requestTimeout)
}

func (c Collector) readWithTimeout(ctx context.Context, env []string, opts Options, contextName string, args []string, timeout time.Duration) (any, CommandResult, string) {
	result, err := c.runQuery(ctx, env, opts, contextName, args, timeout)
	if err != nil || result.Exit != 0 {
		return nil, result, failureFromResult(result, err)
	}
	root, err := DecodeStrict(result.Stdout)
	if err != nil {
		return nil, result, "strict_json_rejected"
	}
	return root, result, ""
}

func (c Collector) runQuery(ctx context.Context, env []string, opts Options, contextName string, args []string, timeout time.Duration) (CommandResult, error) {
	argv := []string{"--kubeconfig", opts.Kubeconfig, "--context", contextName, "--request-timeout=30s"}
	argv = append(argv, args...)
	return c.Runner.Run(ctx, argv, env, timeout)
}

func validateOptions(o *Options) error {
	if o.ComponentConfigurationProfile == "" {
		o.ComponentConfigurationProfile = "v2"
	}
	if o.ComponentConfigurationProfile != "v2" && o.ComponentConfigurationProfile != "v3" {
		return errors.New("Unsupported component configuration profile.")
	}
	if o.OutputRoot == "" || o.Kubeconfig == "" || len(o.Contexts) == 0 {
		return errors.New("Output, kubeconfig, and at least one context are required.")
	}
	if !o.AcknowledgeExecRisk {
		return errors.New("Refusing to use kubeconfig without --acknowledge-kubeconfig-exec-risk. Review the file first: kubectl may execute authentication helpers declared in it.")
	}
	if o.IncludeComponentConfiguration && o.IncludePodStatusImages {
		return errors.New("Refusing --include-pod-status-images with --include-component-configuration.")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Random == nil {
		o.Random = rand.Reader
	}
	return validateLocalPathsAndTools(o)
}

func addWorkloadConfiguration(configuration, omissions []any, payload map[string]any, sourceFile string) ([]any, []any) {
	if rows, ok := payload["configuration"].([]any); ok {
		if len(configuration)+len(rows) <= 10000 {
			configuration = append(configuration, rows...)
		} else {
			omissions = append(omissions, componentFailure(sourceFile, "output_limit_exceeded"))
		}
	}
	if rows, ok := payload["omissions"].([]any); ok {
		for _, row := range rows {
			if m, ok := object(row); ok {
				m["sourceFile"] = sourceFile
				omissions = append(omissions, m)
			}
		}
	}
	return configuration, omissions
}
