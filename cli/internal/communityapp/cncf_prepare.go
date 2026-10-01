// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/currentbundle"
)

func (r runtime) prepareCNCF(args []string) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, `Usage: prufyx prepare cncf --project kyverno --input FILE --container NAME --from VERSION --to VERSION [--distribution official_upstream|custom_build] [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project linkerd --input FILE --from 2.13.7 --to 2.14.0 [--distribution official_upstream|custom_build] [--schema-validation required|disabled] [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project karmada --input FILE --from 1.18.3 --to 1.19.0 [--distribution official_upstream|custom_build] [--target-policy-crd-admission required|disabled] [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project argo-cd --input FILE --from 2.14.0 --to 3.0.0 [--requires-inherited-application-permissions true|false] [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project argo-cd --input FILE --from 3.0.23|3.1.16|3.2.12|3.3.14|3.4.8 --to 3.5.2 --distribution official_upstream|custom_build --repository-settings-resolved true|false --repository-uses-plain-http true|false [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project cilium --input FILE --from 1.18.6 --to 1.19.0 [--complete-cnp-ccnp-set true|false] [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project cilium --input FILE --from 1.18.13 --to 1.19.7 [--complete-cnp-ccnp-set true|false] [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project cilium --cilium-config-map FILE --from 1.16.19 --to 1.17.18 --cilium-distribution official_upstream|custom_build --cilium-config-complete --cilium-config-precedence-resolved [--cilium-config-map-digest SHA256] [--format human|json|input]
	 or: prufyx prepare cncf --project coredns --coredns-corefile FILE --from 1.6.9 --to 1.7.0 or 1.9.4|1.10.1|1.11.4|1.12.4|1.13.2 --to 1.14.7 --coredns-distribution official --coredns-corefile-complete [--coredns-corefile-digest SHA256] [--format human|json|input]
	 or: prufyx prepare cncf --project envoy --envoy-bootstrap FILE --envoy-bootstrap-selected --from 1.34.14|1.35.13|1.36.10|1.37.6|1.38.4 --to 1.39.1 [--envoy-bootstrap-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project spire --spire-entry-argv FILE --from 1.10.4 --to 1.11.0 --spire-distribution official_upstream|custom_build [--spire-entry-argv-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project keda --keda-scaled-object FILE --from 2.16.0 --to 2.17.0 --keda-scaled-object-complete [--keda-legacy-tls-transport-required true|false] [--keda-scaled-object-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project kubernetes --input FILE --from 1.31.0 --to 1.32.0 --distribution official_upstream|custom_build --target-api-apply-required --resource-scope-complete [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project strimzi --kafka-resource FILE --from 0.51.0 --to 1.0.0 --strimzi-distribution official_upstream|custom_build --target-kafka-crd-admission-required [--kafka-resource-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project falco --falco-argv FILE --from 0.40.0 --to 0.41.0|0.42.0 --falco-distribution official_upstream|custom_build [--falco-argv-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project kuma --kumactl-argv FILE --from 2.8.0 --to 2.9.0 --kuma-distribution official_upstream|custom_build [--kumactl-argv-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project crossplane --composition FILE --from 1.20.0 --to 2.0.0 --crossplane-distribution official_upstream|custom_build --crossplane-schema-validation-required [--composition-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project velero --upgrade-plan FILE --from 1.17.0|1.16.2 --to 1.18.0 --velero-server-deployment NAME --velero-plan-order-declared [--upgrade-plan-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project etcd --input FILE --from 3.5.17 --to 3.6.0 [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project jaeger --input FILE --from 1.76.0 --to 2.20.0 [--non-memory-storage-required true|false] [--official-jaeger-distribution true|false] [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project metallb|contour --input FILE --from VERSION --to VERSION [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project cloudnativepg --input FILE --from 1.29.0 --to 1.30.0 [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project kubevirt --input FILE --from 1.8.4 --to 1.9.0 [--input-digest SHA256] [--format human|json|input]
	   or: prufyx prepare cncf --project emissary-ingress --input FILE --from 3.10.0 --to 4.0.1 [--input-digest SHA256] [--format human|json|input]
	   or: prufyx prepare cncf --project harbor --input FILE --from 2.7.0 --to 2.8.0 or 2.10.3|2.11.2|2.12.4|2.13.5|2.14.4 --to 2.15.2 [--input-digest SHA256] [--format human|json|input]
	   or: prufyx prepare cncf --project openfga --input FILE --from 1.17.1 --to 1.18.0 --effective-config-complete [--input-digest SHA256] [--format human|json|input]
	   or: prufyx prepare cncf --project opencost --input FILE --from 1.119.0 --to 1.120.0 [--input-digest SHA256] [--format human|json|input]
	   or: prufyx prepare cncf --project opencost --input FILE --from 1.116.0|1.117.6|1.118.0|1.119.2|1.120.4 --to 1.121.2 [--input-digest SHA256] [--format human|json|input]
	   or: prufyx prepare cncf --project cloud-custodian --input FILE --from 0.9.50 --to 0.9.51 [--input-digest SHA256] [--format human|json|input]
	   or: prufyx prepare cncf --project cloud-custodian --input FILE --from 0.9.47|0.9.48|0.9.49|0.9.50|0.9.51 --to 0.9.52 [--input-digest SHA256] [--format human|json|input]
	   or: prufyx prepare cncf --project fluentd --input FILE --from 1.17.1 --to 1.18.0 [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project distribution --input FILE --from 2.8.3 --to 3.0.0 [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project container-network-interface-cni --input FILE --from 0.4.0 --to 1.0.0 --operation configuration-spec-migration [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project containerd --input FILE --runtime-handler NAME --from 1.7.28 --to 2.0.0 --containerd-config-complete --containerd-config-precedence-resolved --containerd-official-upstream --containerd-official-bundled-runtimes-only [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project prometheus --prometheus-config FILE --prometheus-config-complete --prometheus-config-precedence-resolved --prometheus-rule remote-write-http2-default --prometheus-remote-write-name NAME --prometheus-remote-write-http2-required=true|false --from 2.55.1 --to 3.14.0 [--prometheus-config-digest SHA256] [--format human|json|input]

Prepare a minimized declaration from one private local supported resource JSON or declaration.
Select the Kyverno container explicitly. A scoped result requires an explicit
distribution declaration and the bare literal reports-controller command. Image
entrypoints, other paths, wrappers and ambiguous arguments remain UNKNOWN.
This prepares operator-declared input. It does not observe a cluster, validate
the complete workload or run an upgrade check. No network or model is used.

Linkerd accepts one private MeshTLSAuthentication JSON resource and derives
only selector emptiness. Its --container option is invalid. It does not parse
a CRD, call API admission, inspect stored objects or establish runtime behavior.

Karmada accepts one private policy.karmada.io/v1alpha1 PropagationPolicy or
ClusterPropagationPolicy JSON resource. It can witness a legacy application
purgeMode blocker but never prove aggregate absence or PASS. Its --container
and --schema-validation options are invalid. It does not validate a CRD, call
API admission, inspect stored resources or establish runtime behavior.

Argo CD accepts one private proposed v1 ConfigMap JSON named argocd-cm. It
reads only the explicit true or false inheritance setting and requires an
explicit access-intent declaration. Missing or malformed configuration stays
UNKNOWN; it does not inspect RBAC, call a cluster, or infer an effective default.

For the five reviewed transitions to Argo CD 3.5.2, the same project route
instead accepts one pre-apply v1 repository Secret. It checks only type=helm
with enableOCI=true and a protocol-free OCI registry/path. The caller must
declare plain-HTTP use, official distribution, and complete, precedence-resolved
repository settings; inherited credential templates, authentication and network
use are otherwise UNKNOWN. Secret values, names, URLs and credentials are discarded.

Cilium accepts one private CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, or
bounded policy List JSON. A nonempty requires field is a scoped blocker. A
scoped false result requires an explicit complete CNP and CCNP set declaration;
partial List pages, policy semantics, and runtime behavior remain UNKNOWN.

MetalLB accepts one caller-selected legacy ConfigMap or one supported
metallb.io/v1beta1 CR. Contour accepts one caller-selected Gateway API resource
and classifies only the reviewed v1alpha1 group versus v1alpha2. These checks
do not inspect a cluster or establish runtime behavior; unsupported shapes
remain UNKNOWN.

CloudNativePG accepts one JSON envelope containing matching current and
proposed Database, Pooler, Publication, Subscription, or ScheduledBackup
objects. It compares only the namespaced object identity and spec.cluster.name;
both objects are required to establish an update.

KubeVirt accepts one caller-supplied kubevirt.io/v1 VirtualMachine or
VirtualMachineInstance JSON resource. It counts only the five reviewed
interface binding slots and requires exactly one per named interface. Missing
or malformed native paths remain UNKNOWN; it does not inspect feature gates,
plugins, admission, or runtime behavior.

Emissary-Ingress accepts a caller-supplied direct diagd argv JSON array. OpenFGA
accepts strictly parsed nested authn effective-configuration JSON only when the
caller explicitly declares file, environment, and flag precedence complete.
Both retain only reviewed facts; wrappers, custom behavior, and runtime remain UNKNOWN.

Harbor accepts one caller-declared complete literal make/install.sh argv vector.
It checks only the removed --with-chartmuseum option for the reviewed 2.7.0 to
2.8.0 and 2.10.3, 2.11.2, 2.12.4, 2.13.5, or 2.14.4 to 2.15.2 pairs. Help, wrappers, values, unknown options, and unresolved inputs remain
UNKNOWN; it does not execute the installer or assess chart, database, or runtime state.

OpenCost accepts one Prufyx operator declaration of enabled cloud-cost source
selection. It is not an OpenCost native config parser. The caller declares
selection completeness and whether a target cloud-integration file is selected
and present; file contents, credentials, mounts, startup, and cloud access are
not inspected. The reviewed latest route is each exact 1.116.0, 1.117.6,
1.118.0, 1.119.2, or 1.120.4 origin to 1.121.2.

Cloud Custodian's latest route is each exact package version 0.9.47, 0.9.48,
0.9.49, 0.9.50, or 0.9.51 to package version 0.9.52. The retained source
contract separately binds those package versions to four-part upstream release
tags. The historical 0.9.50 to 0.9.51 route remains available.

etcd accepts one private EtcdEffectiveArguments JSON object containing a complete
direct arguments-only vector. The first slice accepts only self-contained
--name=value atoms and recognizes the eight removed v2/proxy options. It never
resolves wrappers, environment/config/response files, or executes etcd.

Jaeger accepts one private direct-invocation JSON declaration with
authority OPERATOR_DECLARED_DIRECT_OFFICIAL_JAEGER_V2_ARGUMENTS_ONLY and exactly
one local literal --config=VALUE argv atom. It does not read the location or
infer config content, backend, credentials, distribution, startup, or runtime.
The two rule guards remain explicit operator declarations; other argument forms
remain UNKNOWN.

Distribution accepts one private image manifest JSON document and classifies
only a bounded Docker schema1, Docker schema2, or OCI image-manifest shape.
It does not contact a registry, pull an image, validate content references, or
claim that a complete manifest can be stored or run.

Container Network Interface (CNI) accepts one private CNI configuration JSON
and explicit configuration-spec-migration intent. Its versions identify the
specification, not the CNI Go library, plugins, or a runtime. It checks only
single-plugin versus plugin-list configuration shape.

containerd accepts one private effective config.toml and one explicit CRI
runtime-handler selector. Config versions 2 and 3 are supported at their exact
reviewed plugin table paths; version 2 is migrated by containerd 2.0 and is not
itself a blocker. The adapter retains only whether the selected runtime_type is
one of the two removed official shims. Imports, custom runtime types, missing
handlers, runtime_path overrides, custom distributions, and separately supplied
shims remain UNKNOWN.

Prometheus accepts one full private prometheus.yml and selects one unique
remote_write entry by literal name. It retains only the direct inline
enable_http2 class and whether that class conflicts with the caller's explicit
endpoint requirement. Aliases, merges, substitutions, nested http_config
lookalikes, unresolved source precedence, and other version pairs stay UNKNOWN.

--format input writes only the canonical declaration for check cncf. Redirect
with umask 077 to a new file so it remains private. --format json also includes
the source digest, preparation reason and omissions, without raw workload data.
Exit 0: prepared; 11: unresolved preparation; 2: invalid input; 3: integrity failure.`)
		return ExitOK
	}
	fs := flag.NewFlagSet("prepare cncf", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "supported CNCF project")
	input := fs.String("input", "", "private proposed input JSON or supported native configuration")
	container := fs.String("container", "", "explicit local Kyverno container selector")
	from := fs.String("from", "", "actual declared current component version")
	to := fs.String("to", "", "actual declared proposed component version")
	distribution := fs.String("distribution", "", "explicit distribution guard: official_upstream or custom_build")
	schemaValidation := fs.String("schema-validation", "", "Linkerd schema intent: required or disabled")
	targetPolicyCRDAdmission := fs.String("target-policy-crd-admission", "", "Karmada target policy CRD intent: required or disabled")
	requiresInheritedPermissions := fs.String("requires-inherited-application-permissions", "", "explicit Argo CD v2 inheritance access intent: true or false")
	repositorySettingsResolved := fs.String("repository-settings-resolved", "", "explicit Argo CD repository setting completeness and precedence: true or false")
	repositoryUsesPlainHTTP := fs.String("repository-uses-plain-http", "", "explicit selected Argo CD repository transport intent: true or false")
	completeCNPCCNPSet := fs.String("complete-cnp-ccnp-set", "", "explicit Cilium CNP and CCNP policy-set completeness: true or false")
	ciliumConfigMap := fs.String("cilium-config-map", "", "private selected Cilium v1 ConfigMap YAML or JSON")
	ciliumConfigMapPin := fs.String("cilium-config-map-digest", "", "optional exact Cilium ConfigMap SHA-256")
	ciliumConfigComplete := fs.Bool("cilium-config-complete", false, "caller declaration that selected Cilium ConfigMap is complete")
	ciliumConfigPrecedenceResolved := fs.Bool("cilium-config-precedence-resolved", false, "caller declaration that Cilium ConfigMap precedence is resolved")
	ciliumDistribution := fs.String("cilium-distribution", "", "Cilium distribution: official_upstream or custom_build")
	corednsCorefile := fs.String("coredns-corefile", "", "private selected complete CoreDNS Corefile")
	corednsCorefilePin := fs.String("coredns-corefile-digest", "", "optional exact Corefile SHA-256")
	corednsCorefileComplete := fs.Bool("coredns-corefile-complete", false, "caller declaration that selected Corefile is complete")
	corednsDistribution := fs.String("coredns-distribution", "", "CoreDNS distribution: official")
	envoyBootstrap := fs.String("envoy-bootstrap", "", "private selected Envoy JSON bootstrap")
	envoyBootstrapPin := fs.String("envoy-bootstrap-digest", "", "optional exact Envoy bootstrap SHA-256")
	envoyBootstrapSelected := fs.Bool("envoy-bootstrap-selected", false, "caller declaration that this is the directly loaded Envoy bootstrap")
	kafkaResource := fs.String("kafka-resource", "", "private selected rendered Strimzi Kafka resource or flat v1 List JSON")
	kafkaResourcePin := fs.String("kafka-resource-digest", "", "optional exact Kafka resource SHA-256")
	strimziDistribution := fs.String("strimzi-distribution", "", "Strimzi distribution: official_upstream or custom_build")
	targetKafkaCRDAdmissionRequired := fs.Bool("target-kafka-crd-admission-required", false, "caller declaration that the selected Kafka resources must be admitted by the target Kafka CRD")
	falcoArgv := fs.String("falco-argv", "", "private explicit effective Falco JSON argv array")
	falcoArgvPin := fs.String("falco-argv-digest", "", "optional exact Falco argv SHA-256")
	falcoDistribution := fs.String("falco-distribution", "", "Falco distribution: official_upstream or custom_build")
	kumactlArgv := fs.String("kumactl-argv", "", "private explicit effective kumactl install transparent-proxy JSON argv array")
	kumactlArgvPin := fs.String("kumactl-argv-digest", "", "optional exact kumactl argv SHA-256")
	kumaDistribution := fs.String("kuma-distribution", "", "Kuma distribution: official_upstream or custom_build")
	composition := fs.String("composition", "", "private selected rendered Crossplane Composition or flat v1 List JSON")
	compositionPin := fs.String("composition-digest", "", "optional exact Composition SHA-256")
	crossplaneDistribution := fs.String("crossplane-distribution", "", "Crossplane distribution: official_upstream or custom_build")
	crossplaneSchemaValidationRequired := fs.Bool("crossplane-schema-validation-required", false, "caller declaration that the selected Compositions must validate against the official target CRD schema")
	upgradePlan := fs.String("upgrade-plan", "", "private selected flat v1 List of rendered Velero upgrade documents in declared apply order")
	upgradePlanPin := fs.String("upgrade-plan-digest", "", "optional exact upgrade plan SHA-256")
	veleroServerDeployment := fs.String("velero-server-deployment", "", "literal metadata.name of the Velero server Deployment inside the selected plan")
	veleroPlanOrderDeclared := fs.Bool("velero-plan-order-declared", false, "caller declaration that the supplied item order is the declared apply order")
	spireEntryArgv := fs.String("spire-entry-argv", "", "private explicit effective spire-server entry create JSON argv array")
	spireEntryArgvPin := fs.String("spire-entry-argv-digest", "", "optional exact SPIRE argv SHA-256")
	spireDistribution := fs.String("spire-distribution", "", "SPIRE distribution: official_upstream or custom_build")
	kedaScaledObject := fs.String("keda-scaled-object", "", "private selected rendered KEDA ScaledObject JSON, or one flat v1 List")
	kedaScaledObjectPin := fs.String("keda-scaled-object-digest", "", "optional exact KEDA ScaledObject SHA-256")
	kedaScaledObjectComplete := fs.Bool("keda-scaled-object-complete", false, "caller declaration that the selected ScaledObject set is complete")
	kedaLegacyTransport := fs.String("keda-legacy-tls-transport-required", "", "explicit declaration that the External Scaler relies on the removed direct tlsCertFile transport: true or false")
	resourceScopeComplete := fs.Bool("resource-scope-complete", false, "caller declaration that selected rendered resource set is complete")
	targetAPIApplyRequired := fs.Bool("target-api-apply-required", false, "caller declaration that selected resource set is required for target API apply")
	jaegerNonMemoryStorage := fs.String("non-memory-storage-required", "", "explicit Jaeger non-memory storage requirement: true or false")
	jaegerOfficialDistribution := fs.String("official-jaeger-distribution", "", "explicit Jaeger official distribution declaration: true or false")
	operation := fs.String("operation", "", "explicit operation for profiles that require one")
	effectiveConfigComplete := fs.Bool("effective-config-complete", false, "caller declaration that OpenFGA file, environment, and flag precedence is resolved")
	containerdRuntimeHandler := fs.String("runtime-handler", "", "explicit selected containerd CRI runtime handler")
	containerdConfigComplete := fs.Bool("containerd-config-complete", false, "caller declaration that the selected containerd configuration is complete")
	containerdConfigPrecedenceResolved := fs.Bool("containerd-config-precedence-resolved", false, "caller declaration that containerd configuration precedence is resolved")
	containerdOfficialUpstream := fs.Bool("containerd-official-upstream", false, "bind the target to the reviewed upstream containerd distribution")
	containerdOfficialBundledRuntimesOnly := fs.Bool("containerd-official-bundled-runtimes-only", false, "declare that no separately installed custom shim supplies the selected runtime")
	prometheusConfig := fs.String("prometheus-config", "", "private complete Prometheus YAML configuration")
	prometheusConfigPin := fs.String("prometheus-config-digest", "", "optional exact Prometheus configuration SHA-256")
	prometheusConfigComplete := fs.Bool("prometheus-config-complete", false, "caller declaration that the selected remote_write subtree is complete")
	prometheusConfigPrecedenceResolved := fs.Bool("prometheus-config-precedence-resolved", false, "caller declaration that selected remote_write precedence is resolved")
	prometheusRule := fs.String("prometheus-rule", "", "explicit Prometheus rule selector")
	prometheusRemoteWriteName := fs.String("prometheus-remote-write-name", "", "literal name selecting one remote_write entry")
	prometheusRemoteWriteHTTP2Required := fs.String("prometheus-remote-write-http2-required", "", "declared endpoint HTTP/2 requirement: true or false")
	pin := fs.String("input-digest", "", "optional exact source file SHA-256")
	format := fs.String("format", "human", "human, json or input")
	if duplicateFlags(args) || fs.Parse(args) != nil {
		return r.usage("invalid CNCF preparation arguments; use --help")
	}
	if *project != "cilium" && anyFlagProvided(args, "cilium-config-map", "cilium-config-map-digest", "cilium-config-complete", "cilium-config-precedence-resolved", "cilium-distribution") {
		return r.usage("Cilium ConfigMap flags require Cilium preparation")
	}
	if *project != "coredns" && anyFlagProvided(args, "coredns-corefile", "coredns-corefile-digest", "coredns-corefile-complete", "coredns-distribution") {
		return r.usage("CoreDNS Corefile flags require CoreDNS preparation")
	}
	if *project != "envoy" && anyFlagProvided(args, "envoy-bootstrap", "envoy-bootstrap-digest", "envoy-bootstrap-selected") {
		return r.usage("Envoy bootstrap flags require Envoy preparation")
	}
	if *project != "strimzi" && anyFlagProvided(args, "kafka-resource", "kafka-resource-digest", "strimzi-distribution", "target-kafka-crd-admission-required") {
		return r.usage("Strimzi Kafka resource flags require Strimzi preparation")
	}
	if *project != "falco" && anyFlagProvided(args, "falco-argv", "falco-argv-digest", "falco-distribution") {
		return r.usage("Falco argv flags require Falco preparation")
	}
	if *project != "kuma" && anyFlagProvided(args, "kumactl-argv", "kumactl-argv-digest", "kuma-distribution") {
		return r.usage("Kuma kumactl argv flags require Kuma preparation")
	}
	if *project != "crossplane" && anyFlagProvided(args, "composition", "composition-digest", "crossplane-distribution", "crossplane-schema-validation-required") {
		return r.usage("Crossplane Composition flags require Crossplane preparation")
	}
	if *project != "velero" && anyFlagProvided(args, "upgrade-plan", "upgrade-plan-digest", "velero-server-deployment", "velero-plan-order-declared") {
		return r.usage("Velero upgrade plan flags require Velero preparation")
	}
	if *project != "spire" && anyFlagProvided(args, "spire-entry-argv", "spire-entry-argv-digest", "spire-distribution") {
		return r.usage("SPIRE argv flags require SPIRE preparation")
	}
	if *project != "keda" && anyFlagProvided(args, "keda-scaled-object", "keda-scaled-object-digest", "keda-scaled-object-complete", "keda-legacy-tls-transport-required") {
		return r.usage("KEDA ScaledObject flags require KEDA preparation")
	}
	if *project != "prometheus" && anyFlagProvided(args, "prometheus-config", "prometheus-config-digest", "prometheus-config-complete", "prometheus-config-precedence-resolved", "prometheus-rule", "prometheus-remote-write-name", "prometheus-remote-write-http2-required") {
		return r.usage("Prometheus remote-write flags require Prometheus preparation")
	}
	if *project != "kubernetes" && flagProvided(args, "target-api-apply-required") {
		return r.usage("--target-api-apply-required is only valid for Kubernetes preparation")
	}
	if *project != "kubernetes" && flagProvided(args, "resource-scope-complete") {
		return r.usage("--resource-scope-complete is only valid for Kubernetes preparation")
	}
	if *project == "cilium" && *ciliumConfigMap != "" {
		if *input != "" || flagProvided(args, "input-digest") || (flagProvided(args, "cilium-config-map-digest") && !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*ciliumConfigMapPin)) {
			return r.fail("CILIUM_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		*input, *pin = *ciliumConfigMap, *ciliumConfigMapPin
	}
	if *project == "coredns" && *corednsCorefile != "" {
		if *input != "" || flagProvided(args, "input-digest") || (flagProvided(args, "coredns-corefile-digest") && !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*corednsCorefilePin)) {
			return r.fail("COREDNS_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		*input, *pin = *corednsCorefile, *corednsCorefilePin
	}
	if *project == "envoy" && *envoyBootstrap != "" {
		if *input != "" || flagProvided(args, "input-digest") || (flagProvided(args, "envoy-bootstrap-digest") && !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*envoyBootstrapPin)) {
			return r.fail("ENVOY_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		*input, *pin = *envoyBootstrap, *envoyBootstrapPin
	}
	if *project == "strimzi" && *kafkaResource != "" {
		if *input != "" || flagProvided(args, "input-digest") || (flagProvided(args, "kafka-resource-digest") && !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*kafkaResourcePin)) {
			return r.fail("STRIMZI_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		*input, *pin = *kafkaResource, *kafkaResourcePin
	}
	if *project == "kuma" && *kumactlArgv != "" {
		if *input != "" || flagProvided(args, "input-digest") || (flagProvided(args, "kumactl-argv-digest") && !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*kumactlArgvPin)) {
			return r.fail("KUMA_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		*input, *pin = *kumactlArgv, *kumactlArgvPin
	}
	if *project == "falco" && *falcoArgv != "" {
		if *input != "" || flagProvided(args, "input-digest") || (flagProvided(args, "falco-argv-digest") && !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*falcoArgvPin)) {
			return r.fail("FALCO_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		*input, *pin = *falcoArgv, *falcoArgvPin
	}
	if *project == "crossplane" && *composition != "" {
		if *input != "" || flagProvided(args, "input-digest") || (flagProvided(args, "composition-digest") && !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*compositionPin)) {
			return r.fail("CROSSPLANE_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		*input, *pin = *composition, *compositionPin
	}
	if *project == "velero" && *upgradePlan != "" {
		if *input != "" || flagProvided(args, "input-digest") || (flagProvided(args, "upgrade-plan-digest") && !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*upgradePlanPin)) {
			return r.fail("VELERO_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		*input, *pin = *upgradePlan, *upgradePlanPin
	}
	if *project == "spire" && *spireEntryArgv != "" {
		if *input != "" || flagProvided(args, "input-digest") || (flagProvided(args, "spire-entry-argv-digest") && !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*spireEntryArgvPin)) {
			return r.fail("SPIRE_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		*input, *pin = *spireEntryArgv, *spireEntryArgvPin
	}
	if *project == "keda" && *kedaScaledObject != "" {
		if *input != "" || flagProvided(args, "input-digest") || (flagProvided(args, "keda-scaled-object-digest") && !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*kedaScaledObjectPin)) {
			return r.fail("KEDA_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		*input, *pin = *kedaScaledObject, *kedaScaledObjectPin
	}
	if *project == "prometheus" && *prometheusConfig != "" {
		if *input != "" || flagProvided(args, "input-digest") || (flagProvided(args, "prometheus-config-digest") && !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*prometheusConfigPin)) {
			return r.fail("PROMETHEUS_REMOTE_WRITE_INPUT_INVALID", ExitUsage)
		}
		*input, *pin = *prometheusConfig, *prometheusConfigPin
	}
	if concreteCNCFPreparationProject(*project) && (fs.NArg() != 0 || *input == "" || *from == "" || *to == "" || (*format != "human" && *format != "json" && *format != "input") || (flagProvided(args, "input-digest") && !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*pin))) {
		if *project == "linkerd" {
			return r.fail("LINKERD_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "karmada" {
			return r.fail("KARMADA_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "cilium" {
			return r.fail("CILIUM_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "coredns" {
			return r.fail("COREDNS_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "kubernetes" {
			return r.fail("KUBERNETES_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "jaeger" {
			return r.fail("JAEGER_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "opencost" {
			return r.fail("OPENCOST_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "cloud-custodian" {
			return r.fail("CLOUD_CUSTODIAN_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "prometheus" {
			return r.fail("PROMETHEUS_REMOTE_WRITE_INPUT_INVALID", ExitUsage)
		}
		if *project == "strimzi" {
			return r.fail("STRIMZI_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "falco" {
			return r.fail("FALCO_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "kuma" {
			return r.fail("KUMA_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "crossplane" {
			return r.fail("CROSSPLANE_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "velero" {
			return r.fail("VELERO_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "spire" {
			return r.fail("SPIRE_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "keda" {
			return r.fail("KEDA_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		return r.fail("ARGO_CD_PREPARATION_INPUT_INVALID", ExitUsage)
	}
	if fs.NArg() != 0 || *project == "" || *input == "" || *from == "" || *to == "" || (*project == "kyverno" && *container == "") || (*format != "human" && *format != "json" && *format != "input") || (flagProvided(args, "input-digest") && !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*pin)) {
		return r.usage("invalid CNCF preparation arguments; use --help")
	}
	if *project != "openfga" && flagProvided(args, "effective-config-complete") {
		return r.usage("--effective-config-complete is only valid for OpenFGA preparation")
	}
	if *project != "argo-cd" && flagProvided(args, "repository-settings-resolved") {
		return r.usage("--repository-settings-resolved is only valid for Argo CD preparation")
	}
	if *project != "argo-cd" && flagProvided(args, "repository-uses-plain-http") {
		return r.usage("--repository-uses-plain-http is only valid for Argo CD preparation")
	}
	containerdFlags := anyFlagProvided(args, "runtime-handler", "containerd-config-complete", "containerd-config-precedence-resolved", "containerd-official-upstream", "containerd-official-bundled-runtimes-only")
	if *project != "containerd" && containerdFlags {
		return r.usage("containerd configuration flags require project containerd")
	}
	// Validate project-specific flags before opening the private input. This keeps
	// malformed cross-project invocations from admitting any local file.
	switch *project {
	case "kyverno":
		if *container == "" || flagProvided(args, "schema-validation") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") ||
			flagProvided(args, "operation") ||
			(flagProvided(args, "distribution") && *distribution == "") ||
			(*distribution != "" && *distribution != cncfprepare.KyvernoDistributionOfficial && *distribution != cncfprepare.KyvernoDistributionCustom) {
			return r.usage("invalid Kyverno preparation arguments; use --help")
		}
	case "linkerd":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") ||
			flagProvided(args, "operation") ||
			(flagProvided(args, "distribution") && *distribution == "") ||
			(flagProvided(args, "schema-validation") && *schemaValidation == "") ||
			(*distribution != "" && *distribution != cncfprepare.LinkerdDistributionOfficial && *distribution != cncfprepare.LinkerdDistributionCustom) ||
			(*schemaValidation != "" && *schemaValidation != cncfprepare.LinkerdSchemaRequired && *schemaValidation != cncfprepare.LinkerdSchemaDisabled) {
			return r.fail("LINKERD_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "karmada":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") ||
			flagProvided(args, "operation") ||
			(flagProvided(args, "distribution") && *distribution == "") ||
			(flagProvided(args, "target-policy-crd-admission") && *targetPolicyCRDAdmission == "") ||
			(*distribution != "" && *distribution != cncfprepare.KarmadaDistributionOfficial && *distribution != cncfprepare.KarmadaDistributionCustom) ||
			(*targetPolicyCRDAdmission != "" && *targetPolicyCRDAdmission != cncfprepare.KarmadaAdmissionRequired && *targetPolicyCRDAdmission != cncfprepare.KarmadaAdmissionDisabled) {
			return r.fail("KARMADA_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "argo-cd":
		latest := *to == cncfprepare.ArgoCDLatestTo
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") ||
			(latest && (flagProvided(args, "requires-inherited-application-permissions") || (flagProvided(args, "distribution") && *distribution == "") || (*distribution != "" && *distribution != cncfprepare.ArgoCDLatestDistributionOfficial && *distribution != cncfprepare.ArgoCDLatestDistributionCustom) || (flagProvided(args, "repository-settings-resolved") && *repositorySettingsResolved != "true" && *repositorySettingsResolved != "false") || (flagProvided(args, "repository-uses-plain-http") && *repositoryUsesPlainHTTP != "true" && *repositoryUsesPlainHTTP != "false"))) ||
			(!latest && (flagProvided(args, "distribution") || flagProvided(args, "repository-settings-resolved") || flagProvided(args, "repository-uses-plain-http") || (flagProvided(args, "requires-inherited-application-permissions") && *requiresInheritedPermissions != "true" && *requiresInheritedPermissions != "false"))) {
			return r.fail("ARGO_CD_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "cilium":
		configMapMode := *ciliumConfigMap != ""
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") ||
			(!configMapMode && (flagProvided(args, "distribution") || flagProvided(args, "cilium-config-map") || flagProvided(args, "cilium-config-map-digest") || flagProvided(args, "cilium-config-complete") || flagProvided(args, "cilium-config-precedence-resolved") || flagProvided(args, "cilium-distribution") || flagProvided(args, "resource-scope-complete") || flagProvided(args, "target-api-apply-required"))) ||
			(configMapMode && (flagProvided(args, "distribution") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "resource-scope-complete") || flagProvided(args, "target-api-apply-required") || *ciliumDistribution == "" || (*ciliumDistribution != "official_upstream" && *ciliumDistribution != "custom_build"))) ||
			(flagProvided(args, "complete-cnp-ccnp-set") && *completeCNPCCNPSet != "true" && *completeCNPCCNPSet != "false") {
			return r.fail("CILIUM_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "coredns":
		if *corednsCorefile == "" || (*corednsDistribution != "" && *corednsDistribution != "official" && *corednsDistribution != "custom") || (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			return r.fail("COREDNS_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "envoy":
		if *envoyBootstrap == "" || (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			return r.fail("ENVOY_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "keda":
		if *kedaScaledObject == "" || !*kedaScaledObjectComplete || (*kedaLegacyTransport != "" && *kedaLegacyTransport != cncfprepare.KEDADeclarationRequired && *kedaLegacyTransport != cncfprepare.KEDADeclarationNotRequired) || (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "resource-scope-complete") || flagProvided(args, "target-api-apply-required") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			return r.fail("KEDA_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "spire":
		if *spireEntryArgv == "" || (*spireDistribution != cncfprepare.SpireDistributionOfficial && *spireDistribution != cncfprepare.SpireDistributionCustom) || (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "resource-scope-complete") || flagProvided(args, "target-api-apply-required") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			return r.fail("SPIRE_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "kubernetes":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "cilium-config-map") || flagProvided(args, "cilium-config-map-digest") || flagProvided(args, "cilium-config-complete") || flagProvided(args, "cilium-config-precedence-resolved") || flagProvided(args, "cilium-distribution") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") || (*distribution != "official_upstream" && *distribution != "custom_build") {
			return r.fail("KUBERNETES_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "strimzi":
		if *kafkaResource == "" || (*strimziDistribution != cncfprepare.StrimziDistributionOfficial && *strimziDistribution != cncfprepare.StrimziDistributionCustom) || (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "resource-scope-complete") || flagProvided(args, "target-api-apply-required") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			return r.fail("STRIMZI_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "kuma":
		if *kumactlArgv == "" || (*kumaDistribution != cncfprepare.KumaDistributionOfficial && *kumaDistribution != cncfprepare.KumaDistributionCustom) || (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "resource-scope-complete") || flagProvided(args, "target-api-apply-required") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			return r.fail("KUMA_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "falco":
		if *falcoArgv == "" || (*falcoDistribution != cncfprepare.FalcoDistributionOfficial && *falcoDistribution != cncfprepare.FalcoDistributionCustom) || (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "resource-scope-complete") || flagProvided(args, "target-api-apply-required") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			return r.fail("FALCO_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "crossplane":
		if *composition == "" || (*crossplaneDistribution != cncfprepare.CrossplaneDistributionOfficial && *crossplaneDistribution != cncfprepare.CrossplaneDistributionCustom) || (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			return r.fail("CROSSPLANE_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "velero":
		if *upgradePlan == "" || *veleroServerDeployment == "" || !*veleroPlanOrderDeclared || (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			return r.fail("VELERO_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "etcd":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			return r.fail("ETCD_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "jaeger":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") ||
			flagProvided(args, "operation") ||
			(flagProvided(args, "non-memory-storage-required") && *jaegerNonMemoryStorage != "true" && *jaegerNonMemoryStorage != "false") ||
			(flagProvided(args, "official-jaeger-distribution") && *jaegerOfficialDistribution != "true" && *jaegerOfficialDistribution != "false") {
			return r.fail("JAEGER_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "metallb", "contour", "cloudnativepg", "kubevirt", "emissary-ingress", "harbor", "cloud-custodian", "fluentd":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			if *project == "cloud-custodian" {
				return r.fail("CLOUD_CUSTODIAN_PREPARATION_INPUT_INVALID", ExitUsage)
			}
			return r.fail("NATIVE_MIGRATION_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "opencost":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			return r.fail("OPENCOST_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "distribution":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || cncfOptionProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			return r.fail("DISTRIBUTION_MANIFEST_INPUT_INVALID", ExitUsage)
		}
	case "container-network-interface-cni":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || cncfOptionProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") {
			return r.fail("CNI_SPEC_CONFIGURATION_INPUT_INVALID", ExitUsage)
		}
	case "containerd":
		if *containerdRuntimeHandler == "" || (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") || flagProvided(args, "effective-config-complete") {
			return r.fail("CONTAINERD_CONFIG_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "prometheus":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") || flagProvided(args, "effective-config-complete") || *prometheusConfig == "" || (*prometheusRemoteWriteHTTP2Required != "" && *prometheusRemoteWriteHTTP2Required != "true" && *prometheusRemoteWriteHTTP2Required != "false") {
			return r.fail("PROMETHEUS_REMOTE_WRITE_INPUT_INVALID", ExitUsage)
		}
	case "openfga":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			return r.fail("OPENFGA_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	default:
		return r.usage("invalid CNCF preparation project; use --help")
	}
	raw, err := readCNCFPrivate(*input, 1<<20)
	if err != nil {
		if *project == "linkerd" {
			return r.linkerdInputFailure(err)
		}
		if *project == "karmada" {
			return r.karmadaInputFailure(err)
		}
		if *project == "argo-cd" {
			return r.argoCDInputFailure(err)
		}
		if *project == "cilium" {
			return r.fail(withPermissionHint("CILIUM_PREPARATION_INPUT_INVALID", err), ExitUsage)
		}
		if *project == "jaeger" {
			return r.jaegerInputFailure(err)
		}
		return r.cncfError("CNCF preparation input failed local admission", err)
	}
	sourceHash := sha256.Sum256(raw)
	sourceDigest := "sha256:" + hex.EncodeToString(sourceHash[:])
	if *pin != "" && *pin != sourceDigest {
		if concreteCNCFPreparationProject(*project) {
			return r.concretePreparationIntegrityFailure(*project)
		}
		return r.fail("CNCF preparation input digest does not match", ExitIntegrity)
	}
	var prepared cncfprepare.Prepared
	switch *project {
	case "kyverno":
		prepared, err = cncfprepare.PrepareKyvernoScoped(raw, *container, *from, *to, *distribution)
	case "linkerd":
		prepared, err = cncfprepare.PrepareLinkerd(raw, *from, *to, *distribution, *schemaValidation)
	case "karmada":
		prepared, err = cncfprepare.PrepareKarmada(raw, *from, *to, *distribution, *targetPolicyCRDAdmission)
	case "argo-cd":
		if *to == cncfprepare.ArgoCDLatestTo {
			var resolved, plainHTTP *bool
			if *repositorySettingsResolved != "" {
				value := *repositorySettingsResolved == "true"
				resolved = &value
			}
			if *repositoryUsesPlainHTTP != "" {
				value := *repositoryUsesPlainHTTP == "true"
				plainHTTP = &value
			}
			prepared, err = cncfprepare.PrepareArgoCDLatestRepository(raw, *from, *to, *distribution, resolved, plainHTTP)
		} else {
			var required *bool
			if *requiresInheritedPermissions != "" {
				value := *requiresInheritedPermissions == "true"
				required = &value
			}
			prepared, err = cncfprepare.PrepareArgoCD(raw, *from, *to, required)
		}
	case "cilium":
		if *ciliumConfigMap != "" {
			prepared, err = cncfprepare.PrepareCiliumClusterName(raw, *from, *to, *ciliumDistribution, *ciliumConfigComplete, *ciliumConfigPrecedenceResolved)
		} else {
			var complete *bool
			if *completeCNPCCNPSet != "" {
				value := *completeCNPCCNPSet == "true"
				complete = &value
			}
			prepared, err = cncfprepare.PrepareCilium(raw, *from, *to, complete)
		}
	case "coredns":
		prepared, err = cncfprepare.PrepareCoreDNSCorefile(raw, *from, *to, *corednsDistribution, *corednsCorefileComplete)
	case "envoy":
		prepared, err = cncfprepare.PrepareEnvoyBootstrap(raw, *from, *to, *envoyBootstrapSelected)
	case "kubernetes":
		prepared, err = cncfprepare.PrepareKubernetesRemovedAPIs(raw, *from, *to, *distribution, *targetAPIApplyRequired, *resourceScopeComplete)
	case "strimzi":
		prepared, err = cncfprepare.PrepareStrimziKafkaResource(raw, *from, *to, *strimziDistribution, *targetKafkaCRDAdmissionRequired)
	case "falco":
		prepared, err = cncfprepare.PrepareFalcoArgv(raw, *from, *to, *falcoDistribution)
	case "kuma":
		prepared, err = cncfprepare.PrepareKumaInstallTransparentProxyArgv(raw, *from, *to, *kumaDistribution)
	case "crossplane":
		prepared, err = cncfprepare.PrepareCrossplaneComposition(raw, *from, *to, *crossplaneDistribution, *crossplaneSchemaValidationRequired)
	case "velero":
		prepared, err = cncfprepare.PrepareVeleroUpgradePlan(raw, *from, *to, *veleroServerDeployment, *veleroPlanOrderDeclared)
	case "spire":
		prepared, err = cncfprepare.PrepareSpireEntryCreateArgv(raw, *from, *to, *spireDistribution)
	case "keda":
		prepared, err = cncfprepare.PrepareKEDAScaledObject(raw, *from, *to, *kedaLegacyTransport, *kedaScaledObjectComplete)
	case "etcd":
		prepared, err = cncfprepare.PrepareEtcd(raw, *from, *to)
	case "jaeger":
		var nonMemory, official *bool
		if *jaegerNonMemoryStorage != "" {
			value := *jaegerNonMemoryStorage == "true"
			nonMemory = &value
		}
		if *jaegerOfficialDistribution != "" {
			value := *jaegerOfficialDistribution == "true"
			official = &value
		}
		prepared, err = cncfprepare.PrepareJaeger(raw, *from, *to, nonMemory, official)
	case "metallb", "contour":
		prepared, err = cncfprepare.PrepareNativeMigration(raw, *project, *from, *to)
	case "cloudnativepg":
		prepared, err = cncfprepare.PrepareCloudNativePG(raw, *from, *to)
	case "kubevirt":
		prepared, err = cncfprepare.PrepareKubeVirt(raw, *from, *to)
	case "distribution":
		prepared, err = cncfprepare.PrepareDistributionManifest(raw, *from, *to)
	case "container-network-interface-cni":
		prepared, err = cncfprepare.PrepareCNISpecConfiguration(raw, *from, *to, *operation)
	case "containerd":
		prepared, err = cncfprepare.PrepareContainerdConfig(raw, *containerdRuntimeHandler, *from, *to, *containerdConfigComplete, *containerdConfigPrecedenceResolved, *containerdOfficialUpstream, *containerdOfficialBundledRuntimesOnly)
	case "prometheus":
		var required *bool
		if *prometheusRule == cncfprepare.PrometheusRemoteWriteHTTP2Rule && *prometheusRemoteWriteHTTP2Required != "" {
			value := *prometheusRemoteWriteHTTP2Required == "true"
			required = &value
		}
		prepared, err = cncfprepare.PreparePrometheusRemoteWriteConfig(raw, *prometheusRemoteWriteName, *from, *to, *prometheusConfigComplete, *prometheusConfigPrecedenceResolved, required)
	case "emissary-ingress":
		prepared, err = cncfprepare.PrepareEmissary(raw, *from, *to)
	case "harbor":
		prepared, err = cncfprepare.PrepareHarbor(raw, *from, *to)
	case "openfga":
		prepared, err = cncfprepare.PrepareOpenFGAOIDC(raw, *from, *to, effectiveConfigComplete)
	case "opencost":
		prepared, err = cncfprepare.PrepareOpenCostCloudSource(raw, *from, *to)
	case "cloud-custodian":
		prepared, err = cncfprepare.PrepareCloudCustodian(raw, *from, *to)
	case "fluentd":
		prepared, err = cncfprepare.PrepareFluentD(raw, *from, *to)
	}
	if err != nil {
		if *project == "linkerd" {
			return r.linkerdInputFailure(err)
		}
		if *project == "karmada" {
			return r.karmadaInputFailure(err)
		}
		if *project == "argo-cd" {
			return r.argoCDInputFailure(err)
		}
		if *project == "cilium" {
			return r.fail("CILIUM_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "jaeger" {
			return r.jaegerInputFailure(err)
		}
		if *project == "cloud-custodian" {
			return r.fail("CLOUD_CUSTODIAN_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		return r.fail("CNCF preparation input is invalid", ExitUsage)
	}
	inputHash := sha256.Sum256(prepared.CanonicalInputJSON)
	if prepared.SourceDigest != sourceDigest || prepared.InputDigest != "sha256:"+hex.EncodeToString(inputHash[:]) || !json.Valid(prepared.CanonicalInputJSON) {
		if concreteCNCFPreparationProject(*project) {
			return r.concretePreparationIntegrityFailure(*project)
		}
		return r.fail("CNCF preparation integrity failure", ExitIntegrity)
	}
	exit := ExitOK
	switch prepared.State {
	case cncfprepare.StatePrepared:
	case cncfprepare.StateUnknown:
		exit = ExitUnknown
	default:
		if concreteCNCFPreparationProject(*project) {
			return r.concretePreparationIntegrityFailure(*project)
		}
		return r.fail("CNCF preparation integrity failure", ExitIntegrity)
	}
	if *format == "input" {
		if _, err := r.stdout.Write(prepared.CanonicalInputJSON); err != nil {
			if concreteCNCFPreparationProject(*project) {
				return r.concretePreparationIntegrityFailure(*project)
			}
			return ExitIntegrity
		}
		return exit
	}
	if *format == "json" {
		envelope := struct {
			Schema         string          `json:"schema"`
			Project        string          `json:"project"`
			Authority      string          `json:"authority"`
			State          string          `json:"state"`
			Reason         string          `json:"reason"`
			SourceDigest   string          `json:"sourceDigest"`
			InputDigest    string          `json:"inputDigest"`
			NetworkUsed    bool            `json:"networkUsed"`
			CheckPerformed bool            `json:"checkPerformed"`
			Omissions      []string        `json:"omissions"`
			Input          json.RawMessage `json:"input"`
		}{"prufyx.io/local-cncf-preparation/v1alpha1", *project, "LOCAL_PREPARATION_OF_OPERATOR_DECLARATION", prepared.State, prepared.Reason, prepared.SourceDigest, prepared.InputDigest, false, false, prepared.Omissions, json.RawMessage(prepared.CanonicalInputJSON)}
		if json.NewEncoder(r.stdout).Encode(envelope) != nil {
			if concreteCNCFPreparationProject(*project) {
				return r.concretePreparationIntegrityFailure(*project)
			}
			return ExitIntegrity
		}
		return exit
	}
	label := *project
	if label == "kyverno" {
		label = "Kyverno"
	} else if label == "linkerd" {
		label = "Linkerd"
	} else if label == "karmada" {
		label = "Karmada"
	} else if label == "argo-cd" {
		label = "Argo CD"
	} else if label == "cilium" {
		label = "Cilium"
	} else if label == "kubernetes" {
		label = "Kubernetes"
	} else if label == "jaeger" {
		label = "Jaeger"
	} else if label == "metallb" {
		label = "MetalLB"
	} else if label == "contour" {
		label = "Contour"
	} else if label == "cloudnativepg" {
		label = "CloudNativePG"
	} else if label == "kubevirt" {
		label = "KubeVirt"
	} else if label == "emissary-ingress" {
		label = "Emissary-Ingress"
	} else if label == "harbor" {
		label = "Harbor"
	} else if label == "openfga" {
		label = "OpenFGA"
	} else if label == "opencost" {
		label = "OpenCost"
	} else if label == "cloud-custodian" {
		label = "Cloud Custodian"
	} else if label == "fluentd" {
		label = "Fluentd"
	} else if label == "distribution" {
		label = "Distribution"
	} else if label == "container-network-interface-cni" {
		label = "CNI specification"
	} else if label == "prometheus" {
		label = "Prometheus remote-write HTTP/2"
	} else if label == "strimzi" {
		label = "Strimzi"
	} else if label == "falco" {
		label = "Falco"
	} else if label == "kuma" {
		label = "Kuma"
	} else if label == "crossplane" {
		label = "Crossplane"
	} else if label == "velero" {
		label = "Velero"
	} else if label == "spire" {
		label = "SPIRE"
	} else if label == "keda" {
		label = "KEDA"
	}
	if _, err := fmt.Fprintf(r.stdout, "%s declaration preparation: %s\nreason: %s\nsource digest: %s\nprepared input digest: %s\nnetwork used: false\nupgrade check performed: false\n", label, prepared.State, prepared.Reason, prepared.SourceDigest, prepared.InputDigest); err != nil {
		if concreteCNCFPreparationProject(*project) {
			return r.concretePreparationIntegrityFailure(*project)
		}
		return ExitIntegrity
	}
	if concreteCNCFPreparationProject(*project) {
		if _, err := fmt.Fprintf(r.stdout, "omissions: %s\n", strings.Join(prepared.Omissions, ", ")); err != nil {
			return r.concretePreparationIntegrityFailure(*project)
		}
	}
	if exit == ExitUnknown {
		if *project == "kyverno" {
			_, err = fmt.Fprintln(r.stdout, "next action: supply an explicit distribution and inspect the selected literal reports-controller invocation locally; keep unresolved facts UNKNOWN")
		} else {
			_, err = fmt.Fprintln(r.stdout, "next action: inspect the selected private declaration locally, provide any missing guard or fact, and keep unresolved facts UNKNOWN")
		}
	} else {
		_, err = fmt.Fprintln(r.stdout, "next action: inspect --format json, then save --format input privately and run check cncf at the current UTC time")
	}
	if err != nil {
		if concreteCNCFPreparationProject(*project) {
			return r.concretePreparationIntegrityFailure(*project)
		}
		return ExitIntegrity
	}
	return exit
}

func concreteCNCFPreparationProject(project string) bool {
	return project == "linkerd" || project == "karmada" || project == "argo-cd" || project == "cilium" || project == "coredns" || project == "envoy" || project == "kubernetes" || project == "jaeger" || project == "metallb" || project == "contour" || project == "cloudnativepg" || project == "kubevirt" || project == "emissary-ingress" || project == "harbor" || project == "openfga" || project == "opencost" || project == "cloud-custodian" || project == "fluentd" || project == "distribution" || project == "container-network-interface-cni" || project == "containerd" || project == "prometheus" || project == "strimzi" || project == "falco" || project == "kuma" || project == "crossplane" || project == "velero" || project == "spire" || project == "keda"
}

func cncfOptionProvided(args []string, wanted string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if strings.HasPrefix(arg, "--") && strings.SplitN(strings.TrimPrefix(arg, "--"), "=", 2)[0] == wanted {
			return true
		}
	}
	return false
}

func (r runtime) linkerdInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.linkerdIntegrityFailure()
	}
	return r.fail(withPermissionHint("LINKERD_PREPARATION_INPUT_INVALID", err), ExitUsage)
}

func (r runtime) karmadaInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.karmadaIntegrityFailure()
	}
	return r.fail(withPermissionHint("KARMADA_PREPARATION_INPUT_INVALID", err), ExitUsage)
}

func (r runtime) concretePreparationIntegrityFailure(project string) int {
	if project == "cloud-custodian" {
		return r.fail("CNCF_PREPARATION_INTEGRITY_FAILURE", ExitIntegrity)
	}
	if project == "karmada" {
		return r.karmadaIntegrityFailure()
	}
	if project == "argo-cd" {
		return r.argoCDIntegrityFailure()
	}
	return r.linkerdIntegrityFailure()
}

func (r runtime) karmadaIntegrityFailure() int {
	return r.fail("CNCF_PREPARATION_INTEGRITY_FAILURE", ExitIntegrity)
}

func (r runtime) linkerdIntegrityFailure() int {
	return r.fail("CNCF_PREPARATION_INTEGRITY_FAILURE", ExitIntegrity)
}

func (r runtime) argoCDInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.argoCDIntegrityFailure()
	}
	return r.fail(withPermissionHint("ARGO_CD_PREPARATION_INPUT_INVALID", err), ExitUsage)
}

func (r runtime) argoCDIntegrityFailure() int {
	return r.fail("CNCF_PREPARATION_INTEGRITY_FAILURE", ExitIntegrity)
}

func (r runtime) jaegerInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.fail("CNCF_PREPARATION_INTEGRITY_FAILURE", ExitIntegrity)
	}
	return r.fail(withPermissionHint("JAEGER_PREPARATION_INPUT_INVALID", err), ExitUsage)
}
