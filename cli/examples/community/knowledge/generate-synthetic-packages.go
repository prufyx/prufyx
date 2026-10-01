// SPDX-License-Identifier: AGPL-3.0-only

// Command generate-synthetic-packages creates a local, public-only TUF fixture
// for the offline knowledge database walkthrough. It is not a production
// signing or publishing command.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "synthetic fixture generation failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	output := flag.String("output", "", "new directory for public synthetic fixture files")
	profile := flag.String("profile", "cert-manager", "cert-manager, cncf, cncf-knative, cncf-in-toto, cncf-cubefs, cncf-crio, cncf-tuf, cncf-kubeflow, spiffe-x509-svid, cloudevents-structured-json, or tikv-gcp-v2-wif-backup synthetic fixture")
	flag.Parse()
	if *output == "" || flag.NArg() != 0 || (*profile != "cert-manager" && *profile != "cncf" && *profile != "cncf-knative" && *profile != "cncf-in-toto" && *profile != "cncf-cubefs" && *profile != "cncf-crio" && *profile != "cncf-tuf" && *profile != "cncf-kubeflow" && *profile != "spiffe-x509-svid" && *profile != "cloudevents-structured-json" && *profile != "tikv-gcp-v2-wif-backup") {
		return fmt.Errorf("usage: go run ./examples/community/knowledge/generate-synthetic-packages.go --output NEW_DIRECTORY [--profile cert-manager|cncf|cncf-knative|cncf-in-toto|cncf-cubefs|cncf-crio|cncf-tuf|cncf-kubeflow|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup]")
	}
	var artifacts knowledgefixture.Artifacts
	var err error
	if *profile == "tikv-gcp-v2-wif-backup" {
		artifacts, err = knowledgefixture.GenerateTiKVGCPV2WIFBackup(time.Now().UTC())
	} else if *profile == "cloudevents-structured-json" {
		artifacts, err = knowledgefixture.GenerateCloudEventsStructuredJSON(time.Now().UTC())
	} else if *profile == "spiffe-x509-svid" {
		artifacts, err = knowledgefixture.GenerateSPIFFEX509SVID(time.Now().UTC())
	} else if *profile == "cncf-kubeflow" {
		artifacts, err = knowledgefixture.GenerateKubeflowConstraints(time.Now().UTC())
	} else if *profile == "cncf-tuf" {
		artifacts, err = knowledgefixture.GenerateTUFConstraints(time.Now().UTC())
	} else if *profile == "cncf-cubefs" {
		artifacts, err = knowledgefixture.GenerateCubeFSConstraints(time.Now().UTC())
	} else if *profile == "cncf-crio" {
		artifacts, err = knowledgefixture.GenerateCRIOConstraints(time.Now().UTC())
	} else if *profile == "cncf-in-toto" {
		artifacts, err = knowledgefixture.GenerateInTotoConstraints(time.Now().UTC())
	} else if *profile == "cncf-knative" {
		artifacts, err = knowledgefixture.GenerateKnativeConstraints(time.Now().UTC())
	} else if *profile == "cncf" {
		artifacts, err = knowledgefixture.GenerateConstraints(time.Now().UTC())
	} else {
		artifacts, err = knowledgefixture.Generate(time.Now().UTC())
	}
	if err != nil {
		return err
	}
	if err := os.Mkdir(*output, 0o700); err != nil {
		return fmt.Errorf("create new output directory: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(*output)
		}
	}()
	files := []struct {
		name string
		raw  []byte
	}{
		{knowledgefixture.RootName, artifacts.Root},
		{knowledgefixture.Revision1Name, artifacts.Revision1},
		{knowledgefixture.Revision2Name, artifacts.Revision2},
		{knowledgefixture.ManifestName, artifacts.Manifest},
	}
	if len(artifacts.Revision3) > 0 {
		files = append(files, struct {
			name string
			raw  []byte
		}{knowledgefixture.Revision3Name, artifacts.Revision3})
	}
	for _, file := range files {
		if err := os.WriteFile(filepath.Join(*output, file.name), file.raw, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", file.name, err)
		}
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		return err
	}
	complete = true
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}
