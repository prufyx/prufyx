// SPDX-License-Identifier: AGPL-3.0-only

package sourcecorpus

import (
	"os"
	"sort"
	"strconv"
	"strings"
)

type shardSpec struct {
	manifestPath string
	objectRoot   string
}

func parseIndex(raw []byte) (map[string]any, []shardSpec, error) {
	value, err := DecodeBounded(raw, maxIndexBytes)
	if err != nil {
		return nil, nil, errRejected
	}
	index, err := closed(value, "schema", "revision", "authority", "shards")
	if err != nil || index["schema"] != CollectionSchema || index["authority"] != CollectionAuthority {
		return nil, nil, errRejected
	}
	revision, err := ValidateSlug(index["revision"])
	if err != nil {
		return nil, nil, errRejected
	}
	rawShards, ok := index["shards"].([]any)
	if !ok || len(rawShards) < 1 || len(rawShards) > maxShards {
		return nil, nil, errRejected
	}
	shards := make([]shardSpec, 0, len(rawShards))
	normalized := make([]any, 0, len(rawShards))
	seenManifests, seenRoots := map[string]struct{}{}, map[string]struct{}{}
	prior := ""
	for _, item := range rawShards {
		entry, entryErr := closed(item, "manifestPath", "objectRoot")
		if entryErr != nil {
			return nil, nil, errRejected
		}
		manifestPath, manifestOK := entry["manifestPath"].(string)
		objectRoot, rootOK := entry["objectRoot"].(string)
		if !manifestOK || !rootOK {
			return nil, nil, errRejected
		}
		manifestParts, manifestErr := relativeParts(manifestPath)
		rootParts, rootErr := relativeParts(objectRoot)
		if manifestErr != nil || rootErr != nil {
			return nil, nil, errRejected
		}
		manifestPath, objectRoot = strings.Join(manifestParts, "/"), strings.Join(rootParts, "/")
		if manifestPath == objectRoot {
			return nil, nil, errRejected
		}
		key := manifestPath + "\x00" + objectRoot
		if prior != "" && key < prior {
			return nil, nil, errRejected
		}
		prior = key
		if _, exists := seenManifests[manifestPath]; exists {
			return nil, nil, errRejected
		}
		if _, exists := seenRoots[objectRoot]; exists {
			return nil, nil, errRejected
		}
		seenManifests[manifestPath], seenRoots[objectRoot] = struct{}{}, struct{}{}
		shards = append(shards, shardSpec{manifestPath, objectRoot})
		normalized = append(normalized, map[string]any{"manifestPath": manifestPath, "objectRoot": objectRoot})
	}
	return map[string]any{"schema": CollectionSchema, "revision": revision, "authority": CollectionAuthority, "shards": normalized}, shards, nil
}

// VerifyCollection verifies a private collection index and every selected
// shard through retained directory descriptors.
func VerifyCollection(collectionRoot, indexPath string) ([]byte, error) {
	root, err := openPhysical(collectionRoot, os.O_RDONLY)
	if err != nil {
		return nil, errRejected
	}
	defer root.Close()
	if validatePrivateDirectory(root) != nil {
		return nil, errRejected
	}
	indexRaw, err := readRelativeFile(root, indexPath, maxIndexBytes, true)
	if err != nil {
		return nil, errRejected
	}
	index, shards, err := parseIndex(indexRaw)
	if err != nil {
		return nil, errRejected
	}
	seenIDs, seenLogical := map[string]struct{}{}, map[string]struct{}{}
	projects, sourceMetadata := map[string]string{}, map[string]string{}
	objects := map[string]int64{}
	shardReceipts := make([]any, 0, len(shards))
	recordCount := int64(0)
	for _, shard := range shards {
		manifestRaw, readErr := readRelativeFile(root, shard.manifestPath, maxManifestBytes, true)
		if readErr != nil {
			return nil, errRejected
		}
		manifest, decodeErr := DecodeBounded(manifestRaw, maxManifestBytes)
		if decodeErr != nil {
			return nil, errRejected
		}
		reader := func(name string) ([]byte, error) { return readObjectAt(root, shard.objectRoot, name, true) }
		receipt, verifyErr := verifyValue(manifest, reader)
		if verifyErr != nil {
			return nil, errRejected
		}
		count := receipt["recordCount"].(int64)
		recordCount += count
		if recordCount > maxCollectionRecords {
			return nil, errRejected
		}
		shardObjects := map[string]struct{}{}
		for _, rawRecord := range receipt["records"].([]any) {
			record := rawRecord.(map[string]any)
			id := record["id"].(string)
			if _, exists := seenIDs[id]; exists {
				return nil, errRejected
			}
			seenIDs[id] = struct{}{}
			project := record["project"].(map[string]any)
			source := record["source"].(map[string]any)
			capture := record["capture"].(map[string]any)
			slug, repository := project["slug"].(string), project["canonicalRepositoryURL"].(string)
			logical := slug + "\x00" + source["immutableURL"].(string) + "\x00" + source["spansDigest"].(string)
			if _, exists := seenLogical[logical]; exists {
				return nil, errRejected
			}
			seenLogical[logical] = struct{}{}
			if prior, exists := projects[slug]; exists && prior != repository {
				return nil, errRejected
			}
			projects[slug] = repository
			immutable := source["immutableURL"].(string)
			metadata := strings.Join([]string{source["repositoryURL"].(string), source["sourceKind"].(string), source["version"].(string), source["commit"].(string), immutable, source["fileDigest"].(string), strconv.FormatInt(source["byteLength"].(int64), 10)}, "\x00")
			if prior, exists := sourceMetadata[immutable]; exists && prior != metadata {
				return nil, errRejected
			}
			sourceMetadata[immutable] = metadata
			digest, length := capture["objectDigest"].(string), source["byteLength"].(int64)
			if prior, exists := objects[digest]; exists && prior != length {
				return nil, errRejected
			}
			objects[digest] = length
			shardObjects[digest] = struct{}{}
		}
		if len(objects) > maxObjects {
			return nil, errRejected
		}
		var aggregate, shardBytes int64
		for digest, length := range objects {
			_ = digest
			aggregate += length
		}
		if aggregate > maxUniqueBytes {
			return nil, errRejected
		}
		for digest := range shardObjects {
			shardBytes += objects[digest]
		}
		canonicalReceipt, canonicalErr := Canonical(receipt)
		if canonicalErr != nil {
			return nil, errRejected
		}
		shardReceipts = append(shardReceipts, map[string]any{
			"manifestDigest": receipt["manifestDigest"], "manifestPath": shard.manifestPath, "objectRoot": shard.objectRoot,
			"receiptDigest": SHA(canonicalReceipt), "recordCount": count, "uniqueByteLength": shardBytes, "uniqueObjectCount": int64(len(shardObjects)),
		})
	}
	canonicalIndex, err := Canonical(index)
	if err != nil {
		return nil, errRejected
	}
	var aggregate int64
	for _, length := range objects {
		aggregate += length
	}
	digests := make([]string, 0, len(objects))
	for digest := range objects {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	objectDigests := make([]any, len(digests))
	for i, digest := range digests {
		objectDigests[i] = digest
	}
	receipt := map[string]any{
		"schema": CollectionReceiptSchema, "indexDigest": SHA(canonicalIndex), "revision": index["revision"],
		"verification": "VERIFIED_LOCAL_COLLECTION", "authority": CollectionAuthority,
		"recordCount": recordCount, "projectCount": int64(len(projects)), "uniqueObjectCount": int64(len(objects)), "aggregateByteLength": aggregate,
		"shardReceipts": shardReceipts, "objectDigests": objectDigests,
		"limitations": []any{
			"verification is limited to selected private retained shards and their declared metadata; it does not fetch or authenticate upstream sources",
			"this receipt does not approve catalogue identity, source ownership, rule coverage, compatibility, runtime behavior, signing, publication, or training",
			"only explicitly listed manifests and content-addressed objects are read; unreferenced files are ignored",
		},
	}
	output, err := Canonical(receipt)
	if err != nil || len(output)+1 > maxOutputBytes {
		return nil, errRejected
	}
	return output, nil
}
