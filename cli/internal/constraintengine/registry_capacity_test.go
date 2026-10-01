// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

const capacityComponent = "pkg:example/capacity"

func capacityDefinitions(count int) []FactDefinition {
	definitions := make([]FactDefinition, 0, count)
	for index := 0; index < count; index++ {
		definitions = append(definitions, FactDefinition{
			ID: fmt.Sprintf("component.capacity.fact%03d", index), Component: capacityComponent, Type: FactBool,
		})
	}
	return definitions
}

func capacityTokens(count int) []string {
	tokens := make([]string, 0, count)
	for index := 0; index < count; index++ {
		tokens = append(tokens, fmt.Sprintf("token%03d", index))
	}
	return tokens
}

func capacityInput(t *testing.T, facts int) []byte {
	t.Helper()
	declared := make([]map[string]any, 0, facts)
	for index := 0; index < facts; index++ {
		declared = append(declared, map[string]any{
			"id": fmt.Sprintf("component.capacity.fact%03d", index), "state": "declared", "boolValue": true,
		})
	}
	document := map[string]any{
		"schema": InputSchema, "authority": InputAuthority,
		"current":  map[string]any{"components": []any{map[string]any{"component": capacityComponent, "version": "1.0.0", "facts": declared}}},
		"proposed": map[string]any{"components": []any{map[string]any{"component": capacityComponent, "version": "1.0.1", "facts": []any{}}}},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCompiledRegistryCapacityIsSeparateFromGenericAndInputBounds(t *testing.T) {
	for _, count := range []int{65, 256} {
		if _, err := NewCompiledRegistry(capacityDefinitions(count)); err != nil {
			t.Fatalf("compiled registry %d definitions: %v", count, err)
		}
	}
	if _, err := NewCompiledRegistry(capacityDefinitions(257)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("257 compiled definitions err=%v, want ErrInvalid", err)
	}
	if _, err := NewRegistry(capacityDefinitions(64)); err != nil {
		t.Fatalf("64 generic definitions: %v", err)
	}
	if _, err := NewRegistry(capacityDefinitions(65)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("65 generic definitions err=%v, want ErrInvalid", err)
	}

	registry, err := NewCompiledRegistry(capacityDefinitions(65))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseInput(capacityInput(t, 64), registry); err != nil {
		t.Fatalf("64 component facts: %v", err)
	}
	if _, err := ParseInput(capacityInput(t, 65), registry); !errors.Is(err, ErrInvalid) {
		t.Fatalf("65 component facts err=%v, want ErrInvalid", err)
	}
}

func TestCompiledRegistryCapacityDoesNotRaiseEnumOrBooleanBounds(t *testing.T) {
	valid := FactDefinition{ID: "component.capacity.mode", Component: capacityComponent, Type: FactEnum, EnumTokens: capacityTokens(64)}
	if _, err := NewCompiledRegistry([]FactDefinition{valid}); err != nil {
		t.Fatalf("64 enum tokens: %v", err)
	}
	tooMany := valid
	tooMany.EnumTokens = capacityTokens(65)
	if _, err := NewCompiledRegistry([]FactDefinition{tooMany}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("65 enum tokens err=%v, want ErrInvalid", err)
	}
	invalidBoolean := FactDefinition{ID: "component.capacity.boolean", Component: capacityComponent, Type: FactBool, EnumTokens: []string{"token000"}}
	if _, err := NewCompiledRegistry([]FactDefinition{invalidBoolean}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("boolean enum tokens err=%v, want ErrInvalid", err)
	}
}

func TestCompiledRegistryPreservesGenericDigestWithinSharedCapacity(t *testing.T) {
	definitions := append(capacityDefinitions(63), FactDefinition{
		ID: "component.capacity.mode", Component: capacityComponent, Type: FactEnum,
		EnumTokens: []string{"alpha", "beta", "gamma"},
	})
	generic, err := NewRegistry(definitions)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := NewCompiledRegistry(definitions)
	if err != nil {
		t.Fatal(err)
	}
	if generic.Digest() != compiled.Digest() {
		t.Fatalf("same definitions produced digests %q and %q", generic.Digest(), compiled.Digest())
	}
}
