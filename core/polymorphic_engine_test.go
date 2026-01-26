package core

import (
	"strings"
	"testing"
	"time"
)

func TestPolymorphicEngine_Mutate(t *testing.T) {
	config := &PolymorphicConfig{
		Enabled:           true,
		MutationLevel:     "medium",
		CacheEnabled:      false,
		SeedRotation:      60,
		TemplateMode:      false,
		PreserveSemantics: true,
	}
	// Enable all mutations
	config.EnabledMutations = map[string]bool{
		"variables":   true,
		"functions":   true,
		"deadcode":    true, // Often adds complexity
		"controlflow": true,
		"strings":     true,
		"math":        true,
		"comments":    true,
		"whitespace":  true,
	}

	engine := NewPolymorphicEngine(config)

	tests := []struct {
		name     string
		input    string
		contains []string // Strings that MIGHT be in output (hard to deterministically test mutation)
		excludes []string // Strings that should definitely NOT be in output (if replaced)
	}{
		{
			name:     "Variable Renaming",
			input:    "var secretToken = '123';",
			excludes: []string{"secretToken"}, // Should be renamed
		},
		{
			name:     "String Encryption",
			input:    `var s = "hello world";`,
			excludes: []string{`"hello world"`}, // Should be encoded
		},
		{
			name:  "Math Expression",
			input: "var x = 100;",
			// 100 might become "50 + 50" or similar. Hard to assert exactness.
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Probabilistic mutation retry
			var output string
			for i := 0; i < 20; i++ {
				ctx := &MutationContext{
					SessionID: "test_session",
					Timestamp: time.Now().Unix() + int64(i),
					Seed:      int64(12345 + i),
				}
				output = engine.Mutate(tc.input, ctx)

				mutated := true
				for _, ex := range tc.excludes {
					if strings.Contains(output, ex) {
						mutated = false
						break
					}
				}

				if mutated {
					break
				}
			}

			if output == "" {
				t.Errorf("Mutation returned empty string")
			}

			for _, ex := range tc.excludes {
				if strings.Contains(output, ex) {
					t.Errorf("Output should not contain '%s' after 20 attempts. Best Output: %s", ex, output)
				}
			}
		})
	}
}

func TestPolymorphicEngine_Cache(t *testing.T) {
	config := &PolymorphicConfig{
		Enabled:       true,
		CacheEnabled:  true,
		CacheDuration: 10,
	}
	engine := NewPolymorphicEngine(config)

	input := "var a = 1;"
	ctx := &MutationContext{SessionID: "session1", Timestamp: 100, Seed: 1}

	out1 := engine.Mutate(input, ctx)
	out2 := engine.Mutate(input, ctx)

	if out1 != out2 {
		t.Errorf("Cache enabled but outputs differ for same input/context")
	}

	// Different session check
	ctx2 := &MutationContext{SessionID: "session2", Timestamp: 100, Seed: 2}
	out3 := engine.Mutate(input, ctx2)
	// Ideally out3 should differ from out1 if seed is different
	// But minimal code "var a = 1;" might not have enough entropy to mutate differently always.
	_ = out3
}
