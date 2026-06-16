package infra

import (
	"strings"
	"testing"
	"time"
)

// fullConfig returns a PolymorphicConfig with all mutators enabled.
func fullConfig() *PolymorphicConfig {
	return &PolymorphicConfig{
		Enabled:           true,
		MutationLevel:     "high",
		CacheEnabled:      true,
		CacheDuration:     1,
		SeedRotation:      0,
		PreserveSemantics: true,
		EnabledMutations:  nil, // nil → all enabled
	}
}

// noopConfig returns a config with all mutators disabled so Mutate() is a
// predictable pass-through for cache and stats tests.
func noopConfig() *PolymorphicConfig {
	return &PolymorphicConfig{
		Enabled:       true,
		CacheEnabled:  true,
		CacheDuration: 1,
		EnabledMutations: map[string]bool{
			"variables":   false,
			"functions":   false,
			"deadcode":    false,
			"controlflow": false,
			"strings":     false,
			"math":        false,
			"comments":    false,
			"whitespace":  false,
		},
	}
}

func testContext() *MutationContext {
	return &MutationContext{
		Seed:      42,
		SessionID: "test-session",
		Timestamp: time.Now().Unix(),
	}
}

// --- Lifecycle ---

func TestNewPolymorphicEngine_InitialisesWithoutPanic(t *testing.T) {
	pe := NewPolymorphicEngine(fullConfig())
	if pe == nil {
		t.Fatal("expected non-nil engine")
	}
	pe.Stop()
}

func TestStop_SafeToCallOnce(t *testing.T) {
	pe := NewPolymorphicEngine(fullConfig())
	pe.Stop() // must not panic
}

// --- Mutate ---

func TestMutate_ChangesCode(t *testing.T) {
	pe := NewPolymorphicEngine(fullConfig())
	defer pe.Stop()

	input := `var counter = 0; var name = "hello world test string"; counter += 1;`
	ctx := testContext()
	output := pe.Mutate(input, ctx)

	if output == input {
		t.Error("Mutate() returned identical code — expected at least one mutation")
	}
}

func TestMutate_Deterministic(t *testing.T) {
	pe := NewPolymorphicEngine(noopConfig())
	defer pe.Stop()

	input := `var x = 1; var y = 2;`
	ctx1 := &MutationContext{Seed: 999, SessionID: "s1", Timestamp: 1000}
	ctx2 := &MutationContext{Seed: 999, SessionID: "s1", Timestamp: 1000}

	out1 := pe.Mutate(input, ctx1)
	out2 := pe.Mutate(input, ctx2)

	if out1 != out2 {
		t.Errorf("Mutate() is non-deterministic: %q != %q", out1, out2)
	}
}

// --- Cache ---

func TestMutate_CacheHit(t *testing.T) {
	pe := NewPolymorphicEngine(noopConfig())
	defer pe.Stop()

	input := `var a = 1;`
	ctx := &MutationContext{Seed: 7, SessionID: "cache-test", Timestamp: 500}

	pe.Mutate(input, ctx) // prime cache
	statsBefore := pe.GetStats()
	hitsBefore := statsBefore["cache_hits"].(int64)

	pe.Mutate(input, ctx) // should be a cache hit
	statsAfter := pe.GetStats()
	hitsAfter := statsAfter["cache_hits"].(int64)

	if hitsAfter <= hitsBefore {
		t.Errorf("expected cache hit count to increase: before=%d after=%d", hitsBefore, hitsAfter)
	}
}

func TestClearCache_EmptiesCache(t *testing.T) {
	pe := NewPolymorphicEngine(noopConfig())
	defer pe.Stop()

	pe.Mutate(`var x = 1;`, &MutationContext{Seed: 1, SessionID: "s"})
	pe.ClearCache()

	stats := pe.GetStats()
	if stats["cache_size"].(int) != 0 {
		t.Errorf("expected cache to be empty after ClearCache, got size %d", stats["cache_size"].(int))
	}
}

// --- MutateTemplate ---

func TestMutateTemplate_ValidName_ReturnsOutput(t *testing.T) {
	pe := NewPolymorphicEngine(fullConfig())
	defer pe.Stop()

	ctx := testContext()
	out, err := pe.MutateTemplate("behavior_collector", ctx, map[string]string{
		"endpoint": "/collect",
		"delay":    "3000",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) == 0 {
		t.Error("expected non-empty output from MutateTemplate")
	}
}

func TestMutateTemplate_InvalidName_ReturnsError(t *testing.T) {
	pe := NewPolymorphicEngine(fullConfig())
	defer pe.Stop()

	_, err := pe.MutateTemplate("nonexistent_template", testContext(), nil)
	if err == nil {
		t.Error("expected error for unknown template name, got nil")
	}
}

// --- GetStats ---

func TestGetStats_TotalMutationsIncrement(t *testing.T) {
	pe := NewPolymorphicEngine(noopConfig())
	defer pe.Stop()

	before := pe.GetStats()["total_mutations"].(int64)
	pe.Mutate(`var z = 0;`, &MutationContext{Seed: 1, SessionID: "stats-test"})
	after := pe.GetStats()["total_mutations"].(int64)

	if after != before+1 {
		t.Errorf("expected total_mutations to be %d, got %d", before+1, after)
	}
}

// --- Individual mutators ---

func TestDeadCodeMutator_InjectsCode(t *testing.T) {
	m := &DeadCodeMutator{config: fullConfig()}
	input := "var a = 1;\nvar b = 2;\nvar c = 3;\nvar d = 4;\n"
	output := m.Mutate(input, 12345)

	if len(output) <= len(input) {
		t.Error("DeadCodeMutator: output should be longer than input (dead code injected)")
	}
}

func TestWhitespaceMutator_PreservesContent(t *testing.T) {
	m := &WhitespaceMutator{config: fullConfig()}
	input := "var x = 1; var y = 2;"
	output := m.Mutate(input, 99)

	// strip all whitespace from both and compare tokens
	strip := func(s string) string {
		return strings.Join(strings.Fields(s), "")
	}
	if strip(input) != strip(output) {
		t.Errorf("WhitespaceMutator changed non-whitespace content:\ninput:  %q\noutput: %q", input, output)
	}
}

func TestStringEncodingMutator_EncodesLiterals(t *testing.T) {
	m := &StringEncodingMutator{config: fullConfig()}
	input := `var greeting = "hello world test";`
	output := m.Mutate(input, 42)

	// The literal "hello world test" should not appear verbatim when encoded
	if strings.Contains(output, `"hello world test"`) {
		t.Error("StringEncodingMutator: original string literal still present in output")
	}
}

func TestVariableNameMutator_RenamesVars(t *testing.T) {
	m := &VariableNameMutator{config: fullConfig()}
	input := `var mySpecialVariable = 1; mySpecialVariable += 2;`
	output := m.Mutate(input, 55)

	if strings.Contains(output, "mySpecialVariable") {
		t.Error("VariableNameMutator: original variable name still present in output")
	}
}

func TestCommentMutator_ModifiesCode(t *testing.T) {
	m := &CommentMutator{config: fullConfig()}
	input := "var a = 1;\nvar b = 2;\nvar c = 3;\n"
	output := m.Mutate(input, 7)
	// Comments may be added — output should differ from input
	if output == input {
		t.Error("CommentMutator: output identical to input, expected modification")
	}
}
