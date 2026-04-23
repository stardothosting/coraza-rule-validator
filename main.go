// Copyright 2025 The coraza-rule-validator authors
// SPDX-License-Identifier: Apache-2.0

// coraza-rule-validator is a standalone CLI tool for validating ModSecurity/Coraza
// WAF rules before deployment. It uses the Coraza WAF engine to parse and compile
// rules, catching errors that static analysis might miss.
//
// Usage:
//
//	coraza-rule-validator --conf /path/to/rules.conf
//	coraza-rule-validator --conf "/path/to/rules/*.conf"
//	coraza-rule-validator --directives 'SecRule REQUEST_URI "@rx ^/admin" "id:1,phase:1,deny"'
//	echo 'SecRule ...' | coraza-rule-validator --stdin
//	coraza-rule-validator --conf rules.conf --json
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3"
)

// Version is set at build time
var Version = "dev"

// CorazaVersion reflects the coraza/v3 dependency version in go.mod
// Update this when upgrading the Coraza dependency
const CorazaVersion = "v3.7.0"

// ValidationResult represents the outcome of WAF rule validation
type ValidationResult struct {
	Valid        bool              `json:"valid"`
	Message      string            `json:"message,omitempty"`
	Errors       []ValidationError `json:"errors,omitempty"`
	CorazaEngine string            `json:"coraza_engine,omitempty"`
}

// ValidationError represents a single validation error with context
type ValidationError struct {
	Type    string `json:"type"`              // error type: regex_compilation, parse_error, etc.
	Message string `json:"message"`           // full error message
	File    string `json:"file,omitempty"`    // file where error occurred (if known)
	Line    int    `json:"line,omitempty"`    // line number (if known)
	RuleID  string `json:"rule_id,omitempty"` // rule ID (if known)
	Pattern string `json:"pattern,omitempty"` // problematic pattern (for regex errors)
}

func main() {
	confPath := flag.String("conf", "", "Path to .conf file or glob pattern to validate")
	directivesStr := flag.String("directives", "", "Raw directives string to validate")
	useStdin := flag.Bool("stdin", false, "Read directives from stdin")
	outputJSON := flag.Bool("json", false, "Output results as JSON")
	findLine := flag.Bool("find-line", false, "Binary search to find exact line number of errors (slower)")
	showVersion := flag.Bool("version", false, "Show version and exit")
	showHelp := flag.Bool("help", false, "Show help and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `coraza-rule-validator - Validate ModSecurity/Coraza WAF rules

A standalone CLI tool that validates WAF rules using the Coraza engine.
Use this to catch rule errors before deploying to production.

Usage:
  coraza-rule-validator [options]

Input Options (mutually exclusive):
  -conf <path>        Path to .conf file or glob pattern (e.g., "/etc/caddy/rules/*.conf")
  -directives <str>   Raw directives string to validate
  -stdin              Read directives from standard input

Output Options:
  -json               Output validation results as JSON (default: plain text)
  -find-line          Binary search to find exact line number of errors (slower)

Other Options:
  -version            Show version and exit
  -help               Show this help message

Exit Codes:
  0  Configuration is valid
  1  Configuration has errors
  2  Usage/input error

Examples:
  # Validate a single file
  coraza-rule-validator -conf /etc/caddy/rules/custom.conf

  # Validate multiple files with glob
  coraza-rule-validator -conf "/etc/caddy/adaptive-ruleset/*.conf"

  # Validate inline rule
  coraza-rule-validator -directives 'SecRule REQUEST_URI "@rx ^/admin" "id:1,phase:1,deny"'

  # Validate from stdin with JSON output
  cat rules.conf | coraza-rule-validator -stdin -json

  # Use in CI/CD pipeline
  coraza-rule-validator -conf rules.conf -json || exit 1

`)
	}

	flag.Parse()

	if *showHelp {
		flag.Usage()
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf("coraza-rule-validator version %s (coraza engine %s)\n", Version, CorazaVersion)
		os.Exit(0)
	}

	inputCount := 0
	if *confPath != "" {
		inputCount++
	}
	if *directivesStr != "" {
		inputCount++
	}
	if *useStdin {
		inputCount++
	}

	if inputCount == 0 {
		fmt.Fprintln(os.Stderr, "Error: one of -conf, -directives, or -stdin is required")
		fmt.Fprintln(os.Stderr, "Run with -help for usage information")
		os.Exit(2)
	}
	if inputCount > 1 {
		fmt.Fprintln(os.Stderr, "Error: only one of -conf, -directives, or -stdin may be specified")
		fmt.Fprintln(os.Stderr, "Run with -help for usage information")
		os.Exit(2)
	}

	var directives string
	var inputSource string

	var result ValidationResult

	switch {
	case *confPath != "":
		inputSource = *confPath
		// Expand glob pattern and validate files individually for better error reporting
		files, err := filepath.Glob(*confPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error expanding glob pattern: %v\n", err)
			os.Exit(2)
		}
		if len(files) == 0 {
			fmt.Fprintf(os.Stderr, "No files matched pattern: %s\n", *confPath)
			os.Exit(2)
		}
		result = validateFiles(files, *findLine)

	case *directivesStr != "":
		directives = *directivesStr
		inputSource = "<directives>"
		result = validateRules(directives, inputSource)

	case *useStdin:
		scanner := bufio.NewScanner(os.Stdin)
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(2)
		}
		directives = strings.Join(lines, "\n")
		inputSource = "<stdin>"
		result = validateRules(directives, inputSource)
	}

	if *outputJSON {
		output, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			os.Exit(2)
		}
		fmt.Println(string(output))
	} else {
		if result.Valid {
			fmt.Printf("✓ Rules are valid (%s) [coraza %s]\n", inputSource, CorazaVersion)
		} else {
			fmt.Printf("✗ Rules are invalid (%s) [coraza %s]\n", inputSource, CorazaVersion)
			fmt.Println()
			for i, e := range result.Errors {
				fmt.Printf("Error %d:\n", i+1)
				fmt.Printf("  Type: %s\n", e.Type)
				fmt.Printf("  Message: %s\n", e.Message)
				if e.File != "" {
					fmt.Printf("  File: %s\n", e.File)
				}
				if e.Line > 0 {
					fmt.Printf("  Line: %d\n", e.Line)
				}
				if e.RuleID != "" {
					fmt.Printf("  Rule ID: %s\n", e.RuleID)
				}
				if e.Pattern != "" {
					fmt.Printf("  Pattern: %s\n", e.Pattern)
				}
				fmt.Println()
			}
		}
	}

	if result.Valid {
		os.Exit(0)
	}
	os.Exit(1)
}

// validateFiles validates multiple rule files individually for better error reporting
func validateFiles(files []string, findLine bool) ValidationResult {
	var allErrors []ValidationError
	validCount := 0

	for _, file := range files {
		absPath, err := filepath.Abs(file)
		if err != nil {
			allErrors = append(allErrors, ValidationError{
				Type:    "file_read_error",
				Message: err.Error(),
				File:    file,
			})
			continue
		}

		config := coraza.NewWAFConfig().WithDirectivesFromFile(absPath)
		_, err = coraza.NewWAF(config)
		if err != nil {
			errors := parseCorazaError(err)
			for i := range errors {
				if errors[i].File == "" {
					errors[i].File = file
				}
				if findLine && errors[i].Line == 0 {
					errors[i].Line = findErrorLine(absPath, errors[i].Type)
				}
			}
			allErrors = append(allErrors, errors...)
		} else {
			validCount++
		}
	}

	if len(allErrors) > 0 {
		return ValidationResult{
			Valid:        false,
			Message:      fmt.Sprintf("Validation failed: %d file(s) with errors, %d valid", len(files)-validCount, validCount),
			Errors:       allErrors,
			CorazaEngine: CorazaVersion,
		}
	}

	return ValidationResult{
		Valid:        true,
		Message:      fmt.Sprintf("All %d file(s) are valid", len(files)),
		CorazaEngine: CorazaVersion,
	}
}

// findErrorLine uses binary search to find the line number that causes an error
func findErrorLine(filePath string, errorType string) int {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return 0
	}

	lines := strings.Split(string(content), "\n")
	totalLines := len(lines)

	// Binary search to find the first line that causes an error
	low, high := 0, totalLines
	for low < high {
		mid := (low + high) / 2
		subset := strings.Join(lines[:mid+1], "\n")

		config := coraza.NewWAFConfig().WithDirectives(subset)
		_, err := coraza.NewWAF(config)

		if err != nil && strings.Contains(err.Error(), errorType) {
			high = mid
		} else if err != nil {
			// Different error, might be incomplete rule
			high = mid
		} else {
			low = mid + 1
		}
	}

	if low < totalLines {
		return low + 1 // Convert to 1-indexed
	}
	return 0
}

// validateRules validates ModSecurity/Coraza directives using the Coraza engine
func validateRules(directives string, source string) ValidationResult {
	config := coraza.NewWAFConfig().WithDirectives(directives)

	_, err := coraza.NewWAF(config)
	if err != nil {
		errors := parseCorazaError(err)
		for i := range errors {
			if errors[i].File == "" {
				errors[i].File = source
			}
		}
		return ValidationResult{
			Valid:        false,
			Message:      "Rule validation failed",
			Errors:       errors,
			CorazaEngine: CorazaVersion,
		}
	}

	return ValidationResult{
		Valid:        true,
		Message:      "All rules are valid",
		CorazaEngine: CorazaVersion,
	}
}

// parseCorazaError extracts structured error information from Coraza errors
func parseCorazaError(err error) []ValidationError {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Extract common metadata first
	var ruleID, filePath string
	var lineNum int

	// ModSecurity-style [file "..."] [line "..."] format
	if matches := regexp.MustCompile(`\[file\s+"([^"]+)"\]`).FindStringSubmatch(errStr); len(matches) > 1 {
		filePath = matches[1]
	}
	if matches := regexp.MustCompile(`\[line\s+"?(\d+)"?\]`).FindStringSubmatch(errStr); len(matches) > 1 {
		fmt.Sscanf(matches[1], "%d", &lineNum)
	}
	if matches := regexp.MustCompile(`\[id\s+"?(\d+)"?\]`).FindStringSubmatch(errStr); len(matches) > 1 {
		ruleID = matches[1]
	}

	// Fallback patterns
	if filePath == "" {
		if matches := regexp.MustCompile(`(?:file|in)\s+["\x60]?([^\s"'\x60]+\.conf)["\x60]?`).FindStringSubmatch(errStr); len(matches) > 1 {
			filePath = matches[1]
		}
	}
	if lineNum == 0 {
		if matches := regexp.MustCompile(`line[:\s]+(\d+)`).FindStringSubmatch(strings.ToLower(errStr)); len(matches) > 1 {
			fmt.Sscanf(matches[1], "%d", &lineNum)
		}
	}
	if ruleID == "" {
		if matches := regexp.MustCompile(`(?:rule|id)[:\s]+(\d+)`).FindStringSubmatch(strings.ToLower(errStr)); len(matches) > 1 {
			ruleID = matches[1]
		}
	}

	// Classify error type
	var errType string
	var pattern string

	switch {
	case regexp.MustCompile(`error parsing regexp`).MatchString(errStr):
		errType = "regex_compilation"
		if matches := regexp.MustCompile(`\x60([^\x60]+)\x60`).FindStringSubmatch(errStr); len(matches) > 1 {
			pattern = matches[1]
		}
	case regexp.MustCompile(`unknown variable`).MatchString(errStr):
		errType = "unknown_variable"
	case regexp.MustCompile(`unknown operator`).MatchString(errStr):
		errType = "unknown_operator"
	case regexp.MustCompile(`invalid action`).MatchString(errStr):
		errType = "invalid_action"
	case regexp.MustCompile(`(?:cannot|failed to) (?:open|read|include)`).MatchString(errStr):
		errType = "file_not_found"
	case regexp.MustCompile(`SecDefaultAction`).MatchString(errStr):
		errType = "secdefaultaction_error"
	default:
		errType = "parse_error"
	}

	return []ValidationError{{
		Type:    errType,
		Message: errStr,
		File:    filePath,
		Line:    lineNum,
		RuleID:  ruleID,
		Pattern: pattern,
	}}
}
