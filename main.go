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
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3"
)

// Version is set at build time
var Version = "dev"

// ValidationResult represents the outcome of WAF rule validation
type ValidationResult struct {
	Valid   bool              `json:"valid"`
	Message string            `json:"message,omitempty"`
	Errors  []ValidationError `json:"errors,omitempty"`
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
		fmt.Printf("coraza-rule-validator version %s\n", Version)
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

	switch {
	case *confPath != "":
		// Wrap file path in Include directive (Coraza handles glob expansion)
		directives = fmt.Sprintf("Include %s", *confPath)
		inputSource = *confPath

	case *directivesStr != "":
		directives = *directivesStr
		inputSource = "<directives>"

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
	}

	result := validateRules(directives)

	if *outputJSON {
		output, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			os.Exit(2)
		}
		fmt.Println(string(output))
	} else {
		if result.Valid {
			fmt.Printf("✓ Rules are valid (%s)\n", inputSource)
		} else {
			fmt.Printf("✗ Rules are invalid (%s)\n", inputSource)
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

// validateRules validates ModSecurity/Coraza directives using the Coraza engine
func validateRules(directives string) ValidationResult {
	config := coraza.NewWAFConfig().WithDirectives(directives)

	_, err := coraza.NewWAF(config)
	if err != nil {
		return ValidationResult{
			Valid:   false,
			Message: "Rule validation failed",
			Errors:  parseCorazaError(err),
		}
	}

	return ValidationResult{
		Valid:   true,
		Message: "All rules are valid",
	}
}

// parseCorazaError extracts structured error information from Coraza errors
func parseCorazaError(err error) []ValidationError {
	if err == nil {
		return nil
	}

	errStr := err.Error()
	var errors []ValidationError

	// Match known error patterns and classify them
	if matches := regexp.MustCompile(`error parsing regexp: ([^:]+): \x60([^\x60]+)\x60`).FindStringSubmatch(errStr); len(matches) > 2 {
		return []ValidationError{{Type: "regex_compilation", Message: errStr, Pattern: matches[2]}}
	}
	if matches := regexp.MustCompile(`unknown variable: (\w+)`).FindStringSubmatch(errStr); len(matches) > 1 {
		return []ValidationError{{Type: "unknown_variable", Message: errStr}}
	}
	if matches := regexp.MustCompile(`unknown operator: @?(\w+)`).FindStringSubmatch(errStr); len(matches) > 1 {
		return []ValidationError{{Type: "unknown_operator", Message: errStr}}
	}
	if matches := regexp.MustCompile(`invalid action "([^"]+)"`).FindStringSubmatch(errStr); len(matches) > 1 {
		return []ValidationError{{Type: "invalid_action", Message: errStr}}
	}
	if matches := regexp.MustCompile(`(?:cannot|failed to) (?:open|read|include) ["\x60]?([^"\x60\n]+)["\x60]?`).FindStringSubmatch(errStr); len(matches) > 1 {
		return []ValidationError{{Type: "file_not_found", Message: errStr, File: matches[1]}}
	}
	if regexp.MustCompile(`SecDefaultAction`).MatchString(errStr) {
		return []ValidationError{{Type: "secdefaultaction_error", Message: errStr}}
	}

	// Extract metadata from unrecognized errors
	var ruleID, filePath string
	var lineNum int
	if matches := regexp.MustCompile(`(?:rule|id)[:\s]+(\d+)`).FindStringSubmatch(strings.ToLower(errStr)); len(matches) > 1 {
		ruleID = matches[1]
	}
	if matches := regexp.MustCompile(`line[:\s]+(\d+)`).FindStringSubmatch(strings.ToLower(errStr)); len(matches) > 1 {
		fmt.Sscanf(matches[1], "%d", &lineNum)
	}
	if matches := regexp.MustCompile(`(?:file|in)\s+["\x60]?([^\s"'\x60]+\.conf)["\x60]?`).FindStringSubmatch(errStr); len(matches) > 1 {
		filePath = matches[1]
	}

	errors = append(errors, ValidationError{
		Type:    "parse_error",
		Message: errStr,
		RuleID:  ruleID,
		Line:    lineNum,
		File:    filePath,
	})

	return errors
}
