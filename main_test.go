// Copyright 2025 The coraza-rule-validator authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateRules(t *testing.T) {
	tests := []struct {
		name       string
		directives string
		wantValid  bool
		errorType  string
	}{
		{
			name:       "valid simple rule",
			directives: `SecRule REQUEST_URI "@rx ^/admin" "id:1,phase:1,deny"`,
			wantValid:  true,
		},
		{
			name:       "valid rule with SecRuleEngine",
			directives: "SecRuleEngine On\nSecRule REQUEST_URI \"@rx ^/test\" \"id:100,phase:1,deny\"",
			wantValid:  true,
		},
		{
			name:       "valid multiple rules",
			directives: "SecRule REQUEST_URI \"@rx ^/admin\" \"id:1,phase:1,deny\"\nSecRule REQUEST_URI \"@rx ^/api\" \"id:2,phase:1,log\"",
			wantValid:  true,
		},
		{
			name:       "invalid regex - unclosed paren",
			directives: `SecRule REQUEST_URI "@rx (test" "id:1,phase:1,deny"`,
			wantValid:  false,
			errorType:  "regex_compilation",
		},
		{
			name:       "invalid regex - unclosed bracket",
			directives: `SecRule REQUEST_URI "@rx [test" "id:1,phase:1,deny"`,
			wantValid:  false,
			errorType:  "regex_compilation",
		},
		{
			name:       "valid complex regex",
			directives: `SecRule REQUEST_URI "@rx ^/api/v[0-9]+/users/[a-zA-Z0-9_-]+$" "id:1,phase:1,log"`,
			wantValid:  true,
		},
		{
			name:       "valid rule with multiple actions",
			directives: `SecRule REQUEST_URI "@rx ^/admin" "id:1,phase:1,deny,status:403,log,msg:'Admin blocked'"`,
			wantValid:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateRules(tt.directives, "<test>")

			if result.Valid != tt.wantValid {
				t.Errorf("validateRules() valid = %v, want %v", result.Valid, tt.wantValid)
				if !result.Valid {
					for _, e := range result.Errors {
						t.Logf("  Error type=%s, message=%s", e.Type, e.Message)
					}
				}
			}

			if !tt.wantValid && tt.errorType != "" {
				if len(result.Errors) == 0 {
					t.Errorf("expected errors but got none")
				} else if result.Errors[0].Type != tt.errorType {
					t.Errorf("error type = %v, want %v", result.Errors[0].Type, tt.errorType)
				}
			}
		})
	}
}

func TestValidateRulesFromFile(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "coraza-rule-validator-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name      string
		content   string
		wantValid bool
	}{
		{
			name:      "valid conf file",
			content:   "SecRule REQUEST_URI \"@rx ^/admin\" \"id:1,phase:1,deny\"\nSecRule REQUEST_URI \"@rx ^/api\" \"id:2,phase:1,log\"",
			wantValid: true,
		},
		{
			name:      "invalid conf file - bad regex",
			content:   "SecRule REQUEST_URI \"@rx (invalid\" \"id:1,phase:1,deny\"",
			wantValid: false,
		},
		{
			name:      "empty file",
			content:   "",
			wantValid: true,
		},
		{
			name:      "comments only",
			content:   "# This is a comment\n# Another comment",
			wantValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write test file
			testFile := filepath.Join(tmpDir, tt.name+".conf")
			if err := os.WriteFile(testFile, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to write test file: %v", err)
			}

			// Validate via Include directive
			directives := "Include " + testFile
			result := validateRules(directives, testFile)

			if result.Valid != tt.wantValid {
				t.Errorf("validateRules() valid = %v, want %v", result.Valid, tt.wantValid)
				if !result.Valid {
					for _, e := range result.Errors {
						t.Logf("  Error type=%s, message=%s", e.Type, e.Message)
					}
				}
			}
		})
	}
}

func TestParseCorazaError(t *testing.T) {
	tests := []struct {
		name          string
		errMsg        string
		expectedType  string
		hasPattern    bool
		expectedCount int
	}{
		{
			name:          "regex compilation error",
			errMsg:        "error parsing regexp: missing closing ): `(test`",
			expectedType:  "regex_compilation",
			hasPattern:    true,
			expectedCount: 1,
		},
		{
			name:          "unknown variable error",
			errMsg:        "unknown variable: FAKE_VAR",
			expectedType:  "unknown_variable",
			expectedCount: 1,
		},
		{
			name:          "unknown operator error",
			errMsg:        "unknown operator: @fakeOp",
			expectedType:  "unknown_operator",
			expectedCount: 1,
		},
		{
			name:          "invalid action error",
			errMsg:        `invalid action "fakeaction"`,
			expectedType:  "invalid_action",
			expectedCount: 1,
		},
		{
			name:          "generic error",
			errMsg:        "some unknown error occurred",
			expectedType:  "parse_error",
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &testError{msg: tt.errMsg}
			errors := parseCorazaError(err)

			if len(errors) != tt.expectedCount {
				t.Errorf("parseCorazaError() returned %d errors, want %d", len(errors), tt.expectedCount)
				return
			}

			if len(errors) > 0 && errors[0].Type != tt.expectedType {
				t.Errorf("error type = %v, want %v", errors[0].Type, tt.expectedType)
			}

			if tt.hasPattern && len(errors) > 0 && errors[0].Pattern == "" {
				t.Errorf("expected pattern to be extracted but was empty")
			}
		})
	}
}

// testError implements error interface for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
