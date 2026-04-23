# coraza-rule-validator

A standalone CLI tool for validating ModSecurity/Coraza WAF rules before deployment.

Uses the [Coraza WAF](https://github.com/corazawaf/coraza) engine to parse and compile rules, catching errors that static analysis might miss — including regex compilation issues, unknown variables, invalid operators, and more.

## Why?

Static analysis of ModSecurity rules (e.g., in PHP or Python) can miss issues that only appear at runtime:

- Regex patterns that compile in one engine but fail in RE2 (Go's regex engine)
- Backslash normalization issues across file write/read cycles
- Variable names that don't exist in Coraza
- Operators or actions not supported by Coraza

This tool runs the actual Coraza parser, giving you the same validation that would happen when your WAF loads the rules — but without starting a server.

## Installation

### From Source

```bash
go install github.com/stardothosting/coraza-rule-validator@latest
```

### Build Locally

```bash
git clone https://github.com/stardothosting/coraza-rule-validator.git
cd coraza-rule-validator
go build -o coraza-rule-validator .
```

## Usage

```bash
# Validate a single .conf file
coraza-rule-validator -conf /etc/caddy/rules/custom.conf

# Validate multiple files with glob pattern
coraza-rule-validator -conf "/etc/caddy/adaptive-ruleset/*.conf"

# Validate inline directives
coraza-rule-validator -directives 'SecRule REQUEST_URI "@rx ^/admin" "id:1,phase:1,deny"'

# Read from stdin
cat rules.conf | coraza-rule-validator -stdin

# JSON output for CI/CD
coraza-rule-validator -conf rules.conf -json
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Rules are valid |
| 1    | Rules have errors |
| 2    | Usage/input error |

## JSON Output Format

When using `-json`, the output includes the Coraza engine version:

```json
{
  "valid": false,
  "message": "Rule validation failed",
  "coraza_engine": "v3.7.0",
  "errors": [
    {
      "type": "regex_compilation",
      "message": "error parsing regexp: missing closing ): `(?sm)(invalid`",
      "pattern": "(?sm)(invalid",
      "file": "/path/to/rules.conf",
      "line": 47,
      "rule_id": "12345"
    }
  ]
}
```

### Error Types

- `regex_compilation` - Invalid regex pattern
- `unknown_variable` - Variable not supported by Coraza
- `unknown_operator` - Operator not supported by Coraza
- `invalid_action` - Action not supported by Coraza
- `file_not_found` - Include file doesn't exist
- `secdefaultaction_error` - SecDefaultAction configuration issue
- `parse_error` - General parsing error

## Integration Examples

### Laravel (PHP)

```php
use Illuminate\Process\Process;

private function validateRules(string $confPath): bool
{
    $process = Process::run([
        '/usr/local/bin/coraza-rule-validator',
        '-conf', $confPath,
        '-json'
    ]);
    
    if (!$process->successful()) {
        $result = json_decode($process->output(), true);
        foreach ($result['errors'] ?? [] as $error) {
            Log::error('Rule validation failed', $error);
        }
        return false;
    }
    
    return true;
}
```

### CI/CD Pipeline

```yaml
# GitHub Actions
- name: Validate WAF Rules
  run: |
    coraza-rule-validator -conf "rules/*.conf" -json || exit 1
```

```bash
# Shell script
if ! coraza-rule-validator -conf "$RULES_DIR/*.conf" -json; then
    echo "Rule validation failed, aborting deployment"
    exit 1
fi
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

RULES_CHANGED=$(git diff --cached --name-only | grep '\.conf$')
if [ -n "$RULES_CHANGED" ]; then
    for file in $RULES_CHANGED; do
        if ! coraza-rule-validator -conf "$file"; then
            echo "Validation failed for: $file"
            exit 1
        fi
    done
fi
```

## Binary Size Comparison

| Tool | Size |
|------|------|
| coraza-rule-validator | ~17 MB |
| Full Caddy + coraza-caddy | ~65 MB |

The standalone validator is ~75% smaller because it doesn't include Caddy's HTTP server, TLS, admin API, etc.

## Version Compatibility

The validator reports which Coraza engine version it uses:

```bash
$ coraza-rule-validator -version
coraza-rule-validator version dev (coraza engine v3.7.0)
```

Ensure your deployment environment uses a compatible Coraza version. If your production WAF uses an older version, rules that pass validation here may behave differently there.

## License

Apache-2.0 — same as Coraza.
