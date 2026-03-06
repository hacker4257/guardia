<p align="center">
  <h1 align="center">Guardia 🛡️</h1>
  <p align="center">
    <strong>AI-enhanced code security scanner — blazing fast, multi-language, with LLM-powered false positive filtering</strong>
  </p>
  <p align="center">
    <a href="https://crates.io/crates/guardia"><img src="https://img.shields.io/crates/v/guardia.svg" alt="Crates.io"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
    <a href="https://github.com/hacker4257/guardia/actions"><img src="https://img.shields.io/github/actions/workflow/status/hacker4257/guardia/ci.yml?label=CI" alt="CI"></a>
  </p>
</p>

---

Guardia is a **Rust-powered** security scanner that detects hardcoded secrets, code vulnerabilities, and tainted data flows in your codebase. It combines **regex pattern matching**, **tree-sitter AST analysis**, **taint tracking**, and **AI-powered false positive filtering** to deliver fast, accurate results.

## Features

- **30+ detection rules** — secrets, SQL injection, XSS, command injection, and more
- **5 languages** — Python, JavaScript/TypeScript, Java, Go, Rust
- **AI false positive filtering** — Ollama (offline), OpenAI, Anthropic
- **Interactive TUI** — terminal dashboard for browsing findings
- **Parallel scanning** — multi-core with rayon
- **SARIF output** — integrates with GitHub Code Scanning
- **Git hooks** — pre-commit scanning out of the box
- **Single binary** — no runtime dependencies, ~8MB

## Quick Start

### Install

```bash
cargo install guardia
```

Or download a prebuilt binary from [Releases](https://github.com/hacker4257/guardia/releases).

### Scan

```bash
# Scan current directory
guardia scan

# Scan a specific path
guardia scan ./my-project

# Only show high/critical severity
guardia scan --min-severity high

# JSON output for CI/CD
guardia scan --format json

# SARIF output for GitHub Code Scanning
guardia scan --format sarif > results.sarif

# Only scan for secrets (skip AST analysis)
guardia scan --secret-only

# Interactive TUI dashboard
guardia scan --tui

# AI-enhanced scan (requires Ollama running locally)
guardia scan --ai --ai-model llama3

# AI with OpenAI
OPENAI_API_KEY=sk-... guardia scan --ai --ai-provider openai --ai-model gpt-4o

# List all rules
guardia rules
```

### Example Output

```
   ___                     _ _
  / _ \_   _  __ _ _ __ __| (_) __ _
 / /_\/ | | |/ _` | '__/ _` | |/ _` |
/ /_\\| |_| | (_| | | | (_| | | (_| |
\____/ \__,_|\__,_|_|  \__,_|_|\__,_|

  AI-Enhanced Code Security Scanner v0.2.0

 Security Findings

  #1  CRITICAL  Command Injection [VULN002]
  File: app/utils.py:6
  Desc: System command executed with dynamic input.
     6 │ os.system("ping -c 1 " + user_input)
  Fix: Use subprocess with a list of arguments instead of shell=True.

  #2  CRITICAL  GitHub Token [SEC020]
  File: config.py:19
  Desc: Hardcoded GitHub personal access token detected.
    19 │ GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOP..."
  Fix: Use GitHub Actions secrets or environment variables.

  #3  HIGH  Cross-Site Scripting (XSS) [VULN004]
  File: public/app.js:5
  Desc: Unsafe DOM manipulation that may allow script injection.
     5 │ document.getElementById('output').innerHTML = userData;
  Fix: Use textContent instead of innerHTML.

  #4  HIGH  Tainted Data Flow [TAINT001]
  File: app/db.py:8
  Desc: Variable 'user_input' flows into a dangerous sink without sanitization.
     8 │ cursor.execute(query)
  Fix: Validate and sanitize all user input.

────────────────────────────────────────────────────────────
  Summary: 4 findings in 0.03s

    ● 2 critical
    ● 2 high
```

## Detection Rules

### Secret Detection (23 rules)

| Category | Rules | Examples |
|----------|-------|---------|
| Cloud Providers | SEC001-SEC004 | AWS, GCP, Azure keys |
| API Keys & Tokens | SEC010-SEC013 | Generic keys, Bearer/Basic auth |
| VCS & CI/CD | SEC020-SEC021 | GitHub, GitLab tokens |
| Communication | SEC030-SEC032 | Slack, Discord webhooks |
| Database | SEC040 | Connection strings with credentials |
| Private Keys | SEC050-SEC052 | RSA, SSH, PGP keys |
| Payment | SEC060-SEC061 | Stripe, Square keys |
| AI/LLM Providers | SEC070-SEC071 | OpenAI, Anthropic keys |
| JWT | SEC080 | Hardcoded JSON Web Tokens |
| Environment Files | SEC090 | Secrets in .env files |
| Entropy | SEC100 | High-entropy unknown strings |

### AST Vulnerability Analysis (6 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| VULN001 | Critical | SQL Injection via string concatenation |
| VULN002 | Critical | Command Injection via os.system/subprocess |
| VULN003 | High | Path Traversal with unsanitized input |
| VULN004 | High | Cross-Site Scripting (innerHTML, document.write) |
| VULN005 | Medium | Insecure Cryptography (MD5, SHA1, DES) |
| VULN006 | Low | Hardcoded IP Address |

### Taint Analysis (1 rule)

| Rule | Severity | Description |
|------|----------|-------------|
| TAINT001 | High | User input flows to dangerous sink without sanitization |

## AI-Powered Analysis

Guardia can use LLMs to filter false positives and suggest fixes:

```bash
# Ollama (local, private — recommended)
guardia scan --ai --ai-provider ollama --ai-model llama3

# OpenAI
OPENAI_API_KEY=sk-... guardia scan --ai --ai-provider openai --ai-model gpt-4o

# Anthropic Claude
ANTHROPIC_API_KEY=sk-ant-... guardia scan --ai --ai-provider anthropic --ai-model claude-sonnet-4-20250514
```

The AI engine:
1. Reviews each finding with surrounding code context
2. Determines if it's a true positive or false positive (with confidence score)
3. Suggests specific code fixes for confirmed vulnerabilities

## Git Integration

### Pre-commit Hook

```bash
# Install — scans staged files before each commit
guardia hook install

# Remove
guardia hook remove
```

### GitHub Actions

```bash
# Generate a ready-to-use workflow
guardia ci > .github/workflows/guardia.yml
```

Or add manually:

```yaml
- name: Install Guardia
  run: cargo install guardia
- name: Security Scan
  run: guardia scan --format sarif --no-progress > results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Interactive TUI

```bash
guardia scan --tui
```

Navigate findings with keyboard shortcuts:

| Key | Action |
|-----|--------|
| `↑↓` / `jk` | Navigate findings |
| `Enter` | Toggle detail panel |
| `g` / `G` | Jump to top / bottom |
| `q` | Quit |

## Comparison

| Feature | Gitleaks | TruffleHog | Semgrep | **Guardia** |
|---------|----------|------------|---------|-------------|
| Language | Go | Go | OCaml | **Rust** |
| Secret Detection | ✅ | ✅ | ✅ | ✅ |
| AST Analysis | ❌ | ❌ | ✅ | ✅ |
| Taint Tracking | ❌ | ❌ | Paid | ✅ |
| AI False Positive Filter | ❌ | ❌ | Paid | **✅ Free** |
| AI Fix Suggestions | ❌ | ❌ | ❌ | ✅ |
| Interactive TUI | ❌ | ❌ | ❌ | ✅ |
| SARIF Output | ✅ | ✅ | ✅ | ✅ |
| Parallel Scanning | ❌ | ❌ | ❌ | ✅ |
| Single Binary | ✅ | ✅ | ❌ | ✅ |

## Contributing

Contributions are welcome! Please open an issue or submit a PR.

## License

MIT License. See [LICENSE](LICENSE) for details.
