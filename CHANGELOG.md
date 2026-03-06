# Changelog

## [0.2.0] - 2026-03-06

### Added
- **AST vulnerability analysis** using tree-sitter for Python, JavaScript/TypeScript, Java, Go, Rust
  - SQL Injection detection (VULN001)
  - Command Injection detection (VULN002)
  - Path Traversal detection (VULN003)
  - Cross-Site Scripting / XSS detection (VULN004)
  - Insecure Cryptography detection (VULN005)
  - Hardcoded IP Address detection (VULN006)
- **Taint analysis** — tracks data flow from user input sources to dangerous sinks (TAINT001)
- **AI-powered false positive filtering** — supports Ollama, OpenAI, and Anthropic
- **Interactive TUI dashboard** — `guardia scan --tui` for terminal-based vulnerability browsing
- **Git pre-commit hook** — `guardia hook install` / `guardia hook remove`
- **GitHub Actions generator** — `guardia ci` outputs ready-to-use workflow YAML
- Finding deduplication to reduce noise

## [0.1.0] - 2026-03-06

### Added
- Initial release
- **23 secret detection rules** covering AWS, GCP, Azure, GitHub, GitLab, Slack, Discord, Stripe, OpenAI, Anthropic, and more
- **Shannon entropy analysis** for detecting unknown high-entropy secrets
- **Smart filtering** — skips placeholders, test fixtures, environment variable references
- **Parallel scanning** with rayon for multi-core performance
- **3 output formats** — colored terminal, JSON, SARIF 2.1.0
- **Severity filtering** — `--min-severity` flag
- **CI/CD friendly** — exits with code 1 on critical/high findings
- 8 integration tests with comprehensive test fixtures
