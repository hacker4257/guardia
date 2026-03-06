use anyhow::Result;
use std::fs;

const PRE_COMMIT_HOOK: &str = r#"#!/bin/sh
# Guardia pre-commit hook — scans staged files for security issues
# Install: guardia hook install
# Remove:  guardia hook remove

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

echo "🛡️  Guardia: scanning staged files..."

FAILED=0
for FILE in $STAGED_FILES; do
    if [ -f "$FILE" ]; then
        guardia scan "$FILE" --no-progress --min-severity high 2>/dev/null
        if [ $? -ne 0 ]; then
            FAILED=1
        fi
    fi
done

if [ $FAILED -ne 0 ]; then
    echo ""
    echo "❌ Guardia found security issues in staged files."
    echo "   Fix the issues above or use 'git commit --no-verify' to skip."
    exit 1
fi

echo "✅ Guardia: no security issues found."
exit 0
"#;

pub fn install_hook() -> Result<()> {
    let git_dir = find_git_dir()?;
    let hooks_dir = git_dir.join("hooks");

    if !hooks_dir.exists() {
        fs::create_dir_all(&hooks_dir)?;
    }

    let hook_path = hooks_dir.join("pre-commit");

    if hook_path.exists() {
        let existing = fs::read_to_string(&hook_path)?;
        if existing.contains("guardia") {
            println!("  Guardia pre-commit hook is already installed.");
            return Ok(());
        }
        let backup = hooks_dir.join("pre-commit.backup");
        fs::copy(&hook_path, &backup)?;
        println!("  Backed up existing hook to pre-commit.backup");

        let combined = format!("{}\n\n# --- Guardia hook appended ---\n{}", existing, PRE_COMMIT_HOOK);
        fs::write(&hook_path, combined)?;
    } else {
        fs::write(&hook_path, PRE_COMMIT_HOOK)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&hook_path, perms)?;
    }

    println!("  ✓ Guardia pre-commit hook installed at {}", hook_path.display());
    println!("  Staged files will be scanned before each commit.");
    Ok(())
}

pub fn remove_hook() -> Result<()> {
    let git_dir = find_git_dir()?;
    let hook_path = git_dir.join("hooks").join("pre-commit");

    if !hook_path.exists() {
        println!("  No pre-commit hook found.");
        return Ok(());
    }

    let content = fs::read_to_string(&hook_path)?;
    if !content.contains("guardia") {
        println!("  Pre-commit hook exists but was not installed by Guardia.");
        return Ok(());
    }

    if content.contains("# --- Guardia hook appended ---") {
        let parts: Vec<&str> = content.splitn(2, "# --- Guardia hook appended ---").collect();
        fs::write(&hook_path, parts[0].trim_end())?;
        println!("  ✓ Guardia hook removed. Original hook preserved.");
    } else {
        fs::remove_file(&hook_path)?;
        let backup = git_dir.join("hooks").join("pre-commit.backup");
        if backup.exists() {
            fs::rename(&backup, &hook_path)?;
            println!("  ✓ Guardia hook removed. Restored backup.");
        } else {
            println!("  ✓ Guardia pre-commit hook removed.");
        }
    }

    Ok(())
}

fn find_git_dir() -> Result<std::path::PathBuf> {
    let mut dir = std::env::current_dir()?;
    loop {
        let git = dir.join(".git");
        if git.exists() {
            return Ok(git);
        }
        if !dir.pop() {
            anyhow::bail!("Not a git repository. Run this command inside a git project.");
        }
    }
}

pub fn generate_github_action() -> &'static str {
    r#"name: Guardia Security Scan
on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Install Guardia
        run: cargo install guardia

      - name: Run Security Scan
        run: guardia scan --format sarif --no-progress > results.sarif
        continue-on-error: true

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Check for critical issues
        run: guardia scan --min-severity high --no-progress
"#
}
