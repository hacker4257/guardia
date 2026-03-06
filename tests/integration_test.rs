use std::process::Command;

fn guardia_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_guardia"))
}

#[test]
fn test_scan_finds_vulnerabilities() {
    let output = guardia_cmd()
        .args(["scan", "tests/fixtures/vulnerable_python.py", "--no-progress"])
        .output()
        .expect("Failed to execute guardia");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        combined.contains("GitHub Token") || combined.contains("SEC020"),
        "Should detect GitHub tokens. Output: {}",
        combined
    );
    assert!(
        combined.contains("Security Findings"),
        "Should show findings header. Output: {}",
        combined
    );
}

#[test]
fn test_scan_safe_code_no_findings() {
    let output = guardia_cmd()
        .args(["scan", "tests/fixtures/safe_code.py", "--no-progress"])
        .output()
        .expect("Failed to execute guardia");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        combined.contains("No security issues found"),
        "Safe code should have no findings. Output: {}",
        combined
    );

    assert!(output.status.success(), "Should exit with code 0 for safe code");
}

#[test]
fn test_json_output() {
    let output = guardia_cmd()
        .args([
            "scan",
            "tests/fixtures/vulnerable_python.py",
            "--format",
            "json",
            "--no-progress",
        ])
        .output()
        .expect("Failed to execute guardia");

    let stdout = String::from_utf8_lossy(&output.stdout);

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    assert!(parsed["findings"].is_array());
    assert!(parsed["summary"]["total"].as_u64().unwrap() > 0);
}

#[test]
fn test_sarif_output() {
    let output = guardia_cmd()
        .args([
            "scan",
            "tests/fixtures/vulnerable_python.py",
            "--format",
            "sarif",
            "--no-progress",
        ])
        .output()
        .expect("Failed to execute guardia");

    let stdout = String::from_utf8_lossy(&output.stdout);

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid SARIF JSON");

    assert_eq!(parsed["version"], "2.1.0");
    assert!(parsed["runs"][0]["results"].is_array());
}

#[test]
fn test_rules_command() {
    let output = guardia_cmd()
        .args(["rules"])
        .output()
        .expect("Failed to execute guardia");

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("SEC001"));
    assert!(stdout.contains("AWS Access Key"));
    assert!(stdout.contains("rules loaded"));
}

#[test]
fn test_private_key_detection() {
    let output = guardia_cmd()
        .args([
            "scan",
            "tests/fixtures/private_key.pem",
            "--format",
            "json",
            "--no-progress",
        ])
        .output()
        .expect("Failed to execute guardia");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    let findings = parsed["findings"].as_array().unwrap();
    assert!(
        findings.iter().any(|f| f["rule_id"] == "SEC050"),
        "Should detect RSA private key"
    );
}

#[test]
fn test_exit_code_on_critical() {
    let output = guardia_cmd()
        .args(["scan", "tests/fixtures/vulnerable_python.py", "--no-progress"])
        .output()
        .expect("Failed to execute guardia");

    assert!(
        !output.status.success(),
        "Should exit with non-zero code when critical issues found"
    );
}

#[test]
fn test_min_severity_filter() {
    let output = guardia_cmd()
        .args([
            "scan",
            "tests/fixtures/vulnerable_python.py",
            "--format",
            "json",
            "--no-progress",
            "--min-severity",
            "critical",
        ])
        .output()
        .expect("Failed to execute guardia");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    let findings = parsed["findings"].as_array().unwrap();
    for f in findings {
        assert_eq!(
            f["severity"], "CRITICAL",
            "All findings should be CRITICAL when filtered"
        );
    }
}
