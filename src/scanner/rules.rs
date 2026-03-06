use colored::Colorize;

use super::Severity;
use super::secret;

pub fn print_rules() {
    println!("\n{}\n", " Guardia Detection Rules ".bold().on_cyan().black());

    println!(
        "  {:<10} {:<8} {}",
        "Rule ID".bold(),
        "Level".bold(),
        "Description".bold()
    );
    println!("  {}", "─".repeat(70));

    println!("  {}", "Secret Detection".dimmed().italic());
    let rules = secret::get_rules_info();
    for (id, title, _desc, severity) in &rules {
        print_rule_line(id, title, severity);
    }

    println!("\n  {}", "AST Vulnerability Analysis".dimmed().italic());
    let ast_rules: Vec<(&str, &str, Severity)> = vec![
        ("VULN001", "SQL Injection", Severity::Critical),
        ("VULN002", "Command Injection", Severity::Critical),
        ("VULN003", "Path Traversal", Severity::High),
        ("VULN004", "Cross-Site Scripting (XSS)", Severity::High),
        ("VULN005", "Insecure Cryptography", Severity::Medium),
        ("VULN006", "Hardcoded IP Address", Severity::Low),
    ];
    for (id, title, severity) in &ast_rules {
        print_rule_line(id, title, severity);
    }

    println!("\n  {}", "Taint Analysis".dimmed().italic());
    print_rule_line("TAINT001", "Tainted Data Flow (source → sink)", &Severity::High);

    let total = rules.len() + ast_rules.len() + 1;
    println!(
        "\n  {} rules loaded",
        total.to_string().green().bold()
    );
    println!(
        "  Plus: {} for detecting unknown secrets",
        "entropy analysis".italic()
    );
    println!(
        "  Languages: {}\n",
        "Python, JavaScript/TypeScript, Java, Go, Rust".cyan()
    );
}

fn print_rule_line(id: &str, title: &str, severity: &Severity) {
    let severity_str = match severity {
        Severity::Critical => "CRIT".red().bold().to_string(),
        Severity::High => "HIGH".yellow().bold().to_string(),
        Severity::Medium => "MED ".blue().to_string(),
        Severity::Low => "LOW ".dimmed().to_string(),
    };
    println!("  {:<10} {} {}", id.cyan(), severity_str, title);
}
