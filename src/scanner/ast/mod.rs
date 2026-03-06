mod languages;
mod taint;
mod vuln_rules;

use std::path::PathBuf;

use crate::scanner::Finding;

pub use taint::TaintAnalyzer;

pub fn scan_ast(file_path: &PathBuf, content: &str, findings: &mut Vec<Finding>) {
    let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    let lang = match languages::get_language(ext) {
        Some(l) => l,
        None => return,
    };

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&lang).is_err() {
        return;
    }

    let tree = match parser.parse(content, None) {
        Some(t) => t,
        None => return,
    };

    let root = tree.root_node();
    let source = content.as_bytes();
    let lang_id = languages::ext_to_lang_id(ext);

    vuln_rules::check_sql_injection(&root, source, file_path, lang_id, findings);
    vuln_rules::check_command_injection(&root, source, file_path, lang_id, findings);
    vuln_rules::check_path_traversal(&root, source, file_path, lang_id, findings);
    vuln_rules::check_xss(&root, source, file_path, lang_id, findings);
    vuln_rules::check_insecure_crypto(&root, source, file_path, lang_id, findings);
    vuln_rules::check_hardcoded_ip(&root, source, file_path, lang_id, findings);

    let mut taint = TaintAnalyzer::new(lang_id);
    taint.analyze(&root, source, file_path, findings);
}

