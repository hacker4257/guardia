use tree_sitter::Language;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LangId {
    Python,
    JavaScript,
    Java,
    Go,
    Rust,
}

pub fn get_language(ext: &str) -> Option<Language> {
    match ext {
        "py" => Some(tree_sitter_python::LANGUAGE.into()),
        "js" | "jsx" | "ts" | "tsx" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "rs" => Some(tree_sitter_rust::LANGUAGE.into()),
        _ => None,
    }
}

pub fn ext_to_lang_id(ext: &str) -> LangId {
    match ext {
        "py" => LangId::Python,
        "js" | "jsx" | "ts" | "tsx" => LangId::JavaScript,
        "java" => LangId::Java,
        "go" => LangId::Go,
        "rs" => LangId::Rust,
        _ => LangId::JavaScript,
    }
}
