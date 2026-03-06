pub struct CweEntry {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub vulnerable_patterns: &'static [&'static str],
    pub mitigations: &'static [&'static str],
    pub severity_guidance: &'static str,
    pub related_cwes: &'static [&'static str],
}

pub static CWE_DATABASE: &[CweEntry] = &[
    CweEntry {
        id: "CWE-89",
        name: "SQL Injection",
        description: "The product constructs all or part of an SQL command using externally-influenced input, which can modify the intended SQL command.",
        vulnerable_patterns: &[
            "String concatenation in SQL: query = \"SELECT * FROM users WHERE id=\" + user_input",
            "f-string in SQL: f\"SELECT * FROM users WHERE id={uid}\"",
            "format() in SQL: \"SELECT * FROM users WHERE id=%s\" % uid",
            ".format() in SQL: \"SELECT ... WHERE id={}\".format(uid)",
            "Template literal: `SELECT * FROM users WHERE id=${id}`",
        ],
        mitigations: &[
            "Use parameterized queries / prepared statements",
            "Use ORM methods instead of raw SQL",
            "Apply input validation (whitelist approach)",
            "Use stored procedures with parameterized inputs",
        ],
        severity_guidance: "Critical when user input reaches SQL without parameterization. High if partial sanitization exists. Medium if behind authentication. Low if input is server-generated.",
        related_cwes: &["CWE-564", "CWE-943"],
    },
    CweEntry {
        id: "CWE-78",
        name: "OS Command Injection",
        description: "The product constructs all or part of an OS command using externally-influenced input, which can execute unintended commands.",
        vulnerable_patterns: &[
            "os.system(user_input)",
            "subprocess.call(cmd, shell=True)",
            "exec(user_input)",
            "Runtime.getRuntime().exec(userInput)",
            "child_process.exec(userInput)",
        ],
        mitigations: &[
            "Avoid shell=True; use subprocess with argument list",
            "Use shlex.quote() for shell escaping",
            "Whitelist allowed commands",
            "Use language-specific APIs instead of shell commands",
        ],
        severity_guidance: "Critical when user input reaches shell execution. High if partial validation exists. Reduced if behind strong authentication.",
        related_cwes: &["CWE-77", "CWE-88"],
    },
    CweEntry {
        id: "CWE-79",
        name: "Cross-site Scripting (XSS)",
        description: "The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output used as a web page.",
        vulnerable_patterns: &[
            "innerHTML = user_input",
            "document.write(user_input)",
            "render_template_string(user_input)",
            "res.send(user_input) without encoding",
            "{{ user_input | safe }} in templates",
        ],
        mitigations: &[
            "Use context-aware output encoding",
            "Use Content-Security-Policy headers",
            "Use auto-escaping template engines",
            "Sanitize with DOMPurify or bleach",
        ],
        severity_guidance: "High for stored XSS. Medium for reflected XSS. Low for DOM-based XSS with limited impact. Consider CSP headers as mitigating factor.",
        related_cwes: &["CWE-80", "CWE-83", "CWE-87"],
    },
    CweEntry {
        id: "CWE-22",
        name: "Path Traversal",
        description: "The product uses external input to construct a pathname to a file without properly neutralizing special elements like '..'.",
        vulnerable_patterns: &[
            "open(user_input)",
            "fs.readFile(user_input)",
            "Path.join(base, user_input) without validation",
            "new File(userInput)",
        ],
        mitigations: &[
            "Validate and canonicalize paths",
            "Use a whitelist of allowed files/directories",
            "Chroot or sandbox file access",
            "Reject paths containing '..' or absolute paths",
        ],
        severity_guidance: "High when arbitrary file read is possible. Critical if write access. Medium if limited to specific directory. Low if file type is restricted.",
        related_cwes: &["CWE-23", "CWE-36"],
    },
    CweEntry {
        id: "CWE-502",
        name: "Deserialization of Untrusted Data",
        description: "The product deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
        vulnerable_patterns: &[
            "pickle.loads(user_data)",
            "yaml.load(data) without SafeLoader",
            "ObjectInputStream.readObject()",
            "JSON.parse() with reviver executing code",
            "unserialize(user_input) in PHP",
        ],
        mitigations: &[
            "Use safe deserialization (yaml.safe_load, JSON)",
            "Validate and sanitize before deserialization",
            "Use allowlists for deserialized classes",
            "Sign serialized data with HMAC",
        ],
        severity_guidance: "Critical for pickle/yaml.load with user input. High for Java deserialization. Medium if input is partially trusted.",
        related_cwes: &["CWE-915"],
    },
    CweEntry {
        id: "CWE-798",
        name: "Use of Hard-coded Credentials",
        description: "The product contains hard-coded credentials such as passwords or cryptographic keys.",
        vulnerable_patterns: &[
            "password = 'hardcoded_value'",
            "API_KEY = 'AKIA...'",
            "secret_key = 'fixed_secret'",
            "private_key = '-----BEGIN RSA PRIVATE KEY-----'",
        ],
        mitigations: &[
            "Use environment variables for secrets",
            "Use a secrets management service (Vault, AWS Secrets Manager)",
            "Use configuration files excluded from version control",
            "Rotate credentials regularly",
        ],
        severity_guidance: "Critical if real production credentials. High if API keys with broad permissions. Medium if test/example credentials. Low if clearly placeholder values.",
        related_cwes: &["CWE-259", "CWE-321"],
    },
    CweEntry {
        id: "CWE-918",
        name: "Server-Side Request Forgery (SSRF)",
        description: "The product receives a URL or similar request from an upstream component and retrieves the contents without validating the target.",
        vulnerable_patterns: &[
            "requests.get(user_url)",
            "urllib.urlopen(user_input)",
            "fetch(user_url)",
            "HttpClient.GetAsync(userUrl)",
        ],
        mitigations: &[
            "Validate and whitelist allowed URLs/domains",
            "Block requests to internal/private IP ranges",
            "Use a URL parser to check scheme and host",
            "Disable redirects or validate redirect targets",
        ],
        severity_guidance: "Critical if can reach internal services. High if can read local files. Medium if limited to specific protocols. Low if URL is partially validated.",
        related_cwes: &["CWE-441"],
    },
    CweEntry {
        id: "CWE-611",
        name: "Improper Restriction of XML External Entity Reference",
        description: "The product processes an XML document that can contain XML entities with URIs that resolve to unintended documents.",
        vulnerable_patterns: &[
            "etree.parse(user_xml)",
            "DocumentBuilderFactory without disabling external entities",
            "XMLReader without secure processing",
            "lxml.etree.fromstring(data) without resolve_entities=False",
        ],
        mitigations: &[
            "Disable external entity processing",
            "Use defusedxml library (Python)",
            "Set XMLConstants.FEATURE_SECURE_PROCESSING",
            "Use JSON instead of XML where possible",
        ],
        severity_guidance: "High when external entities are enabled with user XML. Critical if can read system files. Medium if XML source is semi-trusted.",
        related_cwes: &["CWE-776"],
    },
    CweEntry {
        id: "CWE-352",
        name: "Cross-Site Request Forgery (CSRF)",
        description: "The web application does not sufficiently verify that a request was intentionally provided by the user who submitted it.",
        vulnerable_patterns: &[
            "State-changing GET requests",
            "POST handlers without CSRF token validation",
            "Missing @csrf_protect decorator",
            "SameSite cookie attribute not set",
        ],
        mitigations: &[
            "Use anti-CSRF tokens (synchronizer token pattern)",
            "Set SameSite cookie attribute to Strict or Lax",
            "Verify Origin/Referer headers",
            "Use framework CSRF middleware",
        ],
        severity_guidance: "High for state-changing operations without CSRF protection. Medium if SameSite cookies partially mitigate. Low for read-only operations.",
        related_cwes: &["CWE-346"],
    },
    CweEntry {
        id: "CWE-287",
        name: "Improper Authentication",
        description: "The product does not properly verify that a claim of identity is correct.",
        vulnerable_patterns: &[
            "if user == 'admin': grant_access()",
            "Comparing passwords in plaintext",
            "Missing authentication on sensitive endpoints",
            "JWT verification disabled or using 'none' algorithm",
        ],
        mitigations: &[
            "Use established authentication frameworks",
            "Implement multi-factor authentication",
            "Use bcrypt/argon2 for password hashing",
            "Validate JWT signatures properly",
        ],
        severity_guidance: "Critical if authentication can be bypassed entirely. High if weak authentication on sensitive endpoints. Medium if defense-in-depth exists.",
        related_cwes: &["CWE-306", "CWE-862"],
    },
    CweEntry {
        id: "CWE-862",
        name: "Missing Authorization",
        description: "The product does not perform an authorization check when an actor attempts to access a resource or perform an action.",
        vulnerable_patterns: &[
            "Endpoints without @login_required or auth middleware",
            "Direct object references without ownership check",
            "Admin functions accessible to regular users",
            "Missing role-based access control",
        ],
        mitigations: &[
            "Implement role-based access control (RBAC)",
            "Check authorization on every request",
            "Use middleware/decorators for access control",
            "Implement object-level permissions",
        ],
        severity_guidance: "Critical if admin functions are unprotected. High if sensitive data accessible without auth. Medium if limited to non-sensitive operations.",
        related_cwes: &["CWE-863", "CWE-287"],
    },
    CweEntry {
        id: "CWE-434",
        name: "Unrestricted Upload of File with Dangerous Type",
        description: "The product allows the upload of files without properly validating the file type.",
        vulnerable_patterns: &[
            "Saving uploaded files without extension check",
            "Trusting Content-Type header for validation",
            "Allowing executable file extensions (.php, .jsp, .py)",
            "Missing file content validation (magic bytes)",
        ],
        mitigations: &[
            "Validate file extension against whitelist",
            "Check file content (magic bytes) not just extension",
            "Store uploads outside web root",
            "Rename uploaded files with random names",
        ],
        severity_guidance: "Critical if executable files can be uploaded and accessed. High if stored in web-accessible directory. Medium if some validation exists.",
        related_cwes: &["CWE-351"],
    },
    CweEntry {
        id: "CWE-94",
        name: "Improper Control of Generation of Code (Code Injection)",
        description: "The product constructs all or part of a code segment using externally-influenced input, which can alter the intended code.",
        vulnerable_patterns: &[
            "eval(user_input)",
            "exec(user_input)",
            "new Function(user_input)",
            "compile(user_input, ...)",
            "Template injection: render(user_template)",
        ],
        mitigations: &[
            "Avoid eval/exec with user input entirely",
            "Use sandboxed execution environments",
            "Implement strict input validation",
            "Use AST-based approaches instead of string eval",
        ],
        severity_guidance: "Critical when user input reaches eval/exec. High if partial validation. Medium if input is constrained to specific format.",
        related_cwes: &["CWE-95", "CWE-96"],
    },
    CweEntry {
        id: "CWE-200",
        name: "Exposure of Sensitive Information to an Unauthorized Actor",
        description: "The product exposes sensitive information to an actor not explicitly authorized to have access.",
        vulnerable_patterns: &[
            "Stack traces in production error responses",
            "Debug mode enabled in production",
            "Verbose error messages with internal paths",
            "Logging sensitive data (passwords, tokens)",
        ],
        mitigations: &[
            "Use generic error messages in production",
            "Disable debug mode in production",
            "Sanitize log output",
            "Implement proper error handling",
        ],
        severity_guidance: "High if credentials or tokens are exposed. Medium if internal paths/versions are revealed. Low if only generic information leaks.",
        related_cwes: &["CWE-209", "CWE-532"],
    },
    CweEntry {
        id: "CWE-327",
        name: "Use of a Broken or Risky Cryptographic Algorithm",
        description: "The product uses a broken or risky cryptographic algorithm or protocol.",
        vulnerable_patterns: &[
            "hashlib.md5(password)",
            "DES.new(key)",
            "SHA1 for password hashing",
            "ECB mode encryption",
            "RC4 cipher usage",
        ],
        mitigations: &[
            "Use AES-256-GCM for encryption",
            "Use bcrypt/argon2/scrypt for password hashing",
            "Use SHA-256 or SHA-3 for hashing",
            "Follow current NIST guidelines",
        ],
        severity_guidance: "High for MD5/SHA1 password hashing. Medium for weak encryption in transit. Low if used for non-security purposes (checksums).",
        related_cwes: &["CWE-328", "CWE-916"],
    },
    CweEntry {
        id: "CWE-601",
        name: "URL Redirection to Untrusted Site (Open Redirect)",
        description: "The product accepts a user-controlled URL and redirects the user to it without validation.",
        vulnerable_patterns: &[
            "redirect(request.args.get('next'))",
            "res.redirect(req.query.url)",
            "response.sendRedirect(userUrl)",
            "header('Location: ' . $_GET['url'])",
        ],
        mitigations: &[
            "Validate redirect URLs against whitelist",
            "Use relative URLs only",
            "Check that redirect target is same-origin",
            "Warn users before redirecting to external sites",
        ],
        severity_guidance: "Medium for open redirects (phishing vector). High if combined with OAuth flows. Low if redirect targets are partially validated.",
        related_cwes: &["CWE-918"],
    },
    CweEntry {
        id: "CWE-77",
        name: "Command Injection",
        description: "The product constructs all or part of a command using externally-influenced input but does not neutralize special elements.",
        vulnerable_patterns: &[
            "os.popen(user_input)",
            "subprocess.Popen(cmd, shell=True)",
            "backtick execution: `#{user_input}`",
            "system(user_input) in C",
        ],
        mitigations: &[
            "Use parameterized command execution",
            "Escape shell metacharacters",
            "Use allowlist for command arguments",
            "Avoid shell=True",
        ],
        severity_guidance: "Critical when user input reaches command execution. Same as CWE-78.",
        related_cwes: &["CWE-78", "CWE-88"],
    },
    CweEntry {
        id: "CWE-119",
        name: "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        description: "The product performs operations on a memory buffer without restricting the size of the operation.",
        vulnerable_patterns: &[
            "strcpy without bounds checking",
            "gets() usage",
            "Buffer allocation without size validation",
            "Array index without bounds check",
        ],
        mitigations: &[
            "Use bounds-checked functions (strncpy, snprintf)",
            "Use safe languages (Rust, Go) or safe wrappers",
            "Enable compiler protections (ASLR, stack canaries)",
            "Validate all buffer sizes",
        ],
        severity_guidance: "Critical for exploitable buffer overflows. High if memory corruption is possible. Medium with modern mitigations (ASLR, DEP).",
        related_cwes: &["CWE-120", "CWE-787"],
    },
    CweEntry {
        id: "CWE-732",
        name: "Incorrect Permission Assignment for Critical Resource",
        description: "The product specifies permissions for a security-critical resource in a way that allows unintended actors to access it.",
        vulnerable_patterns: &[
            "chmod 777 on sensitive files",
            "World-readable credentials files",
            "Overly permissive IAM policies",
            "Public S3 buckets with sensitive data",
        ],
        mitigations: &[
            "Apply principle of least privilege",
            "Set restrictive file permissions (600/640)",
            "Review IAM policies regularly",
            "Use infrastructure-as-code for permission management",
        ],
        severity_guidance: "Critical if credentials are world-readable. High for overly permissive cloud resources. Medium for non-sensitive files.",
        related_cwes: &["CWE-276"],
    },
    CweEntry {
        id: "CWE-306",
        name: "Missing Authentication for Critical Function",
        description: "The product does not perform any authentication for functionality that requires a provable user identity.",
        vulnerable_patterns: &[
            "Admin endpoints without authentication middleware",
            "API endpoints missing auth decorators",
            "Sensitive operations accessible without login",
            "Management interfaces exposed without auth",
        ],
        mitigations: &[
            "Require authentication for all sensitive endpoints",
            "Use authentication middleware/filters",
            "Implement defense-in-depth with network controls",
            "Audit endpoint access controls regularly",
        ],
        severity_guidance: "Critical for admin/management functions without auth. High for data modification endpoints. Medium for read-only sensitive data.",
        related_cwes: &["CWE-287", "CWE-862"],
    },
];

pub fn lookup_by_cwe_id(cwe_id: &str) -> Option<&'static CweEntry> {
    CWE_DATABASE.iter().find(|e| e.id == cwe_id)
}

pub fn lookup_by_rule_id(rule_id: &str) -> Option<&'static CweEntry> {
    let cwe_id = rule_id_to_cwe(rule_id)?;
    lookup_by_cwe_id(cwe_id)
}

fn rule_id_to_cwe(rule_id: &str) -> Option<&'static str> {
    match rule_id {
        "VULN001" => Some("CWE-89"),
        "VULN002" => Some("CWE-78"),
        "VULN003" => Some("CWE-79"),
        "VULN004" => Some("CWE-22"),
        "VULN005" => Some("CWE-502"),
        "VULN006" => Some("CWE-918"),
        "VULN007" => Some("CWE-611"),
        "VULN008" => Some("CWE-352"),
        "VULN009" => Some("CWE-287"),
        "VULN010" => Some("CWE-862"),
        "VULN011" => Some("CWE-434"),
        "VULN012" => Some("CWE-94"),
        "VULN013" => Some("CWE-200"),
        "VULN014" => Some("CWE-327"),
        "VULN015" => Some("CWE-601"),
        "VULN016" => Some("CWE-77"),
        "VULN017" => Some("CWE-119"),
        "VULN018" => Some("CWE-732"),
        "VULN019" => Some("CWE-306"),
        "SEC001" | "SEC002" | "SEC003" | "SEC004" | "SEC005" => Some("CWE-798"),
        "TAINT001" => Some("CWE-89"),
        "TAINT002" => Some("CWE-78"),
        "TAINT003" => Some("CWE-79"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cwe_database_not_empty() {
        assert!(CWE_DATABASE.len() >= 20);
    }

    #[test]
    fn test_lookup_sql_injection() {
        let entry = lookup_by_cwe_id("CWE-89").unwrap();
        assert_eq!(entry.name, "SQL Injection");
        assert!(!entry.vulnerable_patterns.is_empty());
        assert!(!entry.mitigations.is_empty());
    }

    #[test]
    fn test_lookup_by_rule_id() {
        let entry = lookup_by_rule_id("VULN001").unwrap();
        assert_eq!(entry.id, "CWE-89");
    }

    #[test]
    fn test_secret_rule_maps_to_hardcoded_creds() {
        let entry = lookup_by_rule_id("SEC001").unwrap();
        assert_eq!(entry.id, "CWE-798");
    }

    #[test]
    fn test_unknown_rule_returns_none() {
        assert!(lookup_by_rule_id("UNKNOWN999").is_none());
    }

    #[test]
    fn test_all_entries_have_required_fields() {
        for entry in CWE_DATABASE {
            assert!(!entry.id.is_empty());
            assert!(!entry.name.is_empty());
            assert!(!entry.description.is_empty());
            assert!(!entry.vulnerable_patterns.is_empty());
            assert!(!entry.mitigations.is_empty());
            assert!(!entry.severity_guidance.is_empty());
        }
    }
}
