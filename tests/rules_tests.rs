#[path = "../src/rules.rs"]
mod rules;
#[path = "../src/types.rs"]
mod types;

use std::collections::HashSet;

use rules::RuleSet;

#[test]
fn flags_known_bad_hash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("sample.bin");
    std::fs::write(&file_path, b"bad-payload").expect("write sample");
    let digest = rules::sha256(&file_path).expect("hash");

    let rules = RuleSet {
        known_bad_hashes: HashSet::from([digest]),
        suspicious_names: HashSet::new(),
        suspicious_extensions: HashSet::new(),
        max_file_mb: 200,
    };

    let findings = rules.evaluate(&file_path);
    assert!(findings.iter().any(|f| f.rule_id == "hash.known_bad"));
}

#[test]
fn flags_suspicious_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("postinstall");
    std::fs::write(&file_path, b"echo hello").expect("write sample");

    let rules = RuleSet {
        known_bad_hashes: HashSet::new(),
        suspicious_names: HashSet::from(["postinstall".to_string()]),
        suspicious_extensions: HashSet::new(),
        max_file_mb: 200,
    };

    let findings = rules.evaluate(&file_path);
    assert!(findings.iter().any(|f| f.rule_id == "name.suspicious"));
}
