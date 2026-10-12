//! macOS Seatbelt policy. All literals are escaped, never interpolated as SBPL.

use std::path::Path;

fn literal(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push('_'),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The control directory (logs, sentinels, manifests) is deliberately unwritable.
pub fn profile(project: &Path, home: &Path, temp: &Path, tag: &str) -> String {
    let git = literal(&project.join(".git").to_string_lossy());
    let project = literal(&project.to_string_lossy());
    let home = literal(&home.to_string_lossy());
    let temp = literal(&temp.to_string_lossy());
    let tag = literal(tag);
    format!(
        r#"(version 1)
(debug deny)
(allow default)
(deny file-write* (with message {tag})
  (require-not (require-any
    (subpath {project}) (subpath {home}) (subpath {temp})
    (literal "/dev/null") (literal "/dev/dtracehelper")
    (regex #"^/dev/tty[^/]*$"))))
(deny file-write* (subpath {git}) (with message {tag}))
(deny network* (with message {tag}))
(allow network-inbound network-outbound (remote ip "localhost:*"))
(allow network-inbound (local ip "localhost:*"))
(allow network-bind (local ip "localhost:*"))
(allow network-inbound network-outbound
  (local unix-socket (subpath {project}))
  (local unix-socket (subpath {home}))
  (local unix-socket (subpath {temp}))
  (remote unix-socket (subpath {project}))
  (remote unix-socket (subpath {home}))
  (remote unix-socket (subpath {temp})))
(deny appleevent-send user-preference-write (with message {tag}))
(deny mach-lookup (with message {tag})
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.securityd")
  (global-name "com.apple.securityd.xpc")
  (global-name "com.apple.security.agent"))
(deny signal (target others) (with message {tag}))
(allow signal (target same-sandbox))
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbpl_escapes_paths_and_only_allows_loopback() {
        let policy = profile(
            Path::new("/tmp/a\"b\\c"),
            Path::new("/tmp/h"),
            Path::new("/tmp/t"),
            "dcg-trial-test",
        );
        assert!(policy.contains("/tmp/a\\\"b\\\\c"));
        assert!(policy.contains("(deny network*"));
        assert!(policy.contains("localhost:*"));
        assert!(!policy.contains("(remote ip \"*"));
        assert!(policy.contains("(deny file-write*"));
        assert!(policy.contains("(target same-sandbox)"));
        assert!(policy.contains("SecurityServer"));
    }
}
