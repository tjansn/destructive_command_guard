//! macOS Seatbelt policy. All literals are escaped, never interpolated as SBPL.

use std::fmt::Write as _;
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
    render(
        project,
        home,
        temp,
        tag,
        &[project.to_path_buf()],
        &[],
        true,
    )
}

/// Real-workspace mode grants writes only to enumerated output paths. Host
/// project sockets are never owned just because they are below the cwd.
pub fn confined_profile(
    project: &Path,
    home: &Path,
    temp: &Path,
    tag: &str,
    writable: &[std::path::PathBuf],
    protected: &[std::path::PathBuf],
) -> String {
    render(project, home, temp, tag, writable, protected, false)
}

fn render(
    project: &Path,
    home: &Path,
    temp: &Path,
    tag: &str,
    writable: &[std::path::PathBuf],
    protected: &[std::path::PathBuf],
    cloned: bool,
) -> String {
    let writes = writable
        .iter()
        .map(|p| format!("(subpath {})", literal(&p.to_string_lossy())))
        .collect::<Vec<_>>()
        .join(" ");
    let protected = protected
        .iter()
        .map(|p| {
            format!(
                "(deny file-write* (subpath {}) (with message {}))",
                literal(&p.to_string_lossy()),
                literal(tag)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let project_sockets = if cloned {
        format!(
            "(local unix-socket (subpath {})) (remote unix-socket (subpath {}))",
            literal(&project.to_string_lossy()),
            literal(&project.to_string_lossy())
        )
    } else {
        String::new()
    };
    let git = literal(&project.join(".git").to_string_lossy());
    let project = literal(&project.to_string_lossy());
    let home = literal(&home.to_string_lossy());
    let temp = literal(&temp.to_string_lossy());
    let tag = literal(tag);
    let secrets = crate::config::home_dir().map_or_else(String::new, |host_home| {
        [
            ".ssh",
            ".aws",
            ".config/gcloud",
            ".kube",
            ".docker/config.json",
            ".netrc",
            ".npmrc",
            ".config/dcg",
            "Library/Application Support/dcg",
            "Library/Keychains",
            "Library/Application Support/Google/Chrome",
            "Library/Application Support/Chromium",
            "Library/Application Support/Firefox",
            "Library/Safari",
            ".mozilla",
            ".config/google-chrome",
            ".config/chromium",
            ".gnupg",
            ".1password",
        ]
        .iter()
        .fold(String::new(), |mut text, name| {
            let _ = writeln!(
                text,
                "(deny file-read* (subpath {}) (with message {tag}))",
                literal(&host_home.join(name).to_string_lossy())
            );
            text
        })
    });
    format!(
        r#"(version 1)
(debug deny)
(allow default)
(deny file-read-data (with message {tag})
  (require-not (require-any
    (subpath {project}) (subpath {home}) (subpath {temp})
    (subpath "/System") (subpath "/usr") (subpath "/bin") (subpath "/sbin")
    (subpath "/Library/Apple") (subpath "/Library/Developer")
    (subpath "/nix/store") (subpath "/opt/homebrew/Cellar") (subpath "/opt/homebrew/opt")
    (literal "/")
    (literal "/opt/homebrew/bin") (literal "/usr/local/bin")
    (literal "/dev/null") (literal "/dev/urandom") (literal "/dev/random")
    (literal "/dev/dtracehelper") (literal "/dev/tty")
    (literal "/private/etc/localtime") (literal "/private/etc/hosts")
    (literal "/private/etc/passwd") (literal "/private/etc/group")
    (literal "/Library/Preferences/Logging/com.apple.diagnosticd.filter.plist")
    (literal "/private/etc/ssl/openssl.cnf")
    (literal "/opt/homebrew/etc/openssl@3/openssl.cnf")
    (literal "/usr/local/etc/openssl@3/openssl.cnf")
    (subpath "/private/var/db/timezone")
    (literal "/private/etc/services") (literal "/private/etc/protocols"))))
(deny file-write* (with message {tag})
  (require-not (require-any
    {writes} (subpath {home}) (subpath {temp})
    (literal "/dev/null") (literal "/dev/dtracehelper")
    (regex #"^/dev/tty[^/]*$"))))
(deny file-write* (subpath {git}) (with message {tag}))
(deny file-link (with message {tag}))
{protected}
(deny network* (with message {tag}))
(allow network-inbound (local ip "localhost:*"))
(allow network-bind (local ip "localhost:*"))
(allow network-inbound network-outbound
  {project_sockets}
  (local unix-socket (subpath {home}))
  (local unix-socket (subpath {temp}))
  (remote unix-socket (subpath {home}))
  (remote unix-socket (subpath {temp})))
(deny appleevent-send user-preference-write (with message {tag}))
(deny mach-lookup (with message {tag}))
(allow mach-lookup
  (global-name "com.apple.system.notification_center")
  (global-name "com.apple.system.opendirectoryd.libinfo")
  (global-name "com.apple.logd")
  (global-name "com.apple.diagnosticd"))
(deny process-info* (target others) (with message {tag}))
(deny signal (target others) (with message {tag}))
(allow signal (target same-sandbox))
{secrets}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbpl_escapes_paths_and_requires_read_and_endpoint_boundaries() {
        let policy = profile(
            Path::new("/tmp/a\"b\\c"),
            Path::new("/tmp/h"),
            Path::new("/tmp/t"),
            "dcg-trial-test",
        );
        assert!(policy.contains("/tmp/a\\\"b\\\\c"));
        assert!(policy.contains("(deny network*"));
        assert!(policy.contains("localhost:*"));
        assert!(!policy.contains("(remote ip"));
        assert!(policy.contains("(deny file-write*"));
        assert!(policy.contains("(target same-sandbox)"));
        assert!(policy.contains("(deny file-read-data"));
        assert!(policy.contains("(deny mach-lookup"));
        assert!(policy.contains("(deny process-info* (target others)"));
    }
}
