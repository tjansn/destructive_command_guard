//! End-to-end coverage for `core.filesystem:credential-file-write`.
//!
//! Runs the real binary in hook mode against an isolated `HOME` so the
//! verdicts below are exactly what a harness sees: writes to credential,
//! private-key, login-shell startup, and system authentication files are
//! denied by this rule whether the file exists or not and for every writer
//! spelling, while reads, `chmod`, the `*.pub` and `known_hosts` neighbours,
//! and unrelated files keep their ordinary verdicts. A user allowlist entry
//! for the rule lifts exactly this rule and nothing else.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Allow,
    Deny(&'static str),
}

/// Rule names a denial can be attributed to in these fixtures.
const RULES: &[&str] = &[
    "credential-file-write",
    "redirect-truncate-root-home",
    "redirect-truncate-dynamic-path",
    "mv-sensitive-source-root-home",
    "mv-dynamic-path",
    "dd-overwrite-root-home",
    "sed-exec-unverified",
];

/// Evaluate one shell command in hook mode with `home` as `$HOME`.
fn verdict(command: &str, home: &Path) -> Verdict {
    let config_path = home.join("dcg-test-config.toml");
    if !config_path.exists() {
        fs::write(&config_path, "").expect("write empty config");
    }
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string();

    let mut child = Command::new(dcg_binary())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("xdg_config"))
        .env("DCG_CONFIG", &config_path)
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            home.join("pending_exceptions.jsonl"),
        )
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env_remove("DCG_FAIL_CLOSED")
        .spawn()
        .expect("spawn dcg");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let output = child.wait_with_output().expect("wait for dcg");
    assert_eq!(
        output.status.code(),
        Some(0),
        "hook protocol exit code for {command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains(r#""permissionDecision":"deny""#) {
        let rule = RULES
            .iter()
            .copied()
            .find(|rule| stdout.contains(rule))
            .unwrap_or_else(|| panic!("unexpected rule for {command:?}: {stdout}"));
        Verdict::Deny(rule)
    } else {
        assert!(
            stdout.trim().is_empty(),
            "allow must be an empty response for {command:?}: {stdout}"
        );
        Verdict::Allow
    }
}

/// Every writer spelling the rule covers, for one target path.
fn writers(path: &str) -> Vec<String> {
    vec![
        format!("echo x > {path}"),
        format!("echo x >> {path}"),
        format!("printf x >| {path}"),
        format!("echo x &> {path}"),
        format!("echo x 2> {path}"),
        format!("cat <<EOF > {path}\nline\nEOF"),
        format!("echo x | tee {path}"),
        format!("echo x | tee -a {path}"),
        format!("cp /tmp/src {path}"),
        format!("mv /tmp/src {path}"),
        format!("install -m 600 /tmp/src {path}"),
        format!("ln -sf /tmp/src {path}"),
        format!("dd if=/tmp/src of={path}"),
        format!("sed -i 's/a/b/' {path}"),
        format!("perl -pi -e 's/a/b/' {path}"),
    ]
}

fn fixture_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("temp home");
    let root = home.path();
    for dir in [
        ".ssh",
        ".aws",
        ".config/gh",
        ".gnupg",
        ".bashrc.d",
        ".claude",
        "xdg_config/dcg",
    ] {
        fs::create_dir_all(root.join(dir)).expect("fixture dir");
    }
    for (file, content) in [
        (".ssh/authorized_keys", "ssh-ed25519 AAAA existing"),
        (".ssh/known_hosts", "host ssh-ed25519 AAAA"),
        (".ssh/id_ed25519.pub", "ssh-ed25519 AAAA"),
        (".zshrc", "export EXISTING=1"),
        (".aws/credentials", "[default]"),
        ("notes.txt", "notes"),
    ] {
        fs::write(root.join(file), content).expect("fixture file");
    }
    home
}

fn fixture_bytes(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut seen = Vec::new();
    fn walk(dir: &Path, root: &Path, seen: &mut Vec<(String, Vec<u8>)>) {
        for entry in fs::read_dir(dir).expect("read fixture dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                walk(&path, root, seen);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .expect("under root")
                    .to_string_lossy()
                    .into_owned();
                // dcg's own state (the empty config, the pending allow-once
                // store) is not a fixture.
                if relative.starts_with("xdg_config")
                    || relative == "dcg-test-config.toml"
                    || relative == "pending_exceptions.jsonl"
                {
                    continue;
                }
                seen.push((relative, fs::read(&path).expect("read fixture")));
            }
        }
    }
    walk(root, root, &mut seen);
    seen.sort();
    seen
}

#[test]
fn credential_file_writes_are_denied_absent_or_existing_for_every_writer() {
    let home = fixture_home();
    let home = home.path();
    let before = fixture_bytes(home);

    // Existing and absent targets alike, across the whole list.
    let targets = [
        "~/.ssh/authorized_keys", // existing
        "~/.ssh/config",          // absent
        "~/.ssh/id_ed25519",      // absent private key
        "~/.zshrc",               // existing
        "~/.bashrc",              // absent
        "~/.zshenv",
        "~/.profile",
        "~/.bash_profile",
        "~/.zprofile",
        "~/.bashrc.d/10-path.sh",
        "~/.zshrc.d/aliases.zsh",
        "~/.aws/credentials", // existing
        "~/.aws/config",      // absent
        "~/.netrc",
        "~/.git-credentials",
        "~/.npmrc",
        "~/.pypirc",
        "~/.docker/config.json",
        "~/.kube/config",
        "~/.gnupg/gpg-agent.conf",
        "~/.config/gh/hosts.yml",
        "~/.pgpass",
        "~/.cargo/credentials.toml",
        "~/.config/gcloud/application_default_credentials.json",
        "/etc/sudoers",
        "/etc/sudoers.d/agent",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d/10-root.conf",
    ];
    for target in targets {
        for command in writers(target) {
            assert_eq!(
                verdict(&command, home),
                Verdict::Deny("credential-file-write"),
                "{command}"
            );
        }
    }

    // Spellings of the same files.
    for command in [
        "echo x >> $HOME/.zshrc",
        "echo x >> \"$HOME/.zshrc\"",
        "echo x >> ${HOME}/.ssh/authorized_keys",
        "echo x >> ~/.zsh\"rc\"",
        "echo x >> ~/'.zshrc'",
        "echo x >> ~/.zshr\\c",
        "echo x >> ~/.zshr{c..c}",
        "echo x >> ~/.zshrc{,}",
        "echo x >> ~/{.zshrc,absent}",
        "echo x >> ~/.ssh/id_*",
        "echo x >> ~/.ssh/../.zshrc",
        "echo x >> /home/somebody/.zshrc",
        "echo x >> /Users/somebody/.ssh/authorized_keys",
        "echo x >> ~root/.ssh/authorized_keys",
        "echo x | sudo tee -a /etc/sudoers.d/agent",
        "sudo -u root tee /etc/passwd",
        "echo x | t''ee ~/.zshrc",
        "echo x | \\tee ~/.zshrc",
        "bash -c 'echo x >> ~/.zshrc'",
        "cd /tmp && echo x >> ~/.npmrc",
        "true; echo x >> ~/.npmrc",
        "cp id_ed25519 ~/.ssh/",
        "cp -t ~/.ssh id_ed25519",
        "cp credentials ~/.aws/",
        "cp .zshrc ~/",
        "cp -r dotfiles/. ~/",
        "cp -- src ~/.zshrc",
        "tee -- ~/.zshrc",
        "sed -i -- 's/a/b/' ~/.zshrc",
        "echo x > /tmp/ok > ~/.zshrc",
        "echo x | tee /tmp/ok ~/.npmrc",
    ] {
        assert_eq!(
            verdict(command, home),
            Verdict::Deny("credential-file-write"),
            "{command}"
        );
    }

    // The trust store may be appended to (what ssh does) but not replaced.
    for command in [
        "echo x >> ~/.ssh/known_hosts",
        "ssh-keyscan host >> ~/.ssh/known_hosts",
        "echo x | tee -a ~/.ssh/known_hosts",
    ] {
        assert_eq!(verdict(command, home), Verdict::Allow, "{command}");
    }
    for command in [
        "echo x > ~/.ssh/known_hosts",
        "echo x | tee ~/.ssh/known_hosts",
        "cp /tmp/kh ~/.ssh/known_hosts",
        "sed -i '/host/d' ~/.ssh/known_hosts",
    ] {
        assert_eq!(
            verdict(command, home),
            Verdict::Deny("credential-file-write"),
            "{command}"
        );
    }

    // Reads, permission changes, public keys, and unrelated files.
    for command in [
        "cat ~/.ssh/config",
        "cat ~/.zshrc",
        "grep -rn Host ~/.ssh/",
        "diff ~/.zshrc /tmp/x",
        "source ~/.zshrc",
        "ssh -F ~/.ssh/config host",
        "chmod 600 ~/.ssh/authorized_keys",
        "chmod 700 ~/.ssh",
        "ls -la ~/.ssh",
        "cp ~/.ssh/config /tmp/backup",
        "cat ~/.ssh/id_ed25519.pub",
        "echo x >> ~/.ssh/id_ed25519.pub",
        "echo x >> ~/notes.txt",
        "echo x > ~/.claude/absent.txt",
        "echo x >> ~/.config/gh/config.yml",
        "cp report.txt ~/",
        "cp *.png ~/",
        "cp -r build ~/.claude/",
        "sed -n '/PATH/p' ~/.zshrc",
        "sed -i 's/a/b/' ~/notes.txt",
        "tee /tmp/out < ~/.zshrc",
        "echo 'echo x >> ~/.zshrc'",
        "cat <<'EOF'\necho x >> ~/.zshrc\nEOF",
        "install -d -m 700 ~/.ssh",
        "mkdir -p ~/.ssh",
        "echo x >> ~/notes-{a,b}.txt",
    ] {
        assert_eq!(verdict(command, home), Verdict::Allow, "{command}");
    }

    // Neighbours keep their ordinary verdicts: an existing unlisted file is
    // still a truncation, an absent one is still creation.
    assert_eq!(
        verdict("echo x > ~/notes.txt", home),
        Verdict::Deny("redirect-truncate-root-home")
    );
    assert_eq!(
        verdict("echo x > ~/.ssh/id_ed25519.pub", home),
        Verdict::Deny("redirect-truncate-root-home")
    );
    assert_eq!(verdict("echo x > ~/.ssh/absent.pub", home), Verdict::Allow);
    assert_eq!(
        verdict("echo x > /etc/hosts", home),
        Verdict::Deny("redirect-truncate-root-home")
    );

    // Evaluating never touched the fixtures.
    assert_eq!(fixture_bytes(home), before);
    assert!(!home.join(".ssh/config").exists());
    assert!(!home.join(".npmrc").exists());
}

#[test]
fn allowlisting_the_rule_lifts_only_that_rule() {
    let home = fixture_home();
    let home = home.path();
    fs::write(
        home.join("xdg_config/dcg/allowlist.toml"),
        "[[allow]]\nrule = \"core.filesystem:credential-file-write\"\nreason = \"this project manages its own dotfiles\"\n",
    )
    .expect("write allowlist");

    // The credential rule stands down for an absent and an appended file.
    assert_eq!(verdict("echo x >> ~/.npmrc", home), Verdict::Allow);
    assert_eq!(verdict("echo x >> ~/.zshrc", home), Verdict::Allow);
    assert_eq!(
        verdict("echo x | tee -a ~/.ssh/config", home),
        Verdict::Allow
    );
    // Truncating an EXISTING file is still the redirect rule's call.
    assert_eq!(
        verdict("echo x > ~/.zshrc", home),
        Verdict::Deny("redirect-truncate-root-home")
    );
    assert_eq!(
        verdict("echo x > /etc/passwd", home),
        Verdict::Deny("redirect-truncate-root-home")
    );
}

/// Home roots other than `/home`, `/Users`, `/root` and `/var/root` (#502),
/// through the real hook: on v0.14.4 the append and `tee -a` rows below were
/// all allowed, and `/volume1/homes` had no incidental cover for `>` either.
#[test]
fn unlisted_home_roots_are_guarded_through_the_hook() {
    let home = fixture_home();
    let home = home.path();
    for root in [
        "/var/services/homes/luna",
        "/volume1/homes/luna",
        "/volume10/homes/luna",
        "/export/home/luna",
        "/var/home/luna",
        "/usr/home/luna",
    ] {
        for file in [".ssh/authorized_keys", ".zshrc", ".netrc", ".npmrc"] {
            let path = format!("{root}/{file}");
            for command in [
                format!("echo x >> {path}"),
                format!("echo x | tee -a {path}"),
                format!("cp /tmp/src {path}"),
            ] {
                assert_ne!(verdict(&command, home), Verdict::Allow, "{command}");
            }
        }
        assert_eq!(
            verdict(&format!("echo x >> {root}/notes.txt"), home),
            Verdict::Allow,
            "{root}: ordinary files stay writable"
        );
        assert_eq!(
            verdict(&format!("echo x >> {root}/.ssh/known_hosts"), home),
            Verdict::Allow,
            "{root}: the known_hosts append carve-out holds"
        );
    }
    // `.` ahead of the root, found probing the same fix.
    for command in [
        "echo x >> /home/./luna/.netrc",
        "echo x >> /./home/luna/.netrc",
        "echo x >> /home/../home/luna/.netrc",
    ] {
        assert_ne!(verdict(command, home), Verdict::Allow, "{command}");
    }
}

/// The hook's own `$HOME` is a home root wherever it lives (#502), e.g. a
/// container's `HOME=/app` or a NAS share no fixed list names.
#[test]
fn the_runtime_home_is_a_home_root_through_the_hook() {
    let home = tempfile::Builder::new()
        .prefix("nashome")
        .tempdir()
        .expect("temp home");
    let root = home.path();
    fs::create_dir_all(root.join("xdg_config/dcg")).expect("fixture dir");
    let spelled = root.to_str().expect("utf-8 temp path");
    for file in [".netrc", ".npmrc", ".pypirc", ".zshrc"] {
        let command = format!("echo x >> {spelled}/{file}");
        assert_eq!(
            verdict(&command, root),
            Verdict::Deny("credential-file-write"),
            "{command}"
        );
    }
    assert_eq!(
        verdict(&format!("echo x >> {spelled}/notes.txt"), root),
        Verdict::Allow
    );
}

#[cfg(target_os = "macos")]
#[test]
fn runtime_home_credentials_are_guarded_across_tmp_and_private_tmp_spellings() {
    let home = tempfile::Builder::new()
        .prefix("dcg-credential-home")
        .tempdir_in("/private/tmp")
        .expect("private temp home");
    let private = home.path().to_path_buf();
    let short = Path::new("/").join(private.strip_prefix("/private").unwrap());
    assert_eq!(
        private.canonicalize().unwrap(),
        short.canonicalize().unwrap()
    );
    fs::create_dir_all(private.join("xdg_config/dcg")).expect("fixture dir");
    // Pass both HOME spellings to real, separate hooks; candidate writers are
    // only protocol data and must never create the named credential files.
    for root in [&private, &short] {
        for target in [&private, &short] {
            for file in [".netrc", ".npmrc", ".pypirc", ".zshrc"] {
                let path = target.join(file);
                let command = format!("echo x >> {}", shell_words::quote(path.to_str().unwrap()));
                assert_eq!(
                    verdict(&command, root),
                    Verdict::Deny("credential-file-write")
                );
                assert!(!path.exists());
            }
            let command = format!("echo x >> {}/notes.txt", target.display());
            assert_eq!(verdict(&command, root), Verdict::Allow);
        }
    }
}

/// Spellings of a home or system root that the review of #502 found still
/// open through the hook: a quote splitting the root's name (the candidate
/// gate searched the raw text for `/home/`), a backslash-escaped first
/// character of a redirect target (no core.filesystem keyword matched `> \`,
/// so the pack never ran), and prefixes that only re-spell `/` — macOS's
/// `/System/Volumes/Data` firmlink and Linux's `/proc/<pid>/root` — plus root's
/// real macOS home `/private/var/root`. All were allowed before the fix.
#[test]
fn quoted_escaped_and_aliased_roots_are_guarded_through_the_hook() {
    let home = fixture_home();
    let home = home.path();
    for command in [
        "echo x >> \"/home\"/luna/.netrc",
        "echo x >> /ho\"me\"/luna/.netrc",
        "echo x >> /var/services/'homes'/luna/.netrc",
        "echo x >> /volume1/ho\"mes\"/luna/.npmrc",
        "echo x >> \\/home/luna/.netrc",
        "echo x > \\/etc/passwd",
        "echo x >\\/etc/sudoers",
        "echo x >> /System/Volumes/Data/Users/luna/.netrc",
        "echo x >> /System/Volumes/Data/private/etc/sudoers",
        "cp /tmp/src /System/Volumes/Data/Users/luna/.pypirc",
        "echo x >> /proc/self/root/home/luna/.netrc",
        "echo x | tee -a /proc/1/root/etc/sudoers",
        "echo x >> /private/var/root/.netrc",
    ] {
        assert_ne!(verdict(command, home), Verdict::Allow, "{command}");
    }
    for command in [
        "echo x >> \"/home\"/luna/notes.txt",
        "echo x >> /System/Volumes/Data/Users/luna/notes.txt",
        "echo x >> /proc/self/root/tmp/out.txt",
    ] {
        assert_eq!(verdict(command, home), Verdict::Allow, "{command}");
    }
}

/// Found in the second review of #502, all allowed through the hook on
/// c8b77a1: ANSI-C numeric escapes spelling a separator, a glob, brace list
/// or expansion in a root's own name (`/e?c` also carried no gate needle),
/// `/proc/<pid>/task/<tid>/root`, macOS's `/.nofollow` and
/// `/Volumes/Macintosh HD`, and a base nothing can read — a relative climb out
/// of the working directory (whose `> ..` target selected no pack), a
/// process's working directory, or a substitution spelling the root — plus
/// zsh/extglob alternation in a root's name and a Windows profile mounted by
/// WSL or Git Bash.
#[test]
fn rewritten_and_unknown_base_roots_are_guarded_through_the_hook() {
    let home = fixture_home();
    let home = home.path();
    for command in [
        "echo x >> $'\\x2fetc/sudoers'",
        "echo x >> /home/luna/$'\\x2enetrc'",
        "echo x >> /e?c/sudoers",
        "echo x | tee -a /h?me/luna/.netrc",
        "echo x >> /{home,tmp}/luna/.netrc",
        "cp ./x /*/luna/.npmrc",
        "echo x >> /et${x}c/sudoers",
        "echo x >> /proc/self/task/1/root/home/luna/.netrc",
        "echo x >> /.nofollow/private/etc/sudoers",
        "echo x >> '/Volumes/Macintosh HD/Users/luna/.netrc'",
        "echo x >> ../../../../../../etc/sudoers",
        "echo x >> ./../../../../etc/sudoers",
        "echo x >> /proc/1/cwd/etc/sudoers",
        "echo x >> $x/etc/sudoers",
        "echo x >> $(printf /)etc/sudoers",
        "echo x >> `printf /`etc/sudoers",
        "echo x | tee -a /(etc|x)/sudoers",
        "echo x >> /@(etc)/sudoers",
        "echo x >> /mnt/c/Users/luna/.netrc",
        "echo x >> /c/Users/luna/.npmrc",
    ] {
        assert_ne!(verdict(command, home), Verdict::Allow, "{command}");
    }
    for command in [
        "echo x >> ../notes.md",
        "echo x >> ../etc/app.conf",
        "cp ./x $OUT/passwd",
        "echo x >> /e?c/notes.txt",
        "ls src/*.rs > /tmp/files.txt",
    ] {
        assert_eq!(verdict(command, home), Verdict::Allow, "{command}");
    }
}

/// Third review of #502. A bracket expression whose first member is `]`
/// (`/e[]t]c` is `/etc`) and a brace list whose alternatives span a `/`
/// (`/{tmp/x,etc/sudoers}` expands to two words) were allowed; a long run of
/// rewritable components (`/*/*/…`, `/$x/$x/…`) and a source glob of many
/// `*?` pairs held the hook for over a minute. The slow ones must answer
/// within the hook's own budget, and fail closed rather than time out.
#[test]
fn bracket_brace_and_pathological_roots_are_guarded_in_bounded_time() {
    let home = fixture_home();
    let home = home.path();
    let deep_stars = format!("echo x >> /{}sudoers", "*/".repeat(5000));
    let deep_expansions = format!("echo x >> /{}sudoers", "$x/".repeat(5000));
    let star_pairs = format!("cp ./{} ~/.config/gcloud/", "*?".repeat(40));
    for command in [
        "echo x >> /e[]t]c/sudoers",
        "echo x >> /e[!]x]c/sudoers",
        "echo x >> /[[:lower:]]tc/sudoers",
        "echo x | tee -a /{etc/sudoers,tmp/x}",
        "echo x | tee -a /{tmp/x,etc/sudoers}",
        "cp ./x /{tmp/y,home/luna/.netrc}",
        "echo x | tee -a /{tmp/x,{var/y,etc/sudoers}}",
        deep_stars.as_str(),
        deep_expansions.as_str(),
    ] {
        let started = std::time::Instant::now();
        assert_ne!(verdict(command, home), Verdict::Allow, "{command:.80}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{command:.80} took {:?}",
            started.elapsed()
        );
    }
    // No gcloud file name is 40 characters long, so this may be allowed; it
    // must only be decided quickly.
    let started = std::time::Instant::now();
    let _ = verdict(&star_pairs, home);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "a glob of 40 `*?` pairs took {:?}",
        started.elapsed()
    );
    for command in [
        "echo x | tee -a /{tmp/x,var/tmp/y}",
        "echo x > /tmp/{a,b}/c.txt",
        "echo x >> /e[]x]c/notes.txt",
        "cp ./*.txt /tmp/out/",
    ] {
        assert_eq!(verdict(command, home), Verdict::Allow, "{command}");
    }
}
