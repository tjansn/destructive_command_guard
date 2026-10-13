//! Bounded, read-only Node preload resolution. Never launches Node or a loader.
//! Unsupported package maps, aliases, native addons and resolution hooks remain
//! inconclusive. Conditional export order is preserved without changing the
//! JSON representation used by the rest of the guard.

use serde::Deserialize;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

const MANIFEST_CAP: u64 = 256 * 1024;
const WALK_CAP: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Import,
    Require,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Target {
    Path(String),
    Conditions(Conditions),
    Alternatives(Vec<Self>),
    Disabled(()),
}

#[derive(Debug)]
struct Conditions(Vec<(String, Target)>);

impl<'de> Deserialize<'de> for Conditions {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Conditions;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an ordered Node export map")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut entries = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, Target>()? {
                    if entries.len() >= 256 || entries.iter().any(|(name, _)| name == &key) {
                        return Err(serde::de::Error::custom("duplicate or oversized export map"));
                    }
                    entries.push((key, value));
                }
                Ok(Conditions(entries))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

#[derive(Default, Deserialize)]
struct Package {
    name: Option<String>,
    main: Option<String>,
    exports: Option<Target>,
}

/// A symlink can change both the package search base and its selected source.
/// Keep it inconclusive instead of inspecting a different file than Node loads.
fn no_symlinks(path: &Path) -> Result<(), String> {
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        match fs::symlink_metadata(&prefix) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!(
                    "Node source path contains a symlink: {}",
                    prefix.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

fn manifest(dir: &Path, bytes_left: &mut u64) -> Result<Package, String> {
    let path = dir.join("package.json");
    crate::desktop_review::record_source_path(&path);
    no_symlinks(&path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Package::default()),
        Err(error) => return Err(error.to_string()),
    };
    let meta = file.metadata().map_err(|error| error.to_string())?;
    if !meta.is_file() || meta.len() > MANIFEST_CAP || meta.len() > *bytes_left {
        return Err("Node package manifest inspection limit reached".to_owned());
    }
    let mut source = String::new();
    file.take(meta.len() + 1)
        .read_to_string(&mut source)
        .map_err(|error| error.to_string())?;
    if source.len() as u64 != meta.len() {
        return Err("Node package manifest changed while reading".to_owned());
    }
    crate::script_files::verify_unchanged(&path, &meta)?;
    *bytes_left -= meta.len();
    crate::desktop_review::record_script(
        &path,
        &source,
        dir,
        crate::heredoc::ScriptLanguage::Unknown,
    );
    serde_json::from_str(&source).map_err(|error| format!("invalid Node package manifest: {error}"))
}

fn safe_segments(value: &str) -> bool {
    !value.contains(['\\', '%', '?', '#', ':'])
        && value.split('/').all(|part| {
            !matches!(part, "" | "." | "..") && !part.eq_ignore_ascii_case("node_modules")
        })
}

fn file(path: &Path) -> Result<PathBuf, String> {
    no_symlinks(path)?;
    crate::desktop_review::record_source_path(path);
    let meta = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !meta.is_file()
        || !matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("js" | "mjs" | "cjs")
        )
    {
        return Err("Node preload is not an inspectable JavaScript file".to_owned());
    }
    fs::canonicalize(path).map_err(|error| error.to_string())
}

fn legacy_file(path: &Path) -> Result<Option<PathBuf>, String> {
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}.js", path.display())),
        PathBuf::from(format!("{}.json", path.display())),
        PathBuf::from(format!("{}.node", path.display())),
    ] {
        no_symlinks(&candidate)?;
        crate::desktop_review::record_source_path(&candidate);
        match fs::symlink_metadata(&candidate) {
            Ok(meta) if !meta.is_dir() => return file(&candidate).map(Some),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(None)
}

fn legacy_entry(dir: &Path, main: Option<&str>) -> Result<PathBuf, String> {
    if let Some(main) = main.filter(|main| !main.is_empty()) {
        let main = main.strip_prefix("./").unwrap_or(main);
        if !safe_segments(main) {
            return Err("unsupported Node main path".to_owned());
        }
        let path = dir.join(main);
        if let Some(found) = legacy_file(&path)? {
            return Ok(found);
        }
        if let Some(found) = legacy_file(&path.join("index"))? {
            return Ok(found);
        }
    }
    legacy_file(&dir.join("index"))?.ok_or_else(|| "Node package entry was not found".to_owned())
}

fn export_target(target: &Target, mode: Mode, depth: usize) -> Result<Option<&str>, String> {
    if depth >= 16 {
        return Err("Node export nesting limit reached".to_owned());
    }
    match target {
        Target::Path(path) => Ok(Some(path)),
        Target::Disabled(()) => Err("Node package export is disabled".to_owned()),
        Target::Alternatives(_values) => {
            // Arrays can fall back on invalid targets, but never on missing
            // files. Refuse this less common form rather than guessing.
            Err("Node export alternatives require review".to_owned())
        }
        Target::Conditions(Conditions(entries)) => {
            if entries
                .iter()
                .any(|(name, _)| name.starts_with('.') || name.parse::<u32>().is_ok())
            {
                return Err("invalid Node export condition map".to_owned());
            }
            for (name, value) in entries {
                // module-sync depends on the runtime version/flags. Do not
                // guess whether it takes precedence over import/require.
                if name == "module-sync" {
                    return Err(
                        "runtime-dependent Node export condition requires review".to_owned(),
                    );
                }
                if (matches!(name.as_str(), "node" | "default")
                    || (mode == Mode::Import && name == "import")
                    || (mode == Mode::Require && name == "require"))
                    && let Some(path) = export_target(value, mode, depth + 1)?
                {
                    return Ok(Some(path));
                }
            }
            Ok(None)
        }
    }
}

fn package_entry(
    dir: &Path,
    package: &Package,
    subpath: &str,
    mode: Mode,
) -> Result<PathBuf, String> {
    if let Some(exports) = &package.exports {
        let target = if let Target::Conditions(Conditions(entries)) = exports
            && entries.iter().any(|(key, _)| key.starts_with('.'))
        {
            if entries.iter().any(|(key, _)| !key.starts_with('.')) {
                return Err("mixed Node export keys".to_owned());
            }
            entries
                .iter()
                .find(|(key, _)| key == subpath)
                .map(|(_, target)| target)
        } else {
            (subpath == ".").then_some(exports)
        }
        .ok_or("Node package subpath is not an explicit export")?;
        let target = export_target(target, mode, 0)?.ok_or("no matching Node export condition")?;
        let relative = target
            .strip_prefix("./")
            .ok_or("Node export must start with ./")?;
        if !safe_segments(relative) || relative.contains('*') {
            return Err("unsupported Node export target".to_owned());
        }
        return file(&dir.join(relative));
    }
    if subpath == "." {
        return legacy_entry(dir, package.main.as_deref());
    }
    let path = dir.join(subpath.strip_prefix("./").ok_or("invalid Node subpath")?);
    if mode == Mode::Import {
        file(&path)
    } else {
        legacy_file(&path)?.ok_or_else(|| "Node package subpath was not found".to_owned())
    }
}

pub(crate) fn resolve(specifier: &str, cwd: &Path, mode: Mode) -> Result<PathBuf, String> {
    if std::env::var_os("NODE_OPTIONS").is_some_and(|options| !options.is_empty()) {
        return Err(
            "inherited Node options can change preload resolution; review is required".to_owned(),
        );
    }
    if specifier.is_empty()
        || specifier.len() > 4096
        || specifier.contains(['\\', '%', '?', '#', ':'])
    {
        return Err("unsupported Node preload specifier".to_owned());
    }
    if specifier.starts_with(['/', '.']) {
        let path = cwd.join(specifier);
        return if mode == Mode::Import {
            file(&path)
        } else {
            legacy_file(&path)?.ok_or_else(|| "Node preload file was not found".to_owned())
        };
    }
    if !safe_segments(specifier) {
        return Err("invalid Node package specifier".to_owned());
    }
    let mut parts = specifier.split('/');
    let first = parts.next().ok_or("missing Node package name")?;
    let name = if first.starts_with('@') {
        if first.len() == 1 {
            return Err("empty Node package scope".to_owned());
        }
        format!(
            "{first}/{}",
            parts.next().ok_or("missing scoped Node package name")?
        )
    } else {
        first.to_owned()
    };
    let suffix = parts.collect::<Vec<_>>().join("/");
    let subpath = if suffix.is_empty() {
        ".".to_owned()
    } else {
        format!("./{suffix}")
    };
    let mut bytes_left = 1024 * 1024;
    // Self references take precedence over node_modules. Only the nearest
    // package scope participates, and node_modules terminates that scope.
    for dir in cwd.ancestors().take(WALK_CAP) {
        if dir.file_name().is_some_and(|name| name == "node_modules") {
            break;
        }
        let package = manifest(dir, &mut bytes_left)?;
        if dir.join("package.json").exists() {
            if package.name.as_deref() == Some(name.as_str()) && package.exports.is_some() {
                return package_entry(dir, &package, &subpath, mode);
            }
            break;
        }
    }
    for dir in cwd.ancestors().take(WALK_CAP) {
        if dir.file_name().is_some_and(|name| name == "node_modules") {
            continue;
        }
        let package_dir = dir.join("node_modules").join(&name);
        no_symlinks(&package_dir)?;
        crate::desktop_review::record_source_path(&package_dir);
        match fs::symlink_metadata(&package_dir) {
            Ok(meta) if meta.is_dir() => {
                return package_entry(
                    &package_dir,
                    &manifest(&package_dir, &mut bytes_left)?,
                    &subpath,
                    mode,
                );
            }
            Ok(_) => return Err("Node package path is not a directory".to_owned()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Err("Node preload package was not resolved within the bounded node_modules walk".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, path: &str, value: &str) {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, value).unwrap();
    }

    #[test]
    fn exports_bind_the_preload_and_respect_condition_order_and_mode() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        write(&root, "package.json", r#"{"name":"fixture"}"#);
        for name in ["esm.mjs", "cjs.cjs", "fallback.js"] {
            write(
                &root,
                &format!("node_modules/loader/{name}"),
                "console.log('fixture');",
            );
        }
        write(
            &root,
            "node_modules/loader/package.json",
            r#"{"exports":{".":{"import":"./esm.mjs","require":"./cjs.cjs","default":"./fallback.js"}}}"#,
        );
        assert_eq!(
            resolve("loader", &root, Mode::Import).unwrap(),
            root.join("node_modules/loader/esm.mjs")
        );
        assert_eq!(
            resolve("loader", &root, Mode::Require).unwrap(),
            root.join("node_modules/loader/cjs.cjs")
        );
        write(
            &root,
            "node_modules/loader/package.json",
            r#"{"exports":{"default":"./fallback.js","import":"./esm.mjs"}}"#,
        );
        assert_eq!(
            resolve("loader", &root, Mode::Import).unwrap(),
            root.join("node_modules/loader/fallback.js")
        );
        // Exports encapsulation wins over a valid main or an existing file.
        write(
            &root,
            "node_modules/loader/package.json",
            r#"{"main":"fallback.js","exports":{".":null}}"#,
        );
        assert!(resolve("loader", &root, Mode::Import).is_err());
        assert!(resolve("loader/fallback.js", &root, Mode::Require).is_err());
    }

    #[test]
    fn scoped_packages_nearest_modules_main_index_and_self_references() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        write(
            &root,
            "package.json",
            r#"{"name":"self","exports":{".":"./self.mjs"}}"#,
        );
        write(&root, "self.mjs", "export const value = 1;");
        write(
            &root,
            "node_modules/@scope/loader/package.json",
            r#"{"main":"dist/entry"}"#,
        );
        write(
            &root,
            "node_modules/@scope/loader/dist/entry.js",
            "module.exports = 1;",
        );
        write(&root, "node_modules/fallback/index.js", "module.exports = 1;");
        let nested = root.join("nested/tests");
        fs::create_dir_all(&nested).unwrap();
        assert_eq!(
            resolve("self", &nested, Mode::Import).unwrap(),
            root.join("self.mjs")
        );
        assert_eq!(
            resolve("@scope/loader", &nested, Mode::Require).unwrap(),
            root.join("node_modules/@scope/loader/dist/entry.js")
        );
        assert_eq!(
            resolve("fallback", &nested, Mode::Import).unwrap(),
            root.join("node_modules/fallback/index.js")
        );
        write(
            &root,
            "nested/node_modules/fallback/index.js",
            "module.exports = 2;",
        );
        assert_eq!(
            resolve("fallback", &nested, Mode::Require).unwrap(),
            root.join("nested/node_modules/fallback/index.js")
        );
    }

    #[test]
    fn invalid_missing_escaping_and_oversized_inputs_stay_inconclusive() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        write(&root, "package.json", "{}");
        for specifier in [
            "",
            "missing",
            "@scope",
            "../missing.js",
            "loader/../escape",
            "loader/%2e%2e/escape",
            "node:unknown",
            "https://invalid/loader",
            "#alias",
        ] {
            assert!(resolve(specifier, &root, Mode::Import).is_err(), "{specifier}");
        }
        write(
            &root,
            "node_modules/loader/entry.js",
            "console.log('fixture');",
        );
        for manifest in [
            r#"{"exports":"../entry.js"}"#,
            r#"{"exports":"./../entry.js"}"#,
            r#"{"exports":{".":"./entry.js","default":"./entry.js"}}"#,
            r#"{"exports":{"module-sync":"./entry.js","default":"./entry.js"}}"#,
            r#"{"exports":["./entry.js"]}"#,
            r#"{"exports":"./missing.js","main":"entry.js"}"#,
            "not json",
        ] {
            write(&root, "node_modules/loader/package.json", manifest);
            assert!(resolve("loader", &root, Mode::Import).is_err(), "{manifest}");
        }
        write(
            &root,
            "node_modules/loader/package.json",
            &" ".repeat(usize::try_from(MANIFEST_CAP).unwrap() + 1),
        );
        assert!(resolve("loader", &root, Mode::Require).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_packages_and_sources_are_not_bound_to_the_wrong_file() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        write(&root, "package.json", "{}");
        write(&root, "real/index.js", "console.log('fixture');");
        fs::create_dir(root.join("node_modules")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("node_modules/alias")).unwrap();
        assert!(resolve("alias", &root, Mode::Import).is_err());
        write(
            &root,
            "node_modules/loader/package.json",
            r#"{"exports":"./entry.js"}"#,
        );
        std::os::unix::fs::symlink(
            root.join("real/index.js"),
            root.join("node_modules/loader/entry.js"),
        )
        .unwrap();
        assert!(resolve("loader", &root, Mode::Require).is_err());
    }
}
