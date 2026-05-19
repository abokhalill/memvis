// SPDX-License-Identifier: Apache-2.0
//
// resolution: CLI > env > .rtmap (cwd upward) > ~/.config/rtmap/config > glob auto-detect

use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone)]
pub struct Config {
    pub dynamorio_home: Option<String>,
    pub tracer_path: Option<String>,
    pub drrun_path: Option<String>,
    pub default_topology: Option<bool>,
    pub default_heatmap: Option<bool>,
    pub default_coverage: Option<bool>,
    pub default_no_bb: Option<bool>,
    pub default_min_events: Option<u64>,
    pub include: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct TargetProfile {
    pub tripwire: Option<String>,
    pub args: Vec<String>,
    pub topology: Option<String>,
    pub heatmap: Option<String>,
    pub coverage: Option<String>,
    pub no_bb: Option<bool>,
    pub min_events: Option<u64>,
}

#[derive(Debug, Default, Clone)]
pub struct ProjectConfig {
    pub targets: HashMap<String, TargetProfile>,
}

pub fn parse_flat_config(contents: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, val)) = line.split_once('=') {
            map.insert(key.trim().to_string(), val.trim().to_string());
        }
    }
    map
}

pub fn load_global_config() -> Config {
    let path = global_config_path();
    load_config_from_path(&path)
}

pub fn load_config_from_path(path: &Path) -> Config {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Config::default(),
    };
    let map = parse_flat_config(&contents);
    let mut cfg = config_from_map(&map);

    if let Some(ref inc_path) = cfg.include {
        let inc = Path::new(inc_path);
        if inc.exists() {
            if let Ok(inc_contents) = std::fs::read_to_string(inc) {
                let inc_map = parse_flat_config(&inc_contents);
                let inc_cfg = config_from_map(&inc_map);
                cfg = merge_config(inc_cfg, cfg);
            }
        }
    }
    cfg
}

pub fn find_project_config() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(".rtmap");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

pub fn load_project_config() -> (Config, ProjectConfig) {
    let path = match find_project_config() {
        Some(p) => p,
        None => return (Config::default(), ProjectConfig::default()),
    };
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return (Config::default(), ProjectConfig::default()),
    };
    let map = parse_flat_config(&contents);
    let cfg = config_from_map(&map);
    let proj = project_config_from_map(&map);
    (cfg, proj)
}

pub fn resolve_target_profile<'a>(proj: &'a ProjectConfig, target: &'a str) -> Option<&'a TargetProfile> {
    if let Some(p) = proj.targets.get(target) {
        return Some(p);
    }
    // fallback: basename match for ./path/to/binary invocations
    let basename = Path::new(target)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(target);
    proj.targets.get(basename)
}

pub fn resolve_config() -> (Config, ProjectConfig) {
    let global = load_global_config();
    let (proj_cfg, proj_targets) = load_project_config();
    let merged = merge_config(global, proj_cfg);
    (merged, proj_targets)
}

pub fn shell_split(s: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape_next = false;

    for ch in s.chars() {
        if escape_next {
            current.push(ch);
            escape_next = false;
            continue;
        }
        match ch {
            '\\' if !in_single => escape_next = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ' ' | '\t' if !in_single && !in_double => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

fn global_config_path() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg).join("rtmap/config")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".config/rtmap/config")
    } else {
        PathBuf::from("/etc/rtmap/config")
    }
}

pub fn global_config_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg).join("rtmap")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".config/rtmap")
    } else {
        PathBuf::from("/etc/rtmap")
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.to_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn config_from_map(map: &HashMap<String, String>) -> Config {
    Config {
        dynamorio_home: map.get("paths.dynamorio_home").cloned(),
        tracer_path: map.get("paths.tracer").cloned(),
        drrun_path: map.get("paths.drrun").cloned(),
        default_topology: map.get("defaults.topology").and_then(|v| parse_bool(v)),
        default_heatmap: map.get("defaults.heatmap").and_then(|v| parse_bool(v)),
        default_coverage: map.get("defaults.coverage").and_then(|v| parse_bool(v)),
        default_no_bb: map.get("defaults.no_bb").and_then(|v| parse_bool(v)),
        default_min_events: map.get("defaults.min_events").and_then(|v| v.parse().ok()),
        include: map.get("include").cloned(),
    }
}

fn project_config_from_map(map: &HashMap<String, String>) -> ProjectConfig {
    let mut targets: HashMap<String, TargetProfile> = HashMap::new();

    for (key, val) in map {
            if let Some(rest) = key.strip_prefix("target.") {
            if let Some((name, field)) = rest.rsplit_once('.') {
                let profile = targets.entry(name.to_string()).or_default();
                match field {
                    "tripwire" => profile.tripwire = Some(val.clone()),
                    "args" => profile.args = shell_split(val),
                    "topology" => profile.topology = Some(val.clone()),
                    "heatmap" => profile.heatmap = Some(val.clone()),
                    "coverage" => profile.coverage = Some(val.clone()),
                    "no_bb" => profile.no_bb = parse_bool(val),
                    "min_events" => profile.min_events = val.parse().ok(),
                    _ => {}
                }
            }
        }
    }

    ProjectConfig { targets }
}

fn merge_config(base: Config, overlay: Config) -> Config {
    Config {
        dynamorio_home: overlay.dynamorio_home.or(base.dynamorio_home),
        tracer_path: overlay.tracer_path.or(base.tracer_path),
        drrun_path: overlay.drrun_path.or(base.drrun_path),
        default_topology: overlay.default_topology.or(base.default_topology),
        default_heatmap: overlay.default_heatmap.or(base.default_heatmap),
        default_coverage: overlay.default_coverage.or(base.default_coverage),
        default_no_bb: overlay.default_no_bb.or(base.default_no_bb),
        default_min_events: overlay.default_min_events.or(base.default_min_events),
        include: overlay.include.or(base.include),
    }
}

// glob crawl: ~/DynamoRIO-Linux-*, /opt/dynamorio, etc. newest by mtime wins.
pub fn discover_dynamorio() -> Option<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    let patterns: Vec<String> = vec![
        format!("{}/DynamoRIO-Linux-*", home),
        format!("{}/dynamorio*", home),
        format!("{}/.local/share/dynamorio", home),
        "/opt/dynamorio".to_string(),
        "/opt/DynamoRIO*".to_string(),
        "/usr/local/share/dynamorio".to_string(),
    ];

    let mut found: Vec<(PathBuf, std::time::SystemTime)> = Vec::new();

    for pattern in &patterns {
        if pattern.contains('*') {
            if let Some((dir, prefix)) = pattern.rsplit_once('/') {
                let prefix_base = prefix.trim_end_matches('*');
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();
                        if name_str.starts_with(prefix_base) && entry.path().is_dir() {
                            let drrun = entry.path().join("bin64/drrun");
                            if drrun.exists() {
                                let mtime = entry.metadata()
                                    .and_then(|m| m.modified())
                                    .unwrap_or(std::time::UNIX_EPOCH);
                                found.push((entry.path(), mtime));
                            }
                        }
                    }
                }
            }
        } else {
            let p = PathBuf::from(pattern);
            if p.is_dir() && p.join("bin64/drrun").exists() {
                let mtime = std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::UNIX_EPOCH);
                found.push((p, mtime));
            }
        }
    }

    found.sort_by(|a, b| b.1.cmp(&a.1));
    found.into_iter().next().map(|(p, _)| p)
}

pub fn generate_global_config(dr_home: Option<&str>, tracer: Option<&str>) -> String {
    let mut out = String::new();
    out.push_str("# rtmap global configuration\n");
    out.push_str("# Generated by 'rtmap setup'. Edit freely.\n");
    out.push_str("#\n");
    out.push_str("# Resolution order: CLI flag > env var > .rtmap (project) > this file > auto-detect\n");
    out.push_str("#\n");
    out.push_str("# Paths\n");
    out.push_str("# -----\n");
    out.push_str("# Path to DynamoRIO installation directory (contains bin64/drrun).\n");
    if let Some(dr) = dr_home {
        out.push_str(&format!("paths.dynamorio_home = {}\n", dr));
    } else {
        out.push_str("# paths.dynamorio_home = /opt/DynamoRIO-Linux-11.90.20092\n");
    }
    out.push_str("\n");
    out.push_str("# Explicit path to drrun binary. Overrides dynamorio_home.\n");
    out.push_str("# paths.drrun = /opt/DynamoRIO-Linux-11.90.20092/bin64/drrun\n");
    out.push_str("\n");
    out.push_str("# Explicit path to librtmap_tracer.so. Auto-detected relative to rtmap binary if unset.\n");
    if let Some(t) = tracer {
        out.push_str(&format!("paths.tracer = {}\n", t));
    } else {
        out.push_str("# paths.tracer = /home/you/rtmap/build/librtmap_tracer.so\n");
    }
    out.push_str("\n");
    out.push_str("# Include another config file (single level, no recursion).\n");
    out.push_str("# Useful for Docker/CI: ship /etc/rtmap/site.conf with paths baked in.\n");
    out.push_str("# include = /etc/rtmap/site.conf\n");
    out.push_str("\n");
    out.push_str("# Defaults\n");
    out.push_str("# --------\n");
    out.push_str("# Always emit topology JSONL alongside output.\n");
    out.push_str("# defaults.topology = true\n");
    out.push_str("\n");
    out.push_str("# Always emit field write heatmap.\n");
    out.push_str("# defaults.heatmap = false\n");
    out.push_str("\n");
    out.push_str("# Emit basic-block coverage map.\n");
    out.push_str("# defaults.coverage = false\n");
    out.push_str("\n");
    out.push_str("# Skip BB_ENTRY events to reduce ring buffer volume.\n");
    out.push_str("# defaults.no_bb = false\n");
    out.push_str("\n");
    out.push_str("# Minimum events before taking a snapshot (headless mode).\n");
    out.push_str("# defaults.min_events = 1\n");
    out
}

pub fn generate_project_config(target_name: &str, tripwire: Option<&str>) -> String {
    let mut out = String::new();
    out.push_str("# rtmap project configuration\n");
    out.push_str("# Generated by 'rtmap init'. Edit freely.\n");
    out.push_str("#\n");
    out.push_str("# Target profiles: define per-binary defaults.\n");
    out.push_str("# When you run 'rtmap <target>', these settings are applied automatically.\n");
    out.push_str("# CLI args after '--' fully replace target.*.args (no merge).\n");
    out.push_str("#\n");
    out.push_str(&format!("# Profile for: {}\n", target_name));
    out.push_str("\n");
    out.push_str(&format!("# Tripwire symbol: instrumentation begins when this function is entered.\n"));
    out.push_str(&format!("# Skips init-phase noise (config parsing, static setup).\n"));
    if let Some(tw) = tripwire {
        out.push_str(&format!("target.{}.tripwire = {}\n", target_name, tw));
    } else {
        out.push_str(&format!("# target.{}.tripwire = main\n", target_name));
    }
    out.push_str("\n");
    out.push_str(&format!("# target args: override on CLI with: rtmap run {} -- --custom-flag\n", target_name));
    out.push_str(&format!("# target.{}.args =\n", target_name));
    out.push_str("\n");
    out.push_str(&format!("target.{}.topology = {}.topo.jsonl\n", target_name, target_name));
    out.push_str(&format!("target.{}.heatmap = {}.heatmap.tsv\n", target_name, target_name));
    out.push_str("\n");
    out.push_str(&format!("# target.{}.no_bb = false\n", target_name));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_flat_config() {
        let input = r#"
# comment
paths.dynamorio_home = /opt/DynamoRIO
paths.tracer = /home/user/tracer.so

defaults.topology = true
defaults.min_events = 500
"#;
        let map = parse_flat_config(input);
        assert_eq!(map.get("paths.dynamorio_home").unwrap(), "/opt/DynamoRIO");
        assert_eq!(map.get("paths.tracer").unwrap(), "/home/user/tracer.so");
        assert_eq!(map.get("defaults.topology").unwrap(), "true");
        assert_eq!(map.get("defaults.min_events").unwrap(), "500");
    }

    #[test]
    fn test_config_from_map() {
        let mut map = HashMap::new();
        map.insert("paths.dynamorio_home".into(), "/opt/DR".into());
        map.insert("defaults.topology".into(), "true".into());
        map.insert("defaults.min_events".into(), "42".into());
        let cfg = config_from_map(&map);
        assert_eq!(cfg.dynamorio_home.as_deref(), Some("/opt/DR"));
        assert_eq!(cfg.default_topology, Some(true));
        assert_eq!(cfg.default_min_events, Some(42));
    }

    #[test]
    fn test_shell_split() {
        assert_eq!(shell_split("--port 6399"), vec!["--port", "6399"]);
        assert_eq!(shell_split("--name 'hello world'"), vec!["--name", "hello world"]);
        assert_eq!(shell_split(r#"--msg "it's fine""#), vec!["--msg", "it's fine"]);
        assert_eq!(shell_split(""), Vec::<String>::new());
    }

    #[test]
    fn test_project_config_from_map() {
        let mut map = HashMap::new();
        map.insert("target.redis-server.tripwire".into(), "aeMain".into());
        map.insert("target.redis-server.args".into(), "--port 6399 --loglevel debug".into());
        map.insert("target.bench.no_bb".into(), "true".into());
        let proj = project_config_from_map(&map);
        let redis = proj.targets.get("redis-server").unwrap();
        assert_eq!(redis.tripwire.as_deref(), Some("aeMain"));
        assert_eq!(redis.args, vec!["--port", "6399", "--loglevel", "debug"]);
        let bench = proj.targets.get("bench").unwrap();
        assert_eq!(bench.no_bb, Some(true));
    }

    #[test]
    fn test_merge_config() {
        let base = Config {
            dynamorio_home: Some("/opt/DR".into()),
            default_topology: Some(true),
            ..Default::default()
        };
        let overlay = Config {
            dynamorio_home: Some("/home/user/DR".into()),
            default_heatmap: Some(true),
            ..Default::default()
        };
        let merged = merge_config(base, overlay);
        assert_eq!(merged.dynamorio_home.as_deref(), Some("/home/user/DR"));
        assert_eq!(merged.default_topology, Some(true));
        assert_eq!(merged.default_heatmap, Some(true));
    }
}
