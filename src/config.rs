use directories::ProjectDirs;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub schema_version: u32,
    pub globally_enabled: bool,
    pub start_with_windows: bool,
    pub sample_interval_seconds: u64,
    pub cpu_quiet_percent: f32,
    pub io_quiet_bytes_per_sample: u64,
    pub rules: Vec<ProcessRule>,
    #[serde(flatten)]
    pub extra_fields: BTreeMap<String, serde_json::Value>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            globally_enabled: true,
            start_with_windows: false,
            sample_interval_seconds: 2,
            cpu_quiet_percent: 1.0,
            io_quiet_bytes_per_sample: 4 * 1024,
            rules: built_in_presets(),
            extra_fields: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProcessRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub built_in: bool,
    pub include_descendants: bool,
    pub allow_suspend: bool,
    pub throttle_after_seconds: u64,
    pub suspend_after_seconds: u64,
    pub matcher: RuleMatcher,
    pub exclusions: Vec<RuleMatcher>,
    #[serde(flatten)]
    pub extra_fields: BTreeMap<String, serde_json::Value>,
}

impl Default for ProcessRule {
    fn default() -> Self {
        Self {
            id: "new-rule".into(),
            name: "New rule".into(),
            enabled: true,
            built_in: false,
            include_descendants: true,
            allow_suspend: false,
            throttle_after_seconds: 5 * 60,
            suspend_after_seconds: 20 * 60,
            matcher: RuleMatcher::default(),
            exclusions: Vec::new(),
            extra_fields: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleMatcher {
    pub process_name: Option<String>,
    pub executable_path: Option<PathBuf>,
    pub path_contains: Option<String>,
    pub command_contains: Option<String>,
    pub command_regex: Option<String>,
    pub ancestor_process_name: Option<String>,
    #[serde(flatten)]
    pub extra_fields: BTreeMap<String, serde_json::Value>,
}

impl RuleMatcher {
    pub fn validate(&self) -> Result<(), regex::Error> {
        if let Some(pattern) = &self.command_regex {
            Regex::new(pattern)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn summary(&self) -> String {
        if let Some(path) = &self.executable_path {
            return path.display().to_string();
        }
        let mut parts = Vec::new();
        if let Some(name) = &self.process_name {
            parts.push(name.clone());
        }
        if let Some(parent) = &self.ancestor_process_name {
            parts.push(format!("父级 {parent}"));
        }
        if let Some(fragment) = &self.command_contains {
            parts.push(format!("参数包含 {fragment}"));
        }
        if parts.is_empty() {
            "未设置".into()
        } else {
            parts.join(" · ")
        }
    }
}

#[must_use]
pub fn built_in_presets() -> Vec<ProcessRule> {
    vec![
        ProcessRule {
            id: "preset-codex".into(),
            name: "Codex".into(),
            enabled: true,
            built_in: true,
            matcher: RuleMatcher {
                process_name: Some("codex.exe".into()),
                ..Default::default()
            },
            ..Default::default()
        },
        ProcessRule {
            id: "preset-terminal-pwsh".into(),
            name: "Windows Terminal PowerShell".into(),
            enabled: false,
            built_in: true,
            matcher: RuleMatcher {
                process_name: Some("pwsh.exe".into()),
                ancestor_process_name: Some("WindowsTerminal.exe".into()),
                ..Default::default()
            },
            ..Default::default()
        },
    ]
}

impl AppConfig {
    pub fn load_or_create(path: &Path) -> io::Result<Self> {
        if !path.exists() {
            let config = Self::default();
            config.save_atomic(path)?;
            return Ok(config);
        }
        let text = fs::read_to_string(path)?;
        let mut config: Self = serde_json::from_str(&text).map_err(io::Error::other)?;
        if config.schema_version > SCHEMA_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "配置来自更新版本",
            ));
        }
        config.schema_version = SCHEMA_VERSION;
        for rule in &config.rules {
            rule.matcher.validate().map_err(io::Error::other)?;
            for exclusion in &rule.exclusions {
                exclusion.validate().map_err(io::Error::other)?;
            }
        }
        Ok(config)
    }

    pub fn save_atomic(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("json.tmp");
        let mut file = fs::File::create(&temporary)?;
        serde_json::to_writer_pretty(&mut file, self).map_err(io::Error::other)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(temporary, path)
    }
}

#[must_use]
pub fn config_path() -> PathBuf {
    ProjectDirs::from("dev", "LazyProcess", "Lazy Process")
        .expect("Windows has a local application data directory")
        .config_dir()
        .join("config.json")
}

#[must_use]
pub fn journal_path() -> PathBuf {
    config_path().with_file_name("suspended.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conservative() {
        let config = AppConfig::default();
        assert!(config.rules[0].enabled);
        assert!(!config.rules[0].allow_suspend);
        assert_eq!(config.rules[0].throttle_after_seconds, 300);
        assert_eq!(config.rules[0].suspend_after_seconds, 1200);
    }

    #[test]
    fn matcher_summary_prefers_exact_path() {
        let matcher = RuleMatcher {
            process_name: Some("pwsh.exe".into()),
            executable_path: Some(PathBuf::from(r"C:\Program Files\PowerShell\7\pwsh.exe")),
            ..Default::default()
        };
        assert!(matcher.summary().ends_with("pwsh.exe"));
    }

    #[test]
    fn unknown_fields_survive_a_round_trip() {
        let mut value = serde_json::to_value(AppConfig::default()).unwrap();
        value["future_setting"] = serde_json::json!({ "enabled": true });
        let config: AppConfig = serde_json::from_value(value).unwrap();
        let saved = serde_json::to_value(config).unwrap();
        assert_eq!(saved["future_setting"]["enabled"], true);
    }
}
