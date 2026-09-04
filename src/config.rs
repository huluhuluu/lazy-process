use directories::ProjectDirs;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    io::{self, Write},
    iter,
    path::{Path, PathBuf},
};

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(windows)]
use windows::{
    Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW},
    core::PCWSTR,
};

pub const SCHEMA_VERSION: u32 = 1;

/// Which palette the panel uses. `System` follows the Windows "apps use light mode" setting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemePreference {
    #[default]
    System,
    Light,
    Dark,
}

/// Restricts a rule to part of the day. Windows that wrap past midnight are supported, so
/// 22:00-06:00 means "the night", not "never".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleSchedule {
    /// Minutes from local midnight, 0 to 1439.
    pub start_minute: u16,
    /// Exclusive end, also minutes from local midnight.
    pub end_minute: u16,
    /// Bit 0 is Sunday through bit 6 Saturday. Zero means every day, so a schedule written by hand
    /// without this field still behaves sensibly.
    pub days: u8,
}

impl RuleSchedule {
    /// Whether the window is open at `minute_of_day` on `weekday` (0 = Sunday).
    #[must_use]
    pub fn contains(&self, minute_of_day: u16, weekday: u8) -> bool {
        if self.days != 0 && weekday < 7 && self.days & (1 << weekday) == 0 {
            return false;
        }
        // An empty window covers the whole day rather than nothing, so a half-filled schedule
        // cannot silently disable a rule.
        if self.start_minute == self.end_minute {
            return true;
        }
        if self.start_minute < self.end_minute {
            (self.start_minute..self.end_minute).contains(&minute_of_day)
        } else {
            minute_of_day >= self.start_minute || minute_of_day < self.end_minute
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub schema_version: u32,
    pub globally_enabled: bool,
    pub start_with_windows: bool,
    pub sample_interval_seconds: u64,
    pub cpu_quiet_percent: f32,
    pub io_quiet_bytes_per_sample: u64,
    pub theme: ThemePreference,
    /// Suspends nothing while a game or presentation is on screen. An unfocused group is exactly
    /// what a full-screen application looks like, so this is on by default.
    pub pause_while_fullscreen: bool,
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
            theme: ThemePreference::System,
            pause_while_fullscreen: true,
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
    /// Flushes the working set to the page file alongside suspension. Off by default: recovering
    /// the pages costs more than it saves whenever memory was not actually scarce.
    pub trim_working_set: bool,
    pub throttle_after_seconds: u64,
    pub suspend_after_seconds: u64,
    /// When set, the rule only applies inside this window.
    pub schedule: Option<RuleSchedule>,
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
            trim_working_set: false,
            throttle_after_seconds: 5 * 60,
            suspend_after_seconds: 20 * 60,
            schedule: None,
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

    /// Whether the matcher can select a process on its own. `ancestor_process_name` deliberately
    /// does not count: on its own it would match every child of a host application.
    #[must_use]
    pub fn has_selector(&self) -> bool {
        let non_empty = |value: &Option<String>| {
            value
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
        };
        non_empty(&self.process_name)
            || self
                .executable_path
                .as_ref()
                .is_some_and(|path| !path.as_os_str().is_empty())
            || non_empty(&self.path_contains)
            || non_empty(&self.command_contains)
            || non_empty(&self.command_regex)
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

/// The shipped definition of a preset, so an edited or deleted preset can be put back. Returns
/// `None` for a rule id that was never a preset.
#[must_use]
pub fn built_in_preset(id: &str) -> Option<ProcessRule> {
    built_in_presets().into_iter().find(|rule| rule.id == id)
}

impl AppConfig {
    /// Reinstates every missing preset, keeping the user's own rules and their order. Presets that
    /// are still present are left exactly as they are; use [`built_in_preset`] to reset one.
    pub fn restore_missing_presets(&mut self) -> usize {
        let missing = built_in_presets()
            .into_iter()
            .filter(|preset| !self.rules.iter().any(|rule| rule.id == preset.id))
            .collect::<Vec<_>>();
        let count = missing.len();
        self.rules.extend(missing);
        count
    }

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
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.sample_interval_seconds == 0 || self.sample_interval_seconds > 10 {
            return Err(invalid_config("采样间隔必须在 1 到 10 秒之间"));
        }
        if !self.cpu_quiet_percent.is_finite() || !(0.0..=100.0).contains(&self.cpu_quiet_percent) {
            return Err(invalid_config("CPU 静默阈值必须在 0 到 100 之间"));
        }
        if self.io_quiet_bytes_per_sample > 1024 * 1024 * 1024 {
            return Err(invalid_config("I/O 静默阈值不能超过每次采样 1 GiB"));
        }

        let mut ids = HashSet::new();
        for rule in &self.rules {
            if rule.id.trim().is_empty() || !ids.insert(rule.id.as_str()) {
                return Err(invalid_config("规则 ID 必须非空且不能重复"));
            }
            if rule.name.trim().is_empty() {
                return Err(invalid_config(format!("规则 {} 的名称不能为空", rule.id)));
            }
            if !(60..=14_400).contains(&rule.throttle_after_seconds) {
                return Err(invalid_config(format!(
                    "规则 {} 的低耗延迟必须在 1 分钟到 4 小时之间",
                    rule.id
                )));
            }
            if rule.suspend_after_seconds <= rule.throttle_after_seconds
                || rule.suspend_after_seconds > 28_800
            {
                return Err(invalid_config(format!(
                    "规则 {} 的暂停延迟必须晚于低耗延迟且不超过 8 小时",
                    rule.id
                )));
            }
            if let Some(schedule) = &rule.schedule
                && (schedule.start_minute >= 1440 || schedule.end_minute >= 1440)
            {
                return Err(invalid_config(format!(
                    "规则 {} 的时段必须在一天之内",
                    rule.id
                )));
            }
            validate_matcher(&rule.matcher, &rule.id, false)?;
            for exclusion in &rule.exclusions {
                validate_matcher(exclusion, &rule.id, true)?;
            }
        }
        Ok(())
    }

    pub fn save_atomic(&self, path: &Path) -> io::Result<()> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension(format!("json.{}.tmp", std::process::id()));
        let mut file = fs::File::create(&temporary)?;
        serde_json::to_writer_pretty(&mut file, self).map_err(io::Error::other)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        replace_file_atomic(&temporary, path)
    }
}

fn validate_matcher(matcher: &RuleMatcher, rule_id: &str, exclusion: bool) -> io::Result<()> {
    if matcher
        .process_name
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
        || matcher
            .path_contains
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        || matcher
            .command_contains
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        || matcher
            .command_regex
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        || matcher
            .ancestor_process_name
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        || matcher
            .executable_path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
    {
        return Err(invalid_config(format!(
            "规则 {rule_id} 包含空的{}匹配条件",
            if exclusion { "排除" } else { "进程" }
        )));
    }
    matcher.validate().map_err(io::Error::other)?;
    if !matcher.has_selector() {
        return Err(invalid_config(format!(
            "规则 {rule_id} 的{}匹配器至少需要一个进程、路径或命令条件",
            if exclusion { "排除" } else { "主" }
        )));
    }
    Ok(())
}

fn invalid_config(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub fn replace_file_atomic(temporary: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        let source = temporary
            .as_os_str()
            .encode_wide()
            .chain(iter::once(0))
            .collect::<Vec<_>>();
        let target = destination
            .as_os_str()
            .encode_wide()
            .chain(iter::once(0))
            .collect::<Vec<_>>();
        // MoveFileExW replaces an existing file on the same volume and asks the OS to flush it.
        unsafe {
            MoveFileExW(
                PCWSTR(source.as_ptr()),
                PCWSTR(target.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(io::Error::other)
    }
    #[cfg(not(windows))]
    {
        fs::rename(temporary, destination)
    }
}

#[must_use]
pub fn config_path() -> PathBuf {
    let directories = project_dirs();
    select_existing_path(
        &directories.config_local_dir().join("config.json"),
        &directories.config_dir().join("config.json"),
    )
}

#[must_use]
pub fn journal_path() -> PathBuf {
    let directories = project_dirs();
    let local = directories.config_local_dir().join("suspended.json");
    let roaming = directories.config_dir().join("suspended.json");
    select_existing_path(&local, &roaming)
}

/// The rolling event log. Kept beside the configuration so both follow the same directory choice.
#[must_use]
pub fn event_log_path() -> PathBuf {
    config_path().with_file_name("events.log")
}

#[must_use]
pub fn application_lease_path() -> PathBuf {
    project_dirs()
        .config_local_dir()
        .join("controller-state.json")
}

#[must_use]
pub fn journal_candidate_paths() -> Vec<PathBuf> {
    let directories = project_dirs();
    let local = directories.config_local_dir().join("suspended.json");
    let roaming = directories.config_dir().join("suspended.json");
    [
        local.with_file_name("suspended-elevated.json"),
        roaming.with_file_name("suspended-elevated.json"),
        local,
        roaming,
    ]
    .into_iter()
    .fold(Vec::new(), |mut paths, path| {
        if !paths.contains(&path) {
            paths.push(path);
        }
        paths
    })
}

#[must_use]
pub fn journal_recovery_paths() -> Vec<PathBuf> {
    journal_candidate_paths()
        .into_iter()
        .filter(|path| path.exists())
        .collect()
}

/// Prefers the local directory, staying with a roaming file only while it is the one that exists.
/// Used for both the config and the journal so the two never split across directories.
fn select_existing_path(local: &Path, roaming: &Path) -> PathBuf {
    if roaming.exists() && !local.exists() {
        roaming.to_path_buf()
    } else {
        local.to_path_buf()
    }
}

fn project_dirs() -> ProjectDirs {
    ProjectDirs::from("dev", "LazyProcess", "Lazy Process")
        .expect("Windows has a local application data directory")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_config_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "lazy-process-config-{name}-{}-{nonce}",
                std::process::id()
            ))
            .join("config.json")
    }

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

    #[test]
    fn repeated_atomic_saves_replace_the_existing_config() {
        let path = test_config_path("replace");
        let mut config = AppConfig::default();
        config.save_atomic(&path).unwrap();
        config.globally_enabled = false;
        config.sample_interval_seconds = 7;
        config.save_atomic(&path).unwrap();

        let loaded = AppConfig::load_or_create(&path).unwrap();
        assert!(!loaded.globally_enabled);
        assert_eq!(loaded.sample_interval_seconds, 7);
        assert!(
            !path
                .with_extension(format!("json.{}.tmp", std::process::id()))
                .exists()
        );
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn failed_replacement_preserves_the_existing_file() {
        let path = test_config_path("failure");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"original").unwrap();
        let missing = path.with_file_name("missing.tmp");

        assert!(replace_file_atomic(&missing, &path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"original");
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn invalid_and_future_configs_are_rejected_without_overwrite() {
        let path = test_config_path("invalid");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"not json").unwrap();
        assert!(AppConfig::load_or_create(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"not json");

        let future = serde_json::json!({
            "schema_version": SCHEMA_VERSION + 1,
            "rules": []
        });
        fs::write(&path, serde_json::to_vec(&future).unwrap()).unwrap();
        assert!(AppConfig::load_or_create(&path).is_err());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(&path).unwrap()).unwrap(),
            future
        );
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn unsafe_rule_values_are_rejected() {
        let mut config = AppConfig::default();
        config.rules[0].allow_suspend = true;
        config.rules[0].throttle_after_seconds = 0;
        config.rules[0].suspend_after_seconds = 0;
        assert!(config.validate().is_err());

        config.rules[0].throttle_after_seconds = 60;
        config.rules[0].suspend_after_seconds = 120;
        config.rules[0].matcher = RuleMatcher {
            path_contains: Some(String::new()),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn duplicate_rule_ids_are_rejected() {
        let mut config = AppConfig::default();
        config.rules.push(config.rules[0].clone());
        assert!(config.validate().is_err());
    }

    #[test]
    fn elevated_only_legacy_journal_does_not_move_the_active_directory() {
        let root = test_config_path("journal-selection");
        let local = root.with_file_name("local-suspended.json");
        let roaming_dir = root.with_file_name("roaming");
        let roaming = roaming_dir.join("suspended.json");
        fs::create_dir_all(&roaming_dir).unwrap();
        fs::write(roaming.with_file_name("suspended-elevated.json"), b"[]").unwrap();

        assert_eq!(select_existing_path(&local, &roaming), local);

        fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    #[test]
    fn restoring_presets_adds_only_the_missing_ones_and_keeps_edits() {
        let mut config = AppConfig::default();
        let total = config.rules.len();
        assert!(total > 0, "the default configuration ships presets");

        // Simulate a user who deleted one preset and renamed another.
        let removed_id = config.rules[0].id.clone();
        config.rules.remove(0);
        config.rules[0].name = "我的规则".into();
        let kept_id = config.rules[0].id.clone();

        assert_eq!(config.restore_missing_presets(), 1);
        assert_eq!(config.rules.len(), total);
        assert!(config.rules.iter().any(|rule| rule.id == removed_id));
        assert_eq!(
            config
                .rules
                .iter()
                .find(|rule| rule.id == kept_id)
                .map(|rule| rule.name.as_str()),
            Some("我的规则"),
            "restoring must not overwrite a preset the user has edited"
        );
        // A second call has nothing left to do.
        assert_eq!(config.restore_missing_presets(), 0);
    }

    #[test]
    fn a_schedule_outside_a_day_is_rejected() {
        let mut config = AppConfig::default();
        config.rules[0].schedule = Some(RuleSchedule {
            start_minute: 1440,
            end_minute: 60,
            days: 0,
        });
        assert!(config.validate().is_err());

        config.rules[0].schedule = Some(RuleSchedule {
            start_minute: 1439,
            end_minute: 0,
            days: 0,
        });
        assert!(config.validate().is_ok());
    }

    #[test]
    fn a_theme_preference_survives_a_round_trip() {
        let config = AppConfig {
            theme: ThemePreference::Dark,
            ..Default::default()
        };
        let text = serde_json::to_string(&config).unwrap();
        assert!(text.contains("\"theme\":\"dark\""));
        let parsed: AppConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed.theme, ThemePreference::Dark);

        // A configuration written before themes existed still loads.
        let older = text.replace("\"theme\":\"dark\",", "");
        let parsed: AppConfig = serde_json::from_str(&older).unwrap();
        assert_eq!(parsed.theme, ThemePreference::System);
    }
}
