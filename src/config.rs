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
        // An empty window covers the whole day rather than nothing, so a half-filled schedule
        // cannot silently disable a rule.
        if self.start_minute == self.end_minute {
            return self.day_is_enabled(weekday);
        }
        if self.start_minute < self.end_minute {
            return self.day_is_enabled(weekday)
                && (self.start_minute..self.end_minute).contains(&minute_of_day);
        }
        // The window wraps midnight. The part at or after `start_minute` is the evening that
        // belongs to this day; the part before `end_minute` is the tail of the *previous* day's
        // window. Testing the current weekday for both would cut a night in half at midnight, so a
        // rule set to "Monday, 22:00-06:00" would never reach 06:00 on Tuesday.
        if minute_of_day >= self.start_minute {
            return self.day_is_enabled(weekday);
        }
        if minute_of_day < self.end_minute {
            let previous = match weekday {
                0 => 6,
                day if day < 7 => day - 1,
                // A weekday outside the seven the OS reports is allowed rather than denied.
                _ => return true,
            };
            return self.day_is_enabled(previous);
        }
        false
    }

    /// Whether the day mask allows `weekday`. A zero mask means every day, and a weekday outside
    /// the seven the OS reports is allowed rather than denied. Takes `self` by value because the
    /// struct is smaller than a pointer.
    fn day_is_enabled(self, weekday: u8) -> bool {
        if self.days == 0 || weekday >= 7 {
            return true;
        }
        self.days & (1 << weekday) != 0
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
        // Repair values that are out of range before validating, so a hand-edited file with one bad
        // bit is fixed rather than rejected. Rejecting it would drop into the degraded "config failed
        // to load" mode, where the next settings change writes a default over the user's file.
        config.normalize();
        config.validate()?;
        Ok(config)
    }

    /// Clamps values that a hand-edited file can push out of range. Only fields where a sensible
    /// repair exists are touched; everything else is left for [`Self::validate`] to reject.
    fn normalize(&mut self) {
        for rule in &mut self.rules {
            if let Some(schedule) = &mut rule.schedule {
                // Only bits 0-6 name a day. Clearing the rest keeps the days the user did pick; a
                // mask that was entirely out of range becomes zero, which means "every day" rather
                // than a rule that can never run.
                schedule.days &= 0b0111_1111;
            }
        }
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
            // Only bits 0-6 name a day. A bit outside that range is non-zero, so `contains` would
            // treat the schedule as a real restriction that no weekday can ever satisfy, silently
            // disabling the rule instead of failing loudly.
            if let Some(schedule) = &rule.schedule
                && schedule.days & !0b0111_1111 != 0
            {
                return Err(invalid_config(format!(
                    "规则 {} 的生效日包含无效的星期",
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

    /// A hand-edited file with a day bit outside the week must be repaired on load rather than
    /// rejected: rejecting it drops the whole configuration into the degraded mode where the next
    /// settings change writes a default over the user's file, losing every other rule. The days the
    /// user did pick have to survive the repair.
    #[test]
    fn an_out_of_range_day_mask_is_repaired_on_load_not_rejected() {
        let path = test_config_path("days-repair");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut config = AppConfig::default();
        config.rules[0].schedule = Some(RuleSchedule {
            start_minute: 22 * 60,
            end_minute: 6 * 60,
            // Monday plus the invalid bit 7.
            days: 0b1000_0010,
        });
        // `save_atomic` validates, so write the JSON directly, as a hand edit would.
        let mut raw = serde_json::to_value(&config).unwrap();
        fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();

        let loaded = AppConfig::load_or_create(&path).expect("the file must load after repair");
        assert_eq!(
            loaded.rules[0].schedule.unwrap().days,
            0b0000_0010,
            "the valid Monday bit must survive while bit 7 is cleared"
        );

        // A mask that was entirely out of range becomes zero, which means every day rather than a
        // rule that can never run.
        raw["rules"][0]["schedule"]["days"] = serde_json::json!(0b1000_0000);
        fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
        let loaded = AppConfig::load_or_create(&path).unwrap();
        assert_eq!(loaded.rules[0].schedule.unwrap().days, 0);

        // Saving is still strict, so the invalid value cannot be written back out.
        let mut strict = AppConfig::default();
        strict.rules[0].schedule = Some(RuleSchedule {
            start_minute: 0,
            end_minute: 0,
            days: 0b1000_0000,
        });
        assert!(strict.save_atomic(&path).is_err());
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

    /// A window that wraps midnight is documented as covering "the night", so a rule restricted to
    /// Monday and set to 22:00-06:00 should cover Monday evening *and* the small hours of Tuesday.
    /// Checking the day mask against the current weekday alone cuts that night in half at midnight.
    #[test]
    fn a_wrapping_window_keeps_its_day_across_midnight() {
        // Monday only, 22:00-06:00. Bit 1 is Monday (bit 0 is Sunday).
        let monday_night = RuleSchedule {
            start_minute: 22 * 60,
            end_minute: 6 * 60,
            days: 0b0000_0010,
        };
        // Monday evening is inside.
        assert!(monday_night.contains(23 * 60, 1));
        // The small hours of Tuesday still belong to Monday night.
        assert!(
            monday_night.contains(2 * 60, 2),
            "the night must survive the midnight boundary"
        );
        assert!(monday_night.contains(5 * 60 + 59, 2));
        // But Tuesday evening is not part of Monday night.
        assert!(!monday_night.contains(23 * 60, 2));
        // Sunday night is not Monday night either.
        assert!(!monday_night.contains(2 * 60, 1));
        // The exclusive end is still excluded, now on the following day.
        assert!(!monday_night.contains(6 * 60, 2));
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

    /// The `days` mask has seven meaningful bits, one per day. A value with a bit outside that
    /// range is non-zero, so `contains` treats it as a real restriction, yet it can never match a
    /// weekday the OS reports (0-6). The rule would then be silently dead, which is exactly what the
    /// "a half-filled schedule cannot silently disable a rule" promise rules out.
    #[test]
    fn a_day_mask_with_a_bit_outside_the_week_is_rejected() {
        let mut config = AppConfig::default();
        config.rules[0].schedule = Some(RuleSchedule {
            start_minute: 0,
            end_minute: 0,
            days: 0b1000_0000,
        });
        assert!(
            config.validate().is_err(),
            "a day mask with no valid day must not validate"
        );

        // Every in-range mask is still accepted, including all seven days.
        for days in [0b0000_0001_u8, 0b0111_1111, 0b0011_1110] {
            config.rules[0].schedule = Some(RuleSchedule {
                start_minute: 0,
                end_minute: 0,
                days,
            });
            assert!(config.validate().is_ok(), "days {days:#010b} must validate");
        }
    }

    /// The wrap fix must not change what a window that does *not* wrap does, and the "every day"
    /// mask must still cover every day. These are the cases the fix could plausibly have broken.
    #[test]
    fn day_masks_keep_their_meaning_in_both_directions() {
        // Monday only, a plain 09:00-17:00 window.
        let monday_day = RuleSchedule {
            start_minute: 9 * 60,
            end_minute: 17 * 60,
            days: 0b0000_0010,
        };
        assert!(monday_day.contains(9 * 60, 1));
        assert!(monday_day.contains(16 * 60 + 59, 1));
        assert!(!monday_day.contains(17 * 60, 1));
        assert!(!monday_day.contains(8 * 60 + 59, 1));
        // A non-wrapping window must not bleed into the next day.
        assert!(!monday_day.contains(9 * 60, 2));
        assert!(!monday_day.contains(2 * 60, 2));

        // The same wrap window with "every day" covers every hour of every day.
        let nightly = RuleSchedule {
            start_minute: 22 * 60,
            end_minute: 6 * 60,
            days: 0,
        };
        for weekday in 0..7 {
            assert!(nightly.contains(23 * 60, weekday));
            assert!(nightly.contains(2 * 60, weekday));
            assert!(!nightly.contains(12 * 60, weekday));
        }

        // Saturday night rolling into Sunday: bit 6 is Saturday, bit 0 is Sunday.
        let saturday_night = RuleSchedule {
            start_minute: 22 * 60,
            end_minute: 6 * 60,
            days: 0b0100_0000,
        };
        assert!(saturday_night.contains(23 * 60, 6));
        assert!(
            saturday_night.contains(60, 0),
            "Saturday night ends Sunday morning"
        );
        assert!(!saturday_night.contains(60, 1));

        // Sunday night rolls back to the start of the week.
        let sunday_night = RuleSchedule {
            start_minute: 22 * 60,
            end_minute: 6 * 60,
            days: 0b0000_0001,
        };
        assert!(sunday_night.contains(23 * 60, 0));
        assert!(
            sunday_night.contains(3 * 60, 1),
            "Sunday night ends Monday morning"
        );

        // An out-of-range weekday is allowed rather than denied, in both window shapes.
        assert!(monday_day.contains(12 * 60, 99));
        assert!(monday_night_of(0b0000_0010).contains(2 * 60, 99));
    }

    fn monday_night_of(days: u8) -> RuleSchedule {
        RuleSchedule {
            start_minute: 22 * 60,
            end_minute: 6 * 60,
            days,
        }
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
