use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub started_at: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub started_at_ticks: u64,
    pub executable_path: PathBuf,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[derive(Debug, Clone)]
pub struct ProcessSample {
    pub identity: ProcessIdentity,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub command_line: String,
    pub cpu_percent: f32,
    pub io_bytes: u64,
    /// Resident set, in bytes.
    pub memory_bytes: u64,
    /// Committed address space, in bytes.
    pub virtual_memory_bytes: u64,
    /// Seconds since the process started.
    pub run_time_seconds: u64,
    /// Threads in the process, or zero when the count could not be read.
    pub thread_count: u32,
    /// Whether the process is currently suspended, as reported by the OS rather than by our own
    /// journal. Lets the explorer show processes something else suspended.
    pub os_suspended: bool,
}

/// Machine-wide totals for the explorer header. Sampled alongside the process list so the two
/// always describe the same instant.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemSnapshot {
    pub cpu_percent: f32,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub process_count: usize,
    /// Logical processors, for reading the per-process CPU percentages.
    pub cpu_count: usize,
}

impl SystemSnapshot {
    #[must_use]
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    pub fn memory_percent(&self) -> f32 {
        if self.memory_total_bytes == 0 {
            return 0.0;
        }
        // f64 keeps the ratio exact for byte counts a f32 mantissa could not hold.
        let ratio = self.memory_used_bytes as f64 / self.memory_total_bytes as f64;
        (ratio * 100.0) as f32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityState {
    Active,
    Quiet,
    Throttled,
    Suspended,
    Unresponsive,
    Inaccessible,
}

impl ActivityState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Active => "活跃",
            Self::Quiet => "静默",
            Self::Throttled => "低耗",
            Self::Suspended => "已暂停",
            Self::Unresponsive => "未响应",
            Self::Inaccessible => "权限不足",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProcessGroup {
    pub rule_id: String,
    pub root: ProcessIdentity,
    pub root_name: String,
    pub members: Vec<ProcessSample>,
    pub focused: bool,
}

impl ProcessGroup {
    #[must_use]
    pub fn cpu_percent(&self) -> f32 {
        self.members.iter().map(|sample| sample.cpu_percent).sum()
    }

    #[must_use]
    pub fn io_bytes(&self) -> u64 {
        self.members.iter().map(|sample| sample.io_bytes).sum()
    }

    #[must_use]
    pub fn memory_bytes(&self) -> u64 {
        self.members.iter().map(|sample| sample.memory_bytes).sum()
    }
}

/// One process inside a reported group, so the panel can show what it is actually managing instead
/// of only how many there are.
#[derive(Debug, Clone)]
pub struct GroupMember {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    /// Depth below the group root, for indenting the tree.
    pub depth: usize,
}

#[derive(Debug, Clone)]
pub struct GroupStatus {
    pub rule_id: String,
    pub root: ProcessIdentity,
    pub root_name: String,
    pub process_count: usize,
    pub state: ActivityState,
    pub quiet_seconds: u64,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub detail: String,
    pub members: Vec<GroupMember>,
    /// Seconds until the next action, and what it would be. `None` once nothing further is pending.
    pub next_action: Option<(ManagedActionKind, u64)>,
}

/// Which action a group is counting down towards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedActionKind {
    Throttle,
    Suspend,
}

impl ManagedActionKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Throttle => "降载",
            Self::Suspend => "暂停",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(pid: u32, started_at: u64, ticks: u64, path: &str) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            started_at,
            started_at_ticks: ticks,
            executable_path: PathBuf::from(path),
        }
    }

    /// Identity equality is what every action revalidates against before touching a process, so a
    /// recycled pid must never compare equal to the original. All three components have to matter.
    #[test]
    fn identity_distinguishes_a_recycled_pid() {
        let original = identity(100, 1_000, 5_000, r"C:\bin\app.exe");
        assert_eq!(original, original.clone());
        // Same pid, same path, different start time: a recycled pid.
        assert_ne!(original, identity(100, 2_000, 5_000, r"C:\bin\app.exe"));
        assert_ne!(original, identity(100, 1_000, 9_000, r"C:\bin\app.exe"));
        // Same pid and start time, different image: also not the same process.
        assert_ne!(original, identity(100, 1_000, 5_000, r"C:\bin\other.exe"));
        assert_ne!(original, identity(101, 1_000, 5_000, r"C:\bin\app.exe"));
    }

    /// `started_at_ticks` is optional on the wire: it is skipped when zero and defaults back to zero
    /// on load, so a journal written by an older build still round-trips. `started_at` stays
    /// mandatory, which is the coarser fallback `identity_matches` compares against.
    #[test]
    fn identity_serialization_omits_and_restores_zero_ticks() {
        let coarse = identity(100, 1_000, 0, r"C:\bin\app.exe");
        let json = serde_json::to_string(&coarse).expect("identity serializes");
        assert!(
            !json.contains("started_at_ticks"),
            "zero ticks should be omitted: {json}"
        );
        let restored: ProcessIdentity = serde_json::from_str(&json).expect("identity deserializes");
        assert_eq!(restored, coarse);
        assert_eq!(restored.started_at_ticks, 0);

        // A non-zero value is written and read back exactly.
        let precise = identity(100, 1_000, 5_000, r"C:\bin\app.exe");
        let json = serde_json::to_string(&precise).expect("identity serializes");
        assert!(
            json.contains("started_at_ticks"),
            "ticks should be kept: {json}"
        );
        assert_eq!(
            serde_json::from_str::<ProcessIdentity>(&json).expect("identity deserializes"),
            precise
        );
    }

    /// A missing `started_at_ticks` in an older journal must load as zero rather than failing, which
    /// is what the `#[serde(default)]` is for.
    #[test]
    fn an_older_journal_without_ticks_still_loads() {
        let json = r#"{"pid":100,"started_at":1000,"executable_path":"C:\\bin\\app.exe"}"#;
        let restored: ProcessIdentity = serde_json::from_str(json).expect("legacy identity loads");
        assert_eq!(restored.started_at_ticks, 0);
        assert_eq!(restored.started_at, 1_000);
    }

    #[test]
    fn memory_percent_is_zero_without_a_total_and_capped_by_the_ratio() {
        let empty = SystemSnapshot::default();
        assert!((empty.memory_percent() - 0.0).abs() < f32::EPSILON);
        let half = SystemSnapshot {
            memory_used_bytes: 8,
            memory_total_bytes: 16,
            ..SystemSnapshot::default()
        };
        assert!((half.memory_percent() - 50.0).abs() < f32::EPSILON);
        // A ratio over one is reported as-is rather than clamped, so an over-commit is visible.
        let over = SystemSnapshot {
            memory_used_bytes: 32,
            memory_total_bytes: 16,
            ..SystemSnapshot::default()
        };
        assert!((over.memory_percent() - 200.0).abs() < f32::EPSILON);
    }

    #[test]
    fn group_totals_sum_every_member() {
        let sample = |pid: u32, cpu: f32, io: u64, memory: u64| ProcessSample {
            identity: identity(pid, 1, 1, r"C:\bin\app.exe"),
            parent_pid: None,
            name: "app.exe".into(),
            command_line: String::new(),
            cpu_percent: cpu,
            io_bytes: io,
            memory_bytes: memory,
            virtual_memory_bytes: 0,
            run_time_seconds: 0,
            thread_count: 0,
            os_suspended: false,
        };
        let group = ProcessGroup {
            rule_id: "rule".into(),
            root: identity(1, 1, 1, r"C:\bin\app.exe"),
            root_name: "app.exe".into(),
            members: vec![
                sample(1, 1.5, 100, 1_000),
                sample(2, 2.5, 200, 2_000),
                sample(3, 0.5, 300, 3_000),
            ],
            focused: false,
        };
        assert!((group.cpu_percent() - 4.5).abs() < f32::EPSILON);
        assert_eq!(group.io_bytes(), 600);
        assert_eq!(group.memory_bytes(), 6_000);
        // An empty group totals zero rather than panicking.
        let empty = ProcessGroup {
            members: Vec::new(),
            ..group
        };
        assert!((empty.cpu_percent() - 0.0).abs() < f32::EPSILON);
        assert_eq!(empty.io_bytes(), 0);
        assert_eq!(empty.memory_bytes(), 0);
    }

    #[test]
    fn every_activity_state_has_a_distinct_label() {
        let states = [
            ActivityState::Active,
            ActivityState::Quiet,
            ActivityState::Throttled,
            ActivityState::Suspended,
            ActivityState::Unresponsive,
            ActivityState::Inaccessible,
        ];
        let labels = states.map(ActivityState::label);
        for (index, label) in labels.iter().enumerate() {
            assert!(!label.is_empty(), "state {index} has no label");
            assert!(
                !labels[..index].contains(label),
                "duplicate label {label}, which would make the status column ambiguous"
            );
        }
        assert_eq!(ManagedActionKind::Throttle.label(), "降载");
        assert_eq!(ManagedActionKind::Suspend.label(), "暂停");
    }

    /// The states are persisted in the configuration's vocabulary, so the wire names must stay
    /// stable: renaming one would silently invalidate saved schedules and journals.
    #[test]
    fn activity_state_wire_names_are_stable() {
        let cases = [
            (ActivityState::Active, "\"active\""),
            (ActivityState::Quiet, "\"quiet\""),
            (ActivityState::Throttled, "\"throttled\""),
            (ActivityState::Suspended, "\"suspended\""),
            (ActivityState::Unresponsive, "\"unresponsive\""),
            (ActivityState::Inaccessible, "\"inaccessible\""),
        ];
        for (state, expected) in cases {
            assert_eq!(serde_json::to_string(&state).unwrap(), expected);
            assert_eq!(
                serde_json::from_str::<ActivityState>(expected).unwrap(),
                state
            );
        }
    }
}
