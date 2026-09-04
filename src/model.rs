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
