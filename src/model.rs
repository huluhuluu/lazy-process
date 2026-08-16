use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub started_at: u64,
    pub executable_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ProcessSample {
    pub identity: ProcessIdentity,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub command_line: String,
    pub cpu_percent: f32,
    pub io_bytes: u64,
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
    pub fn pids(&self) -> BTreeSet<u32> {
        self.members
            .iter()
            .map(|sample| sample.identity.pid)
            .collect()
    }

    #[must_use]
    pub fn cpu_percent(&self) -> f32 {
        self.members.iter().map(|sample| sample.cpu_percent).sum()
    }

    #[must_use]
    pub fn io_bytes(&self) -> u64 {
        self.members.iter().map(|sample| sample.io_bytes).sum()
    }
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
    pub detail: String,
}
