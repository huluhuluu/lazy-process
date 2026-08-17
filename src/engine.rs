use crate::{
    config::{AppConfig, ProcessRule, RuleMatcher},
    model::{ActivityState, GroupStatus, ProcessGroup, ProcessIdentity, ProcessSample},
};
use regex::Regex;
use std::collections::{BTreeSet, HashMap, HashSet};

pub trait ResourceController {
    fn throttle(&mut self, processes: &[ProcessIdentity]) -> Result<(), String>;
    fn suspend(&mut self, processes: &[ProcessIdentity]) -> Result<(), String>;
    fn restore(&mut self, processes: &[ProcessIdentity]) -> Result<(), String>;
    fn restore_all(&mut self) -> Vec<String>;
    fn enable_elevation(&mut self) -> Result<(), String>;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GroupKey {
    rule_id: String,
    pid: u32,
    started_at: u64,
}

#[derive(Debug, Clone)]
struct TrackedGroup {
    state: ActivityState,
    quiet_since: Option<u64>,
    last_io_bytes: u64,
    last_pids: BTreeSet<u32>,
    identities: Vec<ProcessIdentity>,
    last_error: Option<String>,
}

impl TrackedGroup {
    fn new(group: &ProcessGroup) -> Self {
        Self {
            state: ActivityState::Active,
            quiet_since: None,
            last_io_bytes: group.io_bytes(),
            last_pids: group.pids(),
            identities: identities(group),
            last_error: None,
        }
    }
}

pub struct Engine<C> {
    controller: C,
    tracked: HashMap<GroupKey, TrackedGroup>,
}

impl<C: ResourceController> Engine<C> {
    #[must_use]
    pub fn new(controller: C) -> Self {
        Self {
            controller,
            tracked: HashMap::new(),
        }
    }

    pub fn tick(
        &mut self,
        config: &AppConfig,
        processes: &[ProcessSample],
        foreground_pid: Option<u32>,
        now_seconds: u64,
    ) -> Vec<GroupStatus> {
        self.tick_with_unresponsive(
            config,
            processes,
            foreground_pid,
            &HashSet::new(),
            now_seconds,
        )
    }

    #[allow(clippy::too_many_lines)]
    pub fn tick_with_unresponsive(
        &mut self,
        config: &AppConfig,
        processes: &[ProcessSample],
        foreground_pid: Option<u32>,
        unresponsive_pids: &HashSet<u32>,
        now_seconds: u64,
    ) -> Vec<GroupStatus> {
        let groups = build_groups(config, processes, foreground_pid);
        let mut present = HashSet::new();
        let mut statuses = Vec::with_capacity(groups.len());

        for (rule, group) in groups {
            let key = GroupKey {
                rule_id: rule.id.clone(),
                pid: group.root.pid,
                started_at: group.root.started_at,
            };
            present.insert(key.clone());
            let tracked = self
                .tracked
                .entry(key)
                .or_insert_with(|| TrackedGroup::new(&group));
            let current_pids = group.pids();
            let membership_changed = tracked.last_pids != current_pids;
            let io_delta = group.io_bytes().saturating_sub(tracked.last_io_bytes);
            let quiet_sample = !group.focused
                && !membership_changed
                && group.cpu_percent() <= config.cpu_quiet_percent
                && io_delta <= config.io_quiet_bytes_per_sample;
            let current_identities = identities(&group);
            let unresponsive = group
                .members
                .iter()
                .any(|member| unresponsive_pids.contains(&member.identity.pid));

            if unresponsive {
                if matches!(
                    tracked.state,
                    ActivityState::Throttled
                        | ActivityState::Suspended
                        | ActivityState::Inaccessible
                ) {
                    let _ = self.controller.restore(&tracked.identities);
                }
                tracked.state = ActivityState::Unresponsive;
                tracked.quiet_since = None;
            } else if !config.globally_enabled || !rule.enabled || group.focused || !quiet_sample {
                if matches!(
                    tracked.state,
                    ActivityState::Throttled
                        | ActivityState::Suspended
                        | ActivityState::Inaccessible
                ) {
                    match self.controller.restore(&tracked.identities) {
                        Ok(()) => tracked.last_error = None,
                        Err(error) => tracked.last_error = Some(error),
                    }
                }
                tracked.state = ActivityState::Active;
                tracked.quiet_since = None;
            } else {
                let quiet_since = *tracked.quiet_since.get_or_insert(now_seconds);
                let quiet_for = now_seconds.saturating_sub(quiet_since);
                if rule.allow_suspend && quiet_for >= rule.suspend_after_seconds {
                    if tracked.state != ActivityState::Suspended {
                        if tracked.state != ActivityState::Throttled {
                            let _ = self.controller.throttle(&current_identities);
                        }
                        match self.controller.suspend(&current_identities) {
                            Ok(()) => {
                                tracked.state = ActivityState::Suspended;
                                tracked.last_error = None;
                            }
                            Err(error) => {
                                tracked.state = ActivityState::Inaccessible;
                                tracked.last_error = Some(error);
                            }
                        }
                    }
                } else if quiet_for >= rule.throttle_after_seconds {
                    if !matches!(
                        tracked.state,
                        ActivityState::Throttled | ActivityState::Suspended
                    ) {
                        match self.controller.throttle(&current_identities) {
                            Ok(()) => {
                                tracked.state = ActivityState::Throttled;
                                tracked.last_error = None;
                            }
                            Err(error) => {
                                tracked.state = ActivityState::Inaccessible;
                                tracked.last_error = Some(error);
                            }
                        }
                    }
                } else {
                    tracked.state = ActivityState::Quiet;
                }
            }

            tracked.last_io_bytes = group.io_bytes();
            tracked.last_pids = current_pids;
            tracked.identities = current_identities;
            let quiet_seconds = tracked
                .quiet_since
                .map_or(0, |since| now_seconds.saturating_sub(since));
            let detail = tracked.last_error.clone().unwrap_or_else(|| {
                if group.focused {
                    "宿主位于前台".into()
                } else {
                    format!(
                        "CPU {:.1}% · 静默 {} 秒",
                        group.cpu_percent(),
                        quiet_seconds
                    )
                }
            });
            let cpu_percent = group.cpu_percent();
            statuses.push(GroupStatus {
                rule_id: rule.id.clone(),
                root: group.root,
                root_name: group.root_name,
                process_count: group.members.len(),
                state: tracked.state,
                quiet_seconds,
                cpu_percent,
                detail,
            });
        }

        let stale = self
            .tracked
            .keys()
            .filter(|key| !present.contains(*key))
            .cloned()
            .collect::<Vec<_>>();
        for key in stale {
            if let Some(group) = self.tracked.remove(&key)
                && matches!(
                    group.state,
                    ActivityState::Throttled
                        | ActivityState::Suspended
                        | ActivityState::Inaccessible
                )
            {
                let _ = self.controller.restore(&group.identities);
            }
        }
        statuses.sort_by(|left, right| {
            left.rule_id
                .cmp(&right.rule_id)
                .then(left.root.pid.cmp(&right.root.pid))
        });
        statuses
    }

    pub fn restore_all(&mut self) -> Vec<String> {
        let errors = self.controller.restore_all();
        for group in self.tracked.values_mut() {
            group.state = ActivityState::Active;
            group.quiet_since = None;
            group.last_error = None;
        }
        errors
    }

    pub fn enable_elevation(&mut self) -> Result<(), String> {
        self.controller.enable_elevation()
    }
}

fn identities(group: &ProcessGroup) -> Vec<ProcessIdentity> {
    group
        .members
        .iter()
        .map(|sample| sample.identity.clone())
        .collect()
}

fn build_groups<'a>(
    config: &'a AppConfig,
    processes: &[ProcessSample],
    foreground_pid: Option<u32>,
) -> Vec<(&'a ProcessRule, ProcessGroup)> {
    let by_pid = processes
        .iter()
        .map(|sample| (sample.identity.pid, sample))
        .collect::<HashMap<_, _>>();
    let mut children_by_parent = HashMap::<u32, Vec<u32>>::new();
    for process in processes {
        if let Some(parent) = process.parent_pid {
            children_by_parent
                .entry(parent)
                .or_default()
                .push(process.identity.pid);
        }
    }
    let mut rules = config
        .rules
        .iter()
        .filter(|rule| rule.enabled)
        .collect::<Vec<_>>();
    rules.sort_by_key(|rule| rule.built_in);
    let mut claimed = HashSet::new();
    let mut groups = Vec::new();

    for rule in rules {
        for root in processes {
            if claimed.contains(&root.identity) || !matches_rule(&rule.matcher, root, &by_pid) {
                continue;
            }
            if rule
                .exclusions
                .iter()
                .any(|matcher| matches_rule(matcher, root, &by_pid))
            {
                continue;
            }
            let mut members = vec![root.clone()];
            if rule.include_descendants {
                let mut included = HashSet::from([root.identity.pid]);
                let mut pending = vec![root.identity.pid];
                while let Some(parent) = pending.pop() {
                    if let Some(children) = children_by_parent.get(&parent) {
                        for &child in children {
                            if included.insert(child) {
                                pending.push(child);
                            }
                        }
                    }
                }
                members = processes
                    .iter()
                    .filter(|process| included.contains(&process.identity.pid))
                    .cloned()
                    .collect();
                members.sort_by_key(|member| member.identity.pid != root.identity.pid);
            }
            claimed.extend(members.iter().map(|member| member.identity.clone()));
            let focused = foreground_pid
                .is_some_and(|pid| members.iter().any(|member| member.identity.pid == pid));
            groups.push((
                rule,
                ProcessGroup {
                    rule_id: rule.id.clone(),
                    root: root.identity.clone(),
                    root_name: root.name.clone(),
                    members,
                    focused,
                },
            ));
        }
    }
    groups
}

fn matches_rule(
    matcher: &RuleMatcher,
    process: &ProcessSample,
    by_pid: &HashMap<u32, &ProcessSample>,
) -> bool {
    if let Some(name) = &matcher.process_name
        && !process.name.eq_ignore_ascii_case(name)
    {
        return false;
    }
    if let Some(path) = &matcher.executable_path
        && !process
            .identity
            .executable_path
            .as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&path.as_os_str().to_string_lossy())
    {
        return false;
    }
    if let Some(fragment) = &matcher.path_contains
        && !contains_case_insensitive(
            &process.identity.executable_path.to_string_lossy(),
            fragment,
        )
    {
        return false;
    }
    if let Some(fragment) = &matcher.command_contains
        && !contains_case_insensitive(&process.command_line, fragment)
    {
        return false;
    }
    if let Some(pattern) = &matcher.command_regex
        && Regex::new(pattern).map_or(true, |regex| !regex.is_match(&process.command_line))
    {
        return false;
    }
    if let Some(ancestor_name) = &matcher.ancestor_process_name {
        let mut parent = process.parent_pid;
        let mut found = false;
        let mut visited = HashSet::new();
        while let Some(pid) = parent {
            if !visited.insert(pid) {
                break;
            }
            let Some(ancestor) = by_pid.get(&pid) else {
                break;
            };
            if ancestor.name.eq_ignore_ascii_case(ancestor_name) {
                found = true;
                break;
            }
            parent = ancestor.parent_pid;
        }
        if !found {
            return false;
        }
    }
    matcher.process_name.is_some()
        || matcher.executable_path.is_some()
        || matcher.path_contains.is_some()
        || matcher.command_contains.is_some()
        || matcher.command_regex.is_some()
}

fn contains_case_insensitive(value: &str, fragment: &str) -> bool {
    value.to_lowercase().contains(&fragment.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProcessRule, RuleMatcher};
    use std::path::PathBuf;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Default)]
    struct FakeController {
        throttles: usize,
        suspends: usize,
        restores: usize,
    }

    impl ResourceController for FakeController {
        fn throttle(&mut self, _: &[ProcessIdentity]) -> Result<(), String> {
            self.throttles += 1;
            Ok(())
        }
        fn suspend(&mut self, _: &[ProcessIdentity]) -> Result<(), String> {
            self.suspends += 1;
            Ok(())
        }
        fn restore(&mut self, _: &[ProcessIdentity]) -> Result<(), String> {
            self.restores += 1;
            Ok(())
        }
        fn restore_all(&mut self) -> Vec<String> {
            self.restores += 1;
            Vec::new()
        }
        fn enable_elevation(&mut self) -> Result<(), String> {
            Ok(())
        }
    }

    struct PartialFailureController {
        restores: Arc<AtomicUsize>,
    }

    impl ResourceController for PartialFailureController {
        fn throttle(&mut self, _: &[ProcessIdentity]) -> Result<(), String> {
            Err("partial access failure".into())
        }
        fn suspend(&mut self, _: &[ProcessIdentity]) -> Result<(), String> {
            Err("partial access failure".into())
        }
        fn restore(&mut self, _: &[ProcessIdentity]) -> Result<(), String> {
            self.restores.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn restore_all(&mut self) -> Vec<String> {
            Vec::new()
        }
        fn enable_elevation(&mut self) -> Result<(), String> {
            Ok(())
        }
    }

    fn process(pid: u32, parent: Option<u32>, name: &str, cpu: f32, io: u64) -> ProcessSample {
        ProcessSample {
            identity: ProcessIdentity {
                pid,
                started_at: u64::from(pid),
                executable_path: PathBuf::from(format!(r"C:\bin\{name}")),
            },
            parent_pid: parent,
            name: name.into(),
            command_line: name.into(),
            cpu_percent: cpu,
            io_bytes: io,
        }
    }

    fn test_config(suspend: bool) -> AppConfig {
        AppConfig {
            sample_interval_seconds: 2,
            cpu_quiet_percent: 1.0,
            io_quiet_bytes_per_sample: 4096,
            rules: vec![ProcessRule {
                id: "codex".into(),
                name: "Codex".into(),
                enabled: true,
                allow_suspend: suspend,
                throttle_after_seconds: 5,
                suspend_after_seconds: 20,
                matcher: RuleMatcher {
                    process_name: Some("codex.exe".into()),
                    ..Default::default()
                },
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn throttles_then_resumes_on_focus() {
        let mut engine = Engine::new(FakeController::default());
        let samples = vec![
            process(10, None, "codex.exe", 0.0, 100),
            process(11, Some(10), "pwsh.exe", 0.0, 100),
        ];
        engine.tick(&test_config(false), &samples, None, 0);
        let statuses = engine.tick(&test_config(false), &samples, None, 6);
        assert_eq!(statuses[0].state, ActivityState::Throttled);
        let statuses = engine.tick(&test_config(false), &samples, Some(10), 8);
        assert_eq!(statuses[0].state, ActivityState::Active);
    }

    #[test]
    fn suspension_requires_explicit_permission() {
        let samples = vec![process(10, None, "codex.exe", 0.0, 0)];
        let mut safe = Engine::new(FakeController::default());
        safe.tick(&test_config(false), &samples, None, 0);
        assert_eq!(
            safe.tick(&test_config(false), &samples, None, 30)[0].state,
            ActivityState::Throttled
        );

        let mut enabled = Engine::new(FakeController::default());
        enabled.tick(&test_config(true), &samples, None, 0);
        assert_eq!(
            enabled.tick(&test_config(true), &samples, None, 30)[0].state,
            ActivityState::Suspended
        );
    }

    #[test]
    fn activity_and_new_descendants_reset_quiet_timer() {
        let mut engine = Engine::new(FakeController::default());
        let config = test_config(false);
        let base = vec![process(10, None, "codex.exe", 0.0, 0)];
        engine.tick(&config, &base, None, 0);
        let with_child = vec![
            process(10, None, "codex.exe", 0.0, 0),
            process(11, Some(10), "pwsh.exe", 0.0, 0),
        ];
        assert_eq!(
            engine.tick(&config, &with_child, None, 10)[0].state,
            ActivityState::Active
        );
        let busy = vec![
            process(10, None, "codex.exe", 5.0, 0),
            process(11, Some(10), "pwsh.exe", 0.0, 0),
        ];
        assert_eq!(
            engine.tick(&config, &busy, None, 20)[0].state,
            ActivityState::Active
        );
    }

    #[test]
    fn ancestor_filter_distinguishes_pwsh_hosts() {
        let mut config = test_config(false);
        config.rules[0].matcher = RuleMatcher {
            process_name: Some("pwsh.exe".into()),
            ancestor_process_name: Some("WindowsTerminal.exe".into()),
            ..Default::default()
        };
        let samples = vec![
            process(1, None, "WindowsTerminal.exe", 0.0, 0),
            process(2, Some(1), "pwsh.exe", 0.0, 0),
            process(3, None, "codex.exe", 0.0, 0),
            process(4, Some(3), "pwsh.exe", 0.0, 0),
        ];
        let mut engine = Engine::new(FakeController::default());
        let statuses = engine.tick(&config, &samples, None, 0);
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].root.pid, 2);
    }

    #[test]
    fn unresponsive_windows_are_diagnostic_only() {
        let samples = vec![process(10, None, "codex.exe", 0.0, 0)];
        let mut engine = Engine::new(FakeController::default());
        let statuses = engine.tick_with_unresponsive(
            &test_config(true),
            &samples,
            None,
            &HashSet::from([10]),
            60,
        );
        assert_eq!(statuses[0].state, ActivityState::Unresponsive);
    }

    #[test]
    fn focus_restores_after_a_partial_action_failure() {
        let restores = Arc::new(AtomicUsize::new(0));
        let mut engine = Engine::new(PartialFailureController {
            restores: restores.clone(),
        });
        let samples = vec![process(10, None, "codex.exe", 0.0, 0)];
        engine.tick(&test_config(false), &samples, None, 0);
        assert_eq!(
            engine.tick(&test_config(false), &samples, None, 10)[0].state,
            ActivityState::Inaccessible
        );
        engine.tick(&test_config(false), &samples, Some(10), 12);
        assert_eq!(restores.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn indexed_process_tree_includes_deep_descendants() {
        let samples = vec![
            process(10, None, "codex.exe", 0.0, 0),
            process(11, Some(10), "child.exe", 0.0, 0),
            process(12, Some(11), "grandchild.exe", 0.0, 0),
            process(13, Some(12), "leaf.exe", 0.0, 0),
            process(20, None, "unrelated.exe", 0.0, 0),
        ];
        let config = test_config(false);
        let groups = build_groups(&config, &samples, None);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].1.members.len(), 4);
        assert_eq!(groups[0].1.members[0].identity.pid, 10);
    }

    #[test]
    fn exclusions_prevent_a_rule_from_claiming_a_process() {
        let mut config = test_config(false);
        config.rules[0].exclusions = vec![RuleMatcher {
            path_contains: Some("\\bin\\codex.exe".into()),
            ..Default::default()
        }];
        let samples = vec![process(10, None, "codex.exe", 0.0, 0)];
        assert!(build_groups(&config, &samples, None).is_empty());
    }

    #[test]
    fn descendants_are_claimed_once_when_rules_overlap() {
        let mut config = test_config(false);
        config.rules.push(ProcessRule {
            id: "child-codex".into(),
            name: "Child Codex".into(),
            matcher: RuleMatcher {
                process_name: Some("codex.exe".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        let samples = vec![
            process(10, None, "codex.exe", 0.0, 0),
            process(11, Some(10), "codex.exe", 0.0, 0),
            process(12, Some(11), "pwsh.exe", 0.0, 0),
        ];
        let groups = build_groups(&config, &samples, None);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].1.members.len(), 3);
    }
}
