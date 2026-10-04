use crate::{
    config::{AppConfig, ProcessRule, RuleMatcher},
    model::{
        ActivityState, GroupMember, GroupStatus, ManagedActionKind, ProcessGroup, ProcessIdentity,
        ProcessSample,
    },
};
use regex::Regex;
use std::{
    collections::{HashMap, HashSet},
    fmt::Write as _,
};

const ACTION_RETRY_SECONDS: u64 = 30;

pub trait ResourceController {
    fn throttle(&mut self, processes: &[ProcessIdentity]) -> Result<(), String>;
    fn suspend(&mut self, processes: &[ProcessIdentity]) -> Result<(), String>;
    fn restore(&mut self, processes: &[ProcessIdentity]) -> Result<(), String>;
    fn restore_all(&mut self) -> Vec<String>;
    fn enable_elevation(&mut self) -> Result<(), String>;
    /// Flushes the working set of already-suspended processes. Best effort by design: it reclaims
    /// memory that the OS would page out anyway, so a failure is not worth failing the action over.
    fn trim_working_set(&mut self, processes: &[ProcessIdentity]) -> Result<(), String>;
}

/// Everything one tick needs from the outside world. A struct rather than more parameters, because
/// the list grew past the point where positional arguments were readable.
#[derive(Debug, Clone, Copy, Default)]
pub struct TickContext {
    pub foreground_pid: Option<u32>,
    pub now_seconds: u64,
    /// Local minutes from midnight, for rule schedules.
    pub minute_of_day: u16,
    /// 0 is Sunday.
    pub weekday: u8,
    /// A game or presentation is on screen. Suppresses every action, because a full-screen
    /// application looks exactly like an unfocused one.
    pub user_busy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GroupKey {
    rule_id: String,
    pid: u32,
    started_at: u64,
    started_at_ticks: u64,
}

#[derive(Debug, Clone)]
struct TrackedGroup {
    state: ActivityState,
    quiet_since: Option<u64>,
    last_io_bytes: u64,
    last_members: HashSet<ProcessIdentity>,
    identities: Vec<ProcessIdentity>,
    resources_modified: bool,
    restore_pending: bool,
    failed_action: Option<ManagedAction>,
    retry_after: Option<u64>,
    last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedAction {
    Throttle,
    Suspend,
}

impl TrackedGroup {
    fn new(group: &ProcessGroup) -> Self {
        Self {
            state: ActivityState::Active,
            quiet_since: None,
            last_io_bytes: group.io_bytes(),
            last_members: identity_set(group),
            identities: identities(group),
            resources_modified: false,
            restore_pending: false,
            failed_action: None,
            retry_after: None,
            last_error: None,
        }
    }
}

pub struct Engine<C> {
    controller: C,
    tracked: HashMap<GroupKey, TrackedGroup>,
    /// Groups the user excluded for this run. Keyed by identity, so a recycled pid is not held by
    /// mistake, and dropped with the tracked group when the process exits.
    held: HashSet<GroupKey>,
}

impl<C: ResourceController> Engine<C> {
    #[must_use]
    pub fn new(controller: C) -> Self {
        Self {
            controller,
            tracked: HashMap::new(),
            held: HashSet::new(),
        }
    }

    pub fn tick(
        &mut self,
        config: &AppConfig,
        processes: &[ProcessSample],
        foreground_pid: Option<u32>,
        now_seconds: u64,
    ) -> Vec<GroupStatus> {
        self.tick_with(
            config,
            processes,
            &HashSet::new(),
            TickContext {
                foreground_pid,
                now_seconds,
                ..TickContext::default()
            },
        )
    }

    pub fn tick_with_unresponsive(
        &mut self,
        config: &AppConfig,
        processes: &[ProcessSample],
        foreground_pid: Option<u32>,
        unresponsive_pids: &HashSet<u32>,
        now_seconds: u64,
    ) -> Vec<GroupStatus> {
        self.tick_with(
            config,
            processes,
            unresponsive_pids,
            TickContext {
                foreground_pid,
                now_seconds,
                ..TickContext::default()
            },
        )
    }

    #[allow(clippy::too_many_lines)]
    pub fn tick_with(
        &mut self,
        config: &AppConfig,
        processes: &[ProcessSample],
        unresponsive_pids: &HashSet<u32>,
        context: TickContext,
    ) -> Vec<GroupStatus> {
        let now_seconds = context.now_seconds;
        let groups = build_groups_at(config, processes, context);
        let mut present = HashSet::new();
        let mut statuses = Vec::with_capacity(groups.len());

        for (rule, group) in groups {
            let key = GroupKey {
                rule_id: rule.id.clone(),
                pid: group.root.pid,
                started_at: group.root.started_at,
                started_at_ticks: group.root.started_at_ticks,
            };
            present.insert(key.clone());
            let held = self.held.contains(&key);
            let tracked = self
                .tracked
                .entry(key)
                .or_insert_with(|| TrackedGroup::new(&group));
            let current_members = identity_set(&group);
            let membership_changed = tracked.last_members != current_members;
            let io_delta = group.io_bytes().saturating_sub(tracked.last_io_bytes);
            let controller_changed_membership = membership_changed && tracked.resources_modified;
            let quiet_sample = !group.focused
                && !membership_changed
                && group.cpu_percent() <= config.cpu_quiet_percent
                && io_delta <= config.io_quiet_bytes_per_sample;
            let current_identities = identities(&group);
            let unresponsive = group
                .members
                .iter()
                .any(|member| unresponsive_pids.contains(&member.identity.pid));

            if tracked.failed_action.is_some()
                && tracked
                    .retry_after
                    .is_some_and(|deadline| now_seconds >= deadline)
            {
                tracked.failed_action = None;
                tracked.retry_after = None;
            }

            let had_pending_restore = tracked.restore_pending;
            let pending_restore_failed = had_pending_restore
                && !restore_group(&mut self.controller, tracked, ActivityState::Active);
            let membership_restore_failed = !pending_restore_failed
                && controller_changed_membership
                && !restore_group(&mut self.controller, tracked, ActivityState::Active);

            if pending_restore_failed || membership_restore_failed || had_pending_restore {
                tracked.quiet_since = None;
            } else if unresponsive {
                if tracked.resources_modified {
                    let _ =
                        restore_group(&mut self.controller, tracked, ActivityState::Unresponsive);
                } else {
                    tracked.state = ActivityState::Unresponsive;
                    tracked.last_error = None;
                }
                tracked.quiet_since = None;
            // `build_groups_at` only returns enabled, in-schedule rules, and `quiet_sample` already
            // requires the group to be unfocused, so neither needs to be re-checked here. `user_busy`
            // is checked because a full-screen game leaves every other group looking idle, and
            // `held` because the user excluded this group by hand for the rest of the run.
            } else if !config.globally_enabled || context.user_busy || held || !quiet_sample {
                if tracked.resources_modified {
                    let _ = restore_group(&mut self.controller, tracked, ActivityState::Active);
                } else {
                    tracked.state = ActivityState::Active;
                    tracked.failed_action = None;
                    tracked.retry_after = None;
                    tracked.last_error = None;
                }
                tracked.quiet_since = None;
            } else {
                let quiet_since = *tracked.quiet_since.get_or_insert(now_seconds);
                let quiet_for = now_seconds.saturating_sub(quiet_since);
                if rule.allow_suspend && quiet_for >= rule.suspend_after_seconds {
                    if tracked.state != ActivityState::Suspended
                        && tracked.failed_action != Some(ManagedAction::Suspend)
                    {
                        let mut ready_to_suspend = tracked.state == ActivityState::Throttled;
                        if tracked.state != ActivityState::Throttled
                            && tracked.failed_action != Some(ManagedAction::Throttle)
                        {
                            tracked.identities.clone_from(&current_identities);
                            tracked.resources_modified = true;
                            match self.controller.throttle(&current_identities) {
                                Ok(()) => {
                                    tracked.state = ActivityState::Throttled;
                                    tracked.failed_action = None;
                                    tracked.retry_after = None;
                                    tracked.last_error = None;
                                    ready_to_suspend = true;
                                }
                                Err(error) => {
                                    record_action_failure(
                                        &mut self.controller,
                                        tracked,
                                        ManagedAction::Throttle,
                                        error,
                                        now_seconds,
                                    );
                                }
                            }
                        }
                        if ready_to_suspend {
                            tracked.identities.clone_from(&current_identities);
                            tracked.resources_modified = true;
                            match self.controller.suspend(&current_identities) {
                                Ok(()) => {
                                    tracked.state = ActivityState::Suspended;
                                    tracked.failed_action = None;
                                    tracked.retry_after = None;
                                    tracked.last_error = None;
                                    if rule.trim_working_set {
                                        // Deliberately not treated as a failure: the group is
                                        // already suspended, which is the state that matters.
                                        let _ =
                                            self.controller.trim_working_set(&current_identities);
                                    }
                                }
                                Err(error) => {
                                    record_action_failure(
                                        &mut self.controller,
                                        tracked,
                                        ManagedAction::Suspend,
                                        error,
                                        now_seconds,
                                    );
                                }
                            }
                        }
                    }
                } else if quiet_for >= rule.throttle_after_seconds {
                    // Suspension may have just been revoked — the user unticked "allow suspend",
                    // or edited `suspend_after_seconds` past the elapsed quiet time — while the
                    // group is still frozen. Wake it first: the `matches!` guard below skips
                    // suspended groups, so without this the application would stay frozen for
                    // good, since nothing else revisits an idle group the user may not touch.
                    let woke = tracked.state != ActivityState::Suspended
                        || restore_group(&mut self.controller, tracked, ActivityState::Active);
                    if woke
                        && !matches!(
                            tracked.state,
                            ActivityState::Throttled | ActivityState::Suspended
                        )
                        && tracked.failed_action.is_none()
                    {
                        tracked.identities.clone_from(&current_identities);
                        tracked.resources_modified = true;
                        match self.controller.throttle(&current_identities) {
                            Ok(()) => {
                                tracked.state = ActivityState::Throttled;
                                tracked.failed_action = None;
                                tracked.retry_after = None;
                                tracked.last_error = None;
                            }
                            Err(error) => {
                                record_action_failure(
                                    &mut self.controller,
                                    tracked,
                                    ManagedAction::Throttle,
                                    error,
                                    now_seconds,
                                );
                            }
                        }
                    }
                } else if tracked.failed_action.is_none() && !tracked.resources_modified {
                    // Only report Quiet while the process is untouched. Raising a rule's delay
                    // can drop `quiet_for` back below the threshold while the group is still
                    // throttled or suspended, and claiming Quiet there would misreport it.
                    tracked.state = ActivityState::Quiet;
                }
            }

            tracked.last_io_bytes = group.io_bytes();
            tracked.last_members = current_members;
            if !tracked.resources_modified {
                tracked.identities = current_identities;
            }
            let quiet_seconds = tracked
                .quiet_since
                .map_or(0, |since| now_seconds.saturating_sub(since));
            let detail = tracked.last_error.clone().unwrap_or_else(|| {
                if held {
                    "本次运行已手动排除".into()
                } else if group.focused {
                    "宿主位于前台".into()
                } else if context.user_busy {
                    "检测到全屏或演示，已暂缓".into()
                } else {
                    let mut detail = format!(
                        "CPU {:.1}% · 静默 {}",
                        group.cpu_percent(),
                        format_duration(quiet_seconds)
                    );
                    // The countdown is the thing a user actually wants to see while waiting.
                    if let Some((action, remaining)) =
                        next_action_for(rule, tracked.state, quiet_seconds)
                    {
                        let _ = write!(
                            detail,
                            " · {} 还需 {}",
                            action.label(),
                            format_duration(remaining)
                        );
                    }
                    detail
                }
            });
            let cpu_percent = group.cpu_percent();
            let memory_bytes = group.memory_bytes();
            let members = group_members(&group.members);
            // Nothing is pending for a group the user pulled out of management, so no countdown.
            let next_action = if held {
                None
            } else {
                next_action_for(rule, tracked.state, quiet_seconds)
            };
            statuses.push(GroupStatus {
                rule_id: rule.id.clone(),
                root: group.root,
                root_name: group.root_name,
                process_count: members.len(),
                state: tracked.state,
                quiet_seconds,
                cpu_percent,
                memory_bytes,
                detail,
                members,
                next_action,
            });
        }

        let stale = self
            .tracked
            .keys()
            .filter(|key| !present.contains(*key))
            .cloned()
            .collect::<Vec<_>>();
        for key in stale {
            let restored = self.tracked.get_mut(&key).is_none_or(|group| {
                !group.resources_modified
                    || restore_group(&mut self.controller, group, ActivityState::Active)
            });
            if restored {
                self.tracked.remove(&key);
                // A session exclusion lasts as long as the process it was applied to. Dropping it
                // here means a restarted application is managed again, which is what "for this
                // run" has to mean once the pid is gone.
                self.held.remove(&key);
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
        if errors.is_empty() {
            for group in self.tracked.values_mut() {
                group.state = ActivityState::Active;
                group.quiet_since = None;
                group.resources_modified = false;
                group.restore_pending = false;
                group.failed_action = None;
                group.retry_after = None;
                group.last_error = None;
            }
        } else {
            let error = errors.join("; ");
            for group in self
                .tracked
                .values_mut()
                .filter(|group| group.resources_modified)
            {
                group.state = ActivityState::Inaccessible;
                group.quiet_since = None;
                group.restore_pending = true;
                group.failed_action = None;
                group.retry_after = None;
                group.last_error = Some(error.clone());
            }
        }
        errors
    }

    /// Restores one group now, on an explicit request from the panel. The group stays tracked, so
    /// the normal quiet timer applies again from this moment: this is "wake it up", not "exclude it".
    pub fn restore_group(&mut self, rule_id: &str, pid: u32) -> Result<(), String> {
        let Some((key, group)) = self
            .tracked
            .iter_mut()
            .find(|(key, _)| key.rule_id == rule_id && key.pid == pid)
        else {
            // The root exited between the click and this call. Returning `Ok` here would report an
            // action that did not happen, to a user who then believes the app is out of management
            // or awake when the next sample may throttle it again.
            return Err(format!("PID {pid} 已退出"));
        };
        if !group.resources_modified {
            group.quiet_since = None;
            return Ok(());
        }
        let identities = group.identities.clone();
        let key = key.clone();
        match self.controller.restore(&identities) {
            Ok(()) => {
                let group = self.tracked.get_mut(&key).ok_or("进程组已不存在")?;
                group.state = ActivityState::Active;
                group.quiet_since = None;
                group.resources_modified = false;
                group.restore_pending = false;
                group.failed_action = None;
                group.retry_after = None;
                group.last_error = None;
                Ok(())
            }
            Err(error) => {
                if let Some(group) = self.tracked.get_mut(&key) {
                    group.state = ActivityState::Inaccessible;
                    group.restore_pending = true;
                    group.last_error = Some(error.clone());
                }
                Err(error)
            }
        }
    }

    /// Restores a group and holds it out of management until its root process exits. Survives only
    /// this run: an exclusion that should outlive a restart belongs in the rule.
    ///
    /// Returns whether the group was actually held. A group whose root exited between the click and
    /// this call cannot be excluded, and reporting success for that would tell the user an app is
    /// out of management when the next sample may throttle it again.
    pub fn exclude_group_for_session(&mut self, rule_id: &str, pid: u32) -> Result<(), String> {
        let result = self.restore_group(rule_id, pid);
        if let Some(key) = self
            .tracked
            .keys()
            .find(|key| key.rule_id == rule_id && key.pid == pid)
            .cloned()
        {
            self.held.insert(key);
        }
        result
    }

    /// Restores every group that contains `identity`, before something outside the engine changes
    /// that process. Errors are collected rather than returned early, so one inaccessible group
    /// cannot stop the others from being restored.
    pub fn restore_group_containing(&mut self, identity: &ProcessIdentity) -> Result<(), String> {
        let affected = self
            .tracked
            .iter()
            .filter(|(_, group)| group.resources_modified && group.identities.contains(identity))
            .map(|(key, _)| (key.rule_id.clone(), key.pid))
            .collect::<Vec<_>>();
        let errors = affected
            .into_iter()
            .filter_map(|(rule_id, pid)| self.restore_group(&rule_id, pid).err())
            .collect::<Vec<_>>();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("；"))
        }
    }

    /// Direct access for operations the engine deliberately does not perform itself, such as the
    /// explorer's manual termination.
    pub fn controller_mut(&mut self) -> &mut C {
        &mut self.controller
    }

    /// Whether a group is being held out of management for this run.
    #[must_use]
    pub fn is_held(&self, rule_id: &str, pid: u32) -> bool {
        self.held
            .iter()
            .any(|key| key.rule_id == rule_id && key.pid == pid)
    }

    pub fn enable_elevation(&mut self) -> Result<(), String> {
        self.controller.enable_elevation()?;
        for group in self.tracked.values_mut() {
            group.failed_action = None;
            group.retry_after = None;
        }
        Ok(())
    }
}

fn record_action_failure<C: ResourceController>(
    controller: &mut C,
    group: &mut TrackedGroup,
    action: ManagedAction,
    error: String,
    now_seconds: u64,
) {
    group.state = ActivityState::Inaccessible;
    group.failed_action = Some(action);
    group.retry_after = Some(now_seconds.saturating_add(ACTION_RETRY_SECONDS));
    match controller.restore(&group.identities) {
        Ok(()) => {
            group.resources_modified = false;
            group.restore_pending = false;
            group.last_error = Some(error);
        }
        Err(rollback_error) => {
            group.restore_pending = true;
            group.last_error = Some(format!("{error}；部分操作回滚失败：{rollback_error}"));
        }
    }
}

fn restore_group<C: ResourceController>(
    controller: &mut C,
    group: &mut TrackedGroup,
    restored_state: ActivityState,
) -> bool {
    if !group.resources_modified {
        group.state = restored_state;
        group.restore_pending = false;
        group.failed_action = None;
        group.retry_after = None;
        group.last_error = None;
        return true;
    }

    match controller.restore(&group.identities) {
        Ok(()) => {
            group.state = restored_state;
            group.resources_modified = false;
            group.restore_pending = false;
            group.failed_action = None;
            group.retry_after = None;
            group.last_error = None;
            true
        }
        Err(error) => {
            group.state = ActivityState::Inaccessible;
            group.restore_pending = true;
            group.failed_action = None;
            group.retry_after = None;
            group.last_error = Some(error);
            false
        }
    }
}

/// One process a draft rule would claim, for the editor's preview.
#[derive(Debug, Clone)]
pub struct PreviewMatch {
    pub pid: u32,
    pub name: String,
    pub executable_path: std::path::PathBuf,
    /// True for the process the matcher selected, false for a descendant pulled in by
    /// `include_descendants`.
    pub is_root: bool,
    /// Set when an exclusion matched, so the user can see why a process was skipped.
    pub excluded_by_rule: bool,
}

/// Evaluates a rule against the current sample without touching any process or any tracked state.
/// Answers "what would this match" while the user is still typing, instead of after a save.
///
/// Excluded processes are reported rather than dropped: seeing that a matcher hit something and an
/// exclusion then removed it is the whole point of a preview.
#[must_use]
pub fn preview_rule(rule: &ProcessRule, processes: &[ProcessSample]) -> Vec<PreviewMatch> {
    let by_pid = processes
        .iter()
        .map(|sample| (sample.identity.pid, sample))
        .collect::<HashMap<_, _>>();
    let mut regexes = HashMap::new();
    if let Some(pattern) = &rule.matcher.command_regex
        && let Ok(regex) = Regex::new(pattern)
    {
        regexes.insert(pattern.as_str(), regex);
    }
    for matcher in &rule.exclusions {
        if let Some(pattern) = &matcher.command_regex
            && let Ok(regex) = Regex::new(pattern)
        {
            regexes.insert(pattern.as_str(), regex);
        }
    }
    let mut children_by_parent = HashMap::<u32, Vec<u32>>::new();
    for process in processes {
        if let Some(parent) = valid_parent(process, &by_pid) {
            children_by_parent
                .entry(parent.identity.pid)
                .or_default()
                .push(process.identity.pid);
        }
    }

    let mut matches = Vec::new();
    let mut seen = HashSet::new();
    for root in processes {
        if !matches_rule(&rule.matcher, root, &by_pid, &regexes) {
            continue;
        }
        let excluded = rule
            .exclusions
            .iter()
            .any(|matcher| matches_rule(matcher, root, &by_pid, &regexes));
        if excluded {
            matches.push(PreviewMatch {
                pid: root.identity.pid,
                name: root.name.clone(),
                executable_path: root.identity.executable_path.clone(),
                is_root: true,
                excluded_by_rule: true,
            });
            continue;
        }
        if !seen.insert(root.identity.pid) {
            continue;
        }
        matches.push(PreviewMatch {
            pid: root.identity.pid,
            name: root.name.clone(),
            executable_path: root.identity.executable_path.clone(),
            is_root: true,
            excluded_by_rule: false,
        });
        if !rule.include_descendants {
            continue;
        }
        for member in collect_descendants(root, processes, &children_by_parent, &HashSet::new()) {
            if member.identity.pid == root.identity.pid || !seen.insert(member.identity.pid) {
                continue;
            }
            matches.push(PreviewMatch {
                pid: member.identity.pid,
                name: member.name.clone(),
                executable_path: member.identity.executable_path.clone(),
                is_root: false,
                excluded_by_rule: false,
            });
        }
    }
    matches
}

fn rule_in_schedule(rule: &ProcessRule, context: TickContext) -> bool {
    rule.schedule
        .is_none_or(|schedule| schedule.contains(context.minute_of_day, context.weekday))
}

/// How long until the group's next action, given how long it has already been quiet. Returns `None`
/// once no further action is pending, so a suspended group shows no countdown.
fn next_action_for(
    rule: &ProcessRule,
    state: ActivityState,
    quiet_seconds: u64,
) -> Option<(ManagedActionKind, u64)> {
    match state {
        ActivityState::Suspended | ActivityState::Inaccessible | ActivityState::Unresponsive => {
            None
        }
        ActivityState::Throttled => rule
            .allow_suspend
            .then(|| {
                (
                    ManagedActionKind::Suspend,
                    rule.suspend_after_seconds.saturating_sub(quiet_seconds),
                )
            })
            .filter(|(_, remaining)| *remaining > 0),
        ActivityState::Active | ActivityState::Quiet => {
            let remaining = rule.throttle_after_seconds.saturating_sub(quiet_seconds);
            (remaining > 0).then_some((ManagedActionKind::Throttle, remaining))
        }
    }
}

/// Orders members parents-first and records their depth so the panel can indent the tree. Depth is
/// derived from the already parent-ordered member list rather than recomputed from PIDs.
fn group_members(members: &[ProcessSample]) -> Vec<GroupMember> {
    let mut depths = HashMap::new();
    let mut rows = Vec::with_capacity(members.len());
    for member in members {
        let depth = member
            .parent_pid
            .and_then(|parent| depths.get(&parent).copied())
            .map_or(0, |parent_depth: usize| parent_depth + 1);
        depths.insert(member.identity.pid, depth);
        rows.push(GroupMember {
            pid: member.identity.pid,
            name: member.name.clone(),
            cpu_percent: member.cpu_percent,
            memory_bytes: member.memory_bytes,
            depth,
        });
    }
    rows
}

/// Compact durations for the status line: seconds below a minute, then minutes, then hours.
fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds} 秒")
    } else if seconds < 3_600 {
        format!("{} 分", seconds / 60)
    } else {
        format!("{} 小时 {} 分", seconds / 3_600, (seconds % 3_600) / 60)
    }
}

fn identities(group: &ProcessGroup) -> Vec<ProcessIdentity> {
    group
        .members
        .iter()
        .map(|sample| sample.identity.clone())
        .collect()
}

fn identity_set(group: &ProcessGroup) -> HashSet<ProcessIdentity> {
    group
        .members
        .iter()
        .map(|sample| sample.identity.clone())
        .collect()
}

#[cfg(test)]
fn build_groups<'a>(
    config: &'a AppConfig,
    processes: &[ProcessSample],
    foreground_pid: Option<u32>,
) -> Vec<(&'a ProcessRule, ProcessGroup)> {
    build_groups_at(
        config,
        processes,
        TickContext {
            foreground_pid,
            ..TickContext::default()
        },
    )
}

fn build_groups_at<'a>(
    config: &'a AppConfig,
    processes: &[ProcessSample],
    context: TickContext,
) -> Vec<(&'a ProcessRule, ProcessGroup)> {
    let foreground_pid = context.foreground_pid;
    let by_pid = processes
        .iter()
        .map(|sample| (sample.identity.pid, sample))
        .collect::<HashMap<_, _>>();
    let command_regexes = compile_command_regexes(config);
    let mut children_by_parent = HashMap::<u32, Vec<u32>>::new();
    for process in processes {
        if let Some(parent) = valid_parent(process, &by_pid) {
            children_by_parent
                .entry(parent.identity.pid)
                .or_default()
                .push(process.identity.pid);
        }
    }
    // A rule outside its schedule is treated exactly like a disabled one, so the existing
    // stale-group cleanup restores anything it was managing when the window closed.
    let mut rules = config
        .rules
        .iter()
        .filter(|rule| rule.enabled && rule_in_schedule(rule, context))
        .collect::<Vec<_>>();
    rules.sort_by_key(|rule| rule.built_in);
    let mut candidates = Vec::new();
    for (rule_priority, rule) in rules.into_iter().enumerate() {
        for root in processes {
            if !matches_rule(&rule.matcher, root, &by_pid, &command_regexes)
                || rule
                    .exclusions
                    .iter()
                    .any(|matcher| matches_rule(matcher, root, &by_pid, &command_regexes))
            {
                continue;
            }
            candidates.push((process_depth(root, &by_pid), rule_priority, rule, root));
        }
    }
    candidates.sort_by(|left, right| {
        left.1
            .cmp(&right.1)
            .then(left.0.cmp(&right.0))
            .then(left.3.identity.pid.cmp(&right.3.identity.pid))
            .then(left.3.identity.started_at.cmp(&right.3.identity.started_at))
    });

    let mut claimed = HashSet::new();
    let mut groups = Vec::new();

    for (_, _, rule, root) in candidates {
        if claimed.contains(&root.identity) {
            continue;
        }
        let members = if rule.include_descendants {
            collect_descendants(root, processes, &children_by_parent, &claimed)
        } else {
            vec![root.clone()]
        };
        claimed.extend(members.iter().map(|member| member.identity.clone()));
        let focused = foreground_pid.is_some_and(|pid| {
            members.iter().any(|member| member.identity.pid == pid)
                || has_ancestor_pid(root, pid, &by_pid)
        });
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
    groups
}

/// Collects the root and every unclaimed descendant, ordered so that a parent always precedes its
/// own children. Suspending the group in this order cannot let a not-yet-suspended parent spawn a
/// child that escapes the batch.
fn collect_descendants(
    root: &ProcessSample,
    processes: &[ProcessSample],
    children_by_parent: &HashMap<u32, Vec<u32>>,
    claimed: &HashSet<ProcessIdentity>,
) -> Vec<ProcessSample> {
    // Breadth-first from the root, recording each process's distance from it.
    let mut depths = HashMap::from([(root.identity.pid, 0_usize)]);
    let mut frontier = vec![root.identity.pid];
    let mut depth = 0_usize;
    while !frontier.is_empty() {
        depth += 1;
        let mut next = Vec::new();
        for parent in frontier {
            for &child in children_by_parent.get(&parent).into_iter().flatten() {
                if let std::collections::hash_map::Entry::Vacant(slot) = depths.entry(child) {
                    slot.insert(depth);
                    next.push(child);
                }
            }
        }
        frontier = next;
    }
    let mut group_identities = HashSet::new();
    let mut members = processes
        .iter()
        .filter(|process| {
            depths.contains_key(&process.identity.pid)
                && !claimed.contains(&process.identity)
                && group_identities.insert(process.identity.clone())
        })
        .cloned()
        .collect::<Vec<_>>();
    members.sort_by_key(|member| {
        (
            depths.get(&member.identity.pid).copied().unwrap_or(0),
            member.identity.pid,
            member.identity.started_at,
        )
    });
    members
}

fn compile_command_regexes(config: &AppConfig) -> HashMap<&str, Regex> {
    config
        .rules
        .iter()
        .flat_map(|rule| std::iter::once(&rule.matcher).chain(&rule.exclusions))
        .filter_map(|matcher| {
            let pattern = matcher.command_regex.as_deref()?;
            Regex::new(pattern).ok().map(|regex| (pattern, regex))
        })
        .collect()
}

fn process_depth(process: &ProcessSample, by_pid: &HashMap<u32, &ProcessSample>) -> usize {
    let mut depth = 0;
    let mut current = process;
    let mut visited = HashSet::from([process.identity.pid]);
    while let Some(parent) = valid_parent(current, by_pid) {
        if !visited.insert(parent.identity.pid) {
            break;
        }
        depth += 1;
        current = parent;
    }
    depth
}

fn valid_parent<'a>(
    process: &ProcessSample,
    by_pid: &HashMap<u32, &'a ProcessSample>,
) -> Option<&'a ProcessSample> {
    let parent = by_pid.get(&process.parent_pid?)?;
    let valid_creation_order =
        if parent.identity.started_at_ticks != 0 && process.identity.started_at_ticks != 0 {
            parent.identity.started_at_ticks <= process.identity.started_at_ticks
        } else {
            parent.identity.started_at <= process.identity.started_at
        };
    valid_creation_order.then_some(*parent)
}

fn has_ancestor_pid(
    process: &ProcessSample,
    ancestor_pid: u32,
    by_pid: &HashMap<u32, &ProcessSample>,
) -> bool {
    let mut current = process;
    let mut visited = HashSet::from([process.identity.pid]);
    while let Some(parent) = valid_parent(current, by_pid) {
        if parent.identity.pid == ancestor_pid {
            return true;
        }
        if !visited.insert(parent.identity.pid) {
            break;
        }
        current = parent;
    }
    false
}

fn matches_rule(
    matcher: &RuleMatcher,
    process: &ProcessSample,
    by_pid: &HashMap<u32, &ProcessSample>,
    command_regexes: &HashMap<&str, Regex>,
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
        && command_regexes
            .get(pattern.as_str())
            .is_none_or(|regex| !regex.is_match(&process.command_line))
    {
        return false;
    }
    if let Some(ancestor_name) = &matcher.ancestor_process_name {
        let mut current = process;
        let mut found = false;
        let mut visited = HashSet::from([process.identity.pid]);
        while let Some(parent) = valid_parent(current, by_pid) {
            if !visited.insert(parent.identity.pid) {
                break;
            }
            if parent.name.eq_ignore_ascii_case(ancestor_name) {
                found = true;
                break;
            }
            current = parent;
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

/// Case-insensitive substring test.
///
/// This runs for every matcher against every process on every tick, so the common all-ASCII case
/// (command lines and most paths) uses a sliding comparison that allocates nothing. `to_lowercase`
/// would build two fresh `String`s per call, which adds up over a few hundred processes. The
/// Unicode-correct path is kept as a fallback so behaviour is unchanged for non-ASCII input.
fn contains_case_insensitive(value: &str, fragment: &str) -> bool {
    if fragment.is_empty() {
        return true;
    }
    let fragment_bytes = fragment.as_bytes();
    let value_bytes = value.as_bytes();
    if value.is_ascii() && fragment.is_ascii() {
        if fragment_bytes.len() > value_bytes.len() {
            return false;
        }
        return value_bytes
            .windows(fragment_bytes.len())
            .any(|window| window.eq_ignore_ascii_case(fragment_bytes));
    }
    value.to_lowercase().contains(&fragment.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProcessRule, RuleMatcher, RuleSchedule};
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
        trims: usize,
    }

    #[test]
    fn case_insensitive_contains_matches_the_allocating_version() {
        // The ASCII fast path and the Unicode fallback must agree on every case a matcher sees.
        assert!(contains_case_insensitive("C:\\App\\Code.exe", "code.exe"));
        assert!(contains_case_insensitive("--SERVE", "--serve"));
        assert!(!contains_case_insensitive("code", "code.exe"));
        assert!(!contains_case_insensitive("", "code"));
        // An empty fragment is contained in everything, including an empty value.
        assert!(contains_case_insensitive("anything", ""));
        assert!(contains_case_insensitive("", ""));
        // Non-ASCII input falls back to `to_lowercase`, which folds these the same way.
        assert!(contains_case_insensitive("记事本", "记事本"));
        assert!(contains_case_insensitive("ÄPFEL", "äpfel"));
        assert!(!contains_case_insensitive("记事本", "浏览器"));
        // A multi-byte fragment must not be matched by slicing through it.
        assert!(!contains_case_insensitive("abc", "记事"));
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
        fn trim_working_set(&mut self, _: &[ProcessIdentity]) -> Result<(), String> {
            self.trims += 1;
            Ok(())
        }
        fn enable_elevation(&mut self) -> Result<(), String> {
            Ok(())
        }
    }

    struct PartialFailureController {
        restores: Arc<AtomicUsize>,
        throttles: Arc<AtomicUsize>,
        suspends: Arc<AtomicUsize>,
    }

    impl ResourceController for PartialFailureController {
        fn throttle(&mut self, _: &[ProcessIdentity]) -> Result<(), String> {
            self.throttles.fetch_add(1, Ordering::Relaxed);
            Err("partial access failure".into())
        }
        fn suspend(&mut self, _: &[ProcessIdentity]) -> Result<(), String> {
            self.suspends.fetch_add(1, Ordering::Relaxed);
            Err("partial access failure".into())
        }
        fn restore(&mut self, _: &[ProcessIdentity]) -> Result<(), String> {
            self.restores.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn restore_all(&mut self) -> Vec<String> {
            Vec::new()
        }
        fn trim_working_set(&mut self, _: &[ProcessIdentity]) -> Result<(), String> {
            Err("partial access failure".into())
        }
        fn enable_elevation(&mut self) -> Result<(), String> {
            Ok(())
        }
    }

    struct RestoreFailureController {
        restores: Arc<AtomicUsize>,
        failures_remaining: Arc<AtomicUsize>,
        fail_restore_all: bool,
    }

    impl ResourceController for RestoreFailureController {
        fn throttle(&mut self, _: &[ProcessIdentity]) -> Result<(), String> {
            Ok(())
        }
        fn suspend(&mut self, _: &[ProcessIdentity]) -> Result<(), String> {
            Ok(())
        }
        fn restore(&mut self, _: &[ProcessIdentity]) -> Result<(), String> {
            self.restores.fetch_add(1, Ordering::Relaxed);
            if self.failures_remaining.load(Ordering::Relaxed) > 0 {
                self.failures_remaining.fetch_sub(1, Ordering::Relaxed);
                Err("restore failed".into())
            } else {
                Ok(())
            }
        }
        fn restore_all(&mut self) -> Vec<String> {
            if self.fail_restore_all {
                vec!["restore all failed".into()]
            } else {
                Vec::new()
            }
        }
        fn trim_working_set(&mut self, _: &[ProcessIdentity]) -> Result<(), String> {
            Ok(())
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
                started_at_ticks: u64::from(pid),
                executable_path: PathBuf::from(format!(r"C:\bin\{name}")),
            },
            parent_pid: parent,
            name: name.into(),
            command_line: name.into(),
            cpu_percent: cpu,
            io_bytes: io,
            memory_bytes: 64 * 1024 * 1024,
            virtual_memory_bytes: 128 * 1024 * 1024,
            run_time_seconds: 60,
            thread_count: 8,
            os_suspended: false,
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
    fn foreground_ancestor_focuses_and_restores_a_group() {
        let mut engine = Engine::new(FakeController::default());
        let samples = vec![
            process(1, None, "WindowsTerminal.exe", 0.0, 100),
            process(2, Some(1), "pwsh.exe", 0.0, 100),
            process(10, Some(2), "codex.exe", 0.0, 100),
        ];
        engine.tick(&test_config(false), &samples, None, 0);
        assert_eq!(
            engine.tick(&test_config(false), &samples, None, 6)[0].state,
            ActivityState::Throttled
        );

        let statuses = engine.tick(&test_config(false), &samples, Some(1), 8);
        assert_eq!(statuses[0].state, ActivityState::Active);
        assert_eq!(engine.controller.restores, 1);
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
    fn turning_off_allow_suspend_wakes_an_already_suspended_group() {
        let samples = vec![process(10, None, "codex.exe", 0.0, 0)];
        let mut engine = Engine::new(FakeController::default());
        engine.tick(&test_config(true), &samples, None, 0);
        assert_eq!(
            engine.tick(&test_config(true), &samples, None, 30)[0].state,
            ActivityState::Suspended
        );

        // The user unchecks "allow suspend" while the group is idle and frozen.
        let statuses = engine.tick(&test_config(false), &samples, None, 31);
        assert_eq!(
            statuses[0].state,
            ActivityState::Throttled,
            "a group must not stay suspended after suspension is no longer permitted"
        );
        assert_eq!(engine.controller.restores, 1);
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
        let throttles = Arc::new(AtomicUsize::new(0));
        let mut engine = Engine::new(PartialFailureController {
            restores: restores.clone(),
            throttles,
            suspends: Arc::new(AtomicUsize::new(0)),
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
    fn a_partial_action_failure_is_rolled_back_immediately() {
        let restores = Arc::new(AtomicUsize::new(0));
        let throttles = Arc::new(AtomicUsize::new(0));
        let mut engine = Engine::new(PartialFailureController {
            restores: restores.clone(),
            throttles,
            suspends: Arc::new(AtomicUsize::new(0)),
        });
        let samples = vec![process(10, None, "codex.exe", 0.0, 0)];

        engine.tick(&test_config(false), &samples, None, 0);
        let status = engine.tick(&test_config(false), &samples, None, 10);

        assert_eq!(status[0].state, ActivityState::Inaccessible);
        assert_eq!(restores.load(Ordering::Relaxed), 1);
        assert!(!engine.tracked.values().next().unwrap().resources_modified);
    }

    #[test]
    fn a_failed_action_is_not_repeated_every_tick() {
        let restores = Arc::new(AtomicUsize::new(0));
        let throttles = Arc::new(AtomicUsize::new(0));
        let mut engine = Engine::new(PartialFailureController {
            restores,
            throttles: throttles.clone(),
            suspends: Arc::new(AtomicUsize::new(0)),
        });
        let samples = vec![process(10, None, "codex.exe", 0.0, 0)];

        engine.tick(&test_config(false), &samples, None, 0);
        assert_eq!(
            engine.tick(&test_config(false), &samples, None, 10)[0].state,
            ActivityState::Inaccessible
        );
        assert_eq!(
            engine.tick(&test_config(false), &samples, None, 12)[0].state,
            ActivityState::Inaccessible
        );
        assert_eq!(throttles.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_failed_throttle_does_not_continue_to_suspend() {
        let throttles = Arc::new(AtomicUsize::new(0));
        let suspends = Arc::new(AtomicUsize::new(0));
        let mut engine = Engine::new(PartialFailureController {
            restores: Arc::new(AtomicUsize::new(0)),
            throttles: throttles.clone(),
            suspends: suspends.clone(),
        });
        let samples = vec![process(10, None, "codex.exe", 0.0, 0)];

        engine.tick(&test_config(true), &samples, None, 0);
        let statuses = engine.tick(&test_config(true), &samples, None, 30);

        assert_eq!(statuses[0].state, ActivityState::Inaccessible);
        assert_eq!(throttles.load(Ordering::Relaxed), 1);
        assert_eq!(suspends.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_failed_action_retries_after_a_bounded_delay() {
        let throttles = Arc::new(AtomicUsize::new(0));
        let mut engine = Engine::new(PartialFailureController {
            restores: Arc::new(AtomicUsize::new(0)),
            throttles: throttles.clone(),
            suspends: Arc::new(AtomicUsize::new(0)),
        });
        let samples = vec![process(10, None, "codex.exe", 0.0, 0)];

        engine.tick(&test_config(false), &samples, None, 0);
        engine.tick(&test_config(false), &samples, None, 10);
        engine.tick(&test_config(false), &samples, None, 39);
        assert_eq!(throttles.load(Ordering::Relaxed), 1);

        engine.tick(&test_config(false), &samples, None, 40);
        assert_eq!(throttles.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_failed_restore_stays_pending_and_retries_on_the_next_tick() {
        let restores = Arc::new(AtomicUsize::new(0));
        let failures_remaining = Arc::new(AtomicUsize::new(1));
        let mut engine = Engine::new(RestoreFailureController {
            restores: restores.clone(),
            failures_remaining,
            fail_restore_all: false,
        });
        let samples = vec![process(10, None, "codex.exe", 0.0, 0)];
        let config = test_config(false);
        engine.tick(&config, &samples, None, 0);
        engine.tick(&config, &samples, None, 6);

        let failed = engine.tick(&config, &samples, Some(10), 8);
        assert_eq!(failed[0].state, ActivityState::Inaccessible);
        assert!(failed[0].detail.contains("restore failed"));
        let resumed = engine.tick(&config, &samples, Some(10), 10);
        assert_eq!(resumed[0].state, ActivityState::Active);
        assert_eq!(restores.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_stale_group_is_removed_only_after_restore_succeeds() {
        let restores = Arc::new(AtomicUsize::new(0));
        let failures_remaining = Arc::new(AtomicUsize::new(1));
        let mut engine = Engine::new(RestoreFailureController {
            restores: restores.clone(),
            failures_remaining,
            fail_restore_all: false,
        });
        let samples = vec![process(10, None, "codex.exe", 0.0, 0)];
        let config = test_config(false);
        engine.tick(&config, &samples, None, 0);
        engine.tick(&config, &samples, None, 6);

        engine.tick(&config, &[], None, 8);
        assert_eq!(engine.tracked.len(), 1);
        engine.tick(&config, &[], None, 10);
        assert!(engine.tracked.is_empty());
        assert_eq!(restores.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn restore_all_failure_keeps_groups_pending() {
        let restores = Arc::new(AtomicUsize::new(0));
        let mut engine = Engine::new(RestoreFailureController {
            restores: restores.clone(),
            failures_remaining: Arc::new(AtomicUsize::new(0)),
            fail_restore_all: true,
        });
        let samples = vec![process(10, None, "codex.exe", 0.0, 0)];
        let config = test_config(false);
        engine.tick(&config, &samples, None, 0);
        engine.tick(&config, &samples, None, 6);

        assert_eq!(engine.restore_all(), vec!["restore all failed"]);
        let tracked = engine.tracked.values().next().unwrap();
        assert_eq!(tracked.state, ActivityState::Inaccessible);
        assert!(tracked.restore_pending);

        assert_eq!(
            engine.tick(&config, &samples, Some(10), 8)[0].state,
            ActivityState::Active
        );
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
            process(12, Some(11), "pwsh.exe", 0.0, 0),
            process(11, Some(10), "codex.exe", 0.0, 0),
            process(10, None, "codex.exe", 0.0, 0),
        ];
        let groups = build_groups(&config, &samples, None);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].1.root.pid, 10);
        assert_eq!(groups[0].1.members.len(), 3);
        let identities = groups
            .iter()
            .flat_map(|(_, group)| group.members.iter().map(|member| &member.identity))
            .collect::<HashSet<_>>();
        assert_eq!(identities.len(), 3);
    }

    #[test]
    fn reused_child_pid_resets_the_quiet_timer() {
        let config = test_config(false);
        let mut engine = Engine::new(FakeController::default());
        let initial = vec![
            process(10, None, "codex.exe", 0.0, 0),
            process(11, Some(10), "child.exe", 0.0, 0),
        ];
        engine.tick(&config, &initial, None, 0);

        let mut replacement = initial;
        replacement[1].identity.started_at = 100;
        replacement[1].identity.started_at_ticks = 100;
        let statuses = engine.tick(&config, &replacement, None, 10);

        assert_eq!(statuses[0].state, ActivityState::Active);
        assert_eq!(statuses[0].quiet_seconds, 0);
    }

    #[test]
    fn changed_membership_restores_the_original_control_set_first() {
        let config = test_config(false);
        let mut engine = Engine::new(FakeController::default());
        let initial = vec![
            process(10, None, "codex.exe", 0.0, 0),
            process(11, Some(10), "child.exe", 0.0, 0),
        ];
        engine.tick(&config, &initial, None, 0);
        engine.tick(&config, &initial, None, 10);
        assert_eq!(engine.controller.throttles, 1);

        let changed = vec![process(10, None, "codex.exe", 0.0, 0)];
        let statuses = engine.tick(&config, &changed, None, 12);

        assert_eq!(engine.controller.restores, 1);
        assert_eq!(statuses[0].state, ActivityState::Active);
        assert_eq!(statuses[0].quiet_seconds, 0);
    }

    #[test]
    fn a_newer_parent_pid_is_not_treated_as_an_ancestor() {
        let config = test_config(false);
        let mut parent = process(1, None, "host.exe", 0.0, 0);
        parent.identity.started_at = 20;
        parent.identity.started_at_ticks = 20;
        let mut child = process(10, Some(1), "codex.exe", 0.0, 0);
        child.identity.started_at = 10;
        child.identity.started_at_ticks = 10;
        let groups = build_groups(&config, &[parent, child], Some(1));

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].1.members.len(), 1);
        assert!(!groups[0].1.focused);
    }

    #[test]
    fn raising_the_delay_does_not_report_a_throttled_group_as_quiet() {
        let mut engine = Engine::new(FakeController::default());
        let samples = vec![process(10, None, "codex.exe", 0.0, 0)];
        let mut config = test_config(false);
        config.rules[0].throttle_after_seconds = 5;
        engine.tick(&config, &samples, None, 0);
        assert_eq!(
            engine.tick(&config, &samples, None, 10)[0].state,
            ActivityState::Throttled
        );

        // The rule's delay is raised past the elapsed quiet time. The group is still throttled,
        // so it must keep saying so rather than falling back to Quiet.
        config.rules[0].throttle_after_seconds = 600;
        config.rules[0].suspend_after_seconds = 1_200;
        let statuses = engine.tick(&config, &samples, None, 12);

        assert_eq!(statuses[0].state, ActivityState::Throttled);
        assert_eq!(engine.controller.restores, 0);
    }

    #[test]
    fn group_members_are_ordered_parents_before_children() {
        let config = test_config(false);
        // PIDs deliberately run opposite to tree depth: the grandchild has the lowest PID. Start
        // times still increase downward, since `valid_parent` requires a parent to predate it.
        let started = |mut sample: ProcessSample, at: u64| {
            sample.identity.started_at = at;
            sample.identity.started_at_ticks = at;
            sample
        };
        let samples = vec![
            started(process(10, Some(11), "grandchild.exe", 0.0, 0), 40),
            started(process(11, Some(12), "child.exe", 0.0, 0), 20),
            started(process(12, None, "codex.exe", 0.0, 0), 10),
            started(process(13, Some(12), "sibling.exe", 0.0, 0), 30),
        ];
        let groups = build_groups(&config, &samples, None);

        let order = groups[0]
            .1
            .members
            .iter()
            .map(|member| member.identity.pid)
            .collect::<Vec<_>>();
        // Root, then both depth-1 children by PID, then the depth-2 grandchild.
        assert_eq!(order, vec![12, 11, 13, 10]);
        // Every member's parent, when part of the group, appears before it.
        for (index, member) in groups[0].1.members.iter().enumerate() {
            if let Some(parent) = member.parent_pid
                && order.contains(&parent)
            {
                let parent_index = order.iter().position(|pid| *pid == parent).unwrap();
                assert!(
                    parent_index < index,
                    "parent {parent} must precede its child"
                );
            }
        }
    }

    #[test]
    fn custom_child_rule_takes_priority_over_a_builtin_parent_rule() {
        let mut config = test_config(false);
        config.rules = vec![
            ProcessRule {
                id: "builtin-parent".into(),
                name: "Built-in parent".into(),
                built_in: true,
                allow_suspend: true,
                matcher: RuleMatcher {
                    process_name: Some("host.exe".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
            ProcessRule {
                id: "custom-child".into(),
                name: "Custom child".into(),
                built_in: false,
                allow_suspend: false,
                matcher: RuleMatcher {
                    process_name: Some("codex.exe".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        ];
        let samples = vec![
            process(1, None, "host.exe", 0.0, 0),
            process(10, Some(1), "codex.exe", 0.0, 0),
        ];
        let groups = build_groups(&config, &samples, None);

        let child = groups
            .iter()
            .find(|(rule, _)| rule.id == "custom-child")
            .expect("custom child rule should retain its process");
        assert_eq!(child.1.root.pid, 10);
        assert_eq!(child.1.members.len(), 1);
    }

    #[test]
    fn a_schedule_window_that_wraps_midnight_covers_the_night() {
        let night = RuleSchedule {
            start_minute: 22 * 60,
            end_minute: 6 * 60,
            days: 0,
        };
        assert!(night.contains(23 * 60, 3));
        assert!(night.contains(2 * 60, 3));
        assert!(!night.contains(12 * 60, 3));
        // The exclusive end must not be inside the window.
        assert!(!night.contains(6 * 60, 3));
        assert!(night.contains(22 * 60, 3));
    }

    #[test]
    fn an_empty_schedule_window_does_not_disable_a_rule() {
        let day_only = RuleSchedule {
            start_minute: 0,
            end_minute: 0,
            // Monday to Friday: bit 0 is Sunday, bit 6 is Saturday.
            days: 0b0011_1110,
        };
        assert!(day_only.contains(0, 1));
        assert!(day_only.contains(13 * 60, 5));
        assert!(!day_only.contains(13 * 60, 0));
        assert!(!day_only.contains(13 * 60, 6));
    }

    #[test]
    fn an_out_of_schedule_rule_is_restored_and_then_ignored() {
        let mut config = test_config(false);
        let samples = vec![process(10, None, "codex.exe", 0.0, 100)];
        let mut engine = Engine::new(FakeController::default());
        engine.tick(&config, &samples, None, 0);
        let statuses = engine.tick(&config, &samples, None, 6);
        assert_eq!(statuses[0].state, ActivityState::Throttled);

        // 09:00 on a Wednesday, with the rule restricted to the night.
        config.rules[0].schedule = Some(RuleSchedule {
            start_minute: 22 * 60,
            end_minute: 6 * 60,
            days: 0,
        });
        let context = TickContext {
            now_seconds: 12,
            minute_of_day: 9 * 60,
            weekday: 3,
            ..Default::default()
        };
        let statuses = engine.tick_with(&config, &samples, &HashSet::new(), context);
        assert!(
            statuses.is_empty(),
            "a rule outside its window should not report a group"
        );
        assert_eq!(
            engine.controller.restores, 1,
            "leaving the window must restore what the rule was managing"
        );
    }

    /// End-to-end counterpart of the `RuleSchedule` wrap test: the engine must keep a Monday-night
    /// rule active in the small hours of Tuesday, not just in the `contains` unit test.
    #[test]
    fn a_rule_restricted_to_monday_night_still_applies_on_tuesday_morning() {
        let mut config = test_config(false);
        config.rules[0].schedule = Some(RuleSchedule {
            start_minute: 22 * 60,
            end_minute: 6 * 60,
            // Monday only: bit 1, since bit 0 is Sunday.
            days: 0b0000_0010,
        });
        let samples = vec![process(10, None, "codex.exe", 0.0, 100)];

        // 23:00 on Monday: inside the window, so the group is throttled.
        let mut engine = Engine::new(FakeController::default());
        let monday_evening = TickContext {
            now_seconds: 0,
            minute_of_day: 23 * 60,
            weekday: 1,
            ..Default::default()
        };
        engine.tick_with(&config, &samples, &HashSet::new(), monday_evening);
        let tuesday = TickContext {
            now_seconds: 6,
            minute_of_day: 2 * 60,
            weekday: 2,
            ..Default::default()
        };
        let statuses = engine.tick_with(&config, &samples, &HashSet::new(), tuesday);
        assert_eq!(
            statuses[0].state,
            ActivityState::Throttled,
            "Tuesday 02:00 is still Monday night"
        );
        assert_eq!(engine.controller.restores, 0);

        // 23:00 on Tuesday is a different night and must not be covered. Throttle first, while
        // still inside Monday night, so there is something for leaving the window to restore.
        let mut engine = Engine::new(FakeController::default());
        engine.tick_with(&config, &samples, &HashSet::new(), monday_evening);
        let later_monday = TickContext {
            now_seconds: 6,
            minute_of_day: 23 * 60 + 30,
            weekday: 1,
            ..Default::default()
        };
        let statuses = engine.tick_with(&config, &samples, &HashSet::new(), later_monday);
        assert_eq!(statuses[0].state, ActivityState::Throttled);
        let tuesday_evening = TickContext {
            now_seconds: 12,
            minute_of_day: 23 * 60,
            weekday: 2,
            ..Default::default()
        };
        let statuses = engine.tick_with(&config, &samples, &HashSet::new(), tuesday_evening);
        assert!(
            statuses.is_empty(),
            "Tuesday evening is not part of Monday night"
        );
        assert_eq!(
            engine.controller.restores, 1,
            "leaving the window must restore what the rule was managing"
        );
    }

    #[test]
    fn a_busy_user_holds_off_every_action() {
        let config = test_config(false);
        let samples = vec![process(10, None, "codex.exe", 0.0, 100)];
        let mut engine = Engine::new(FakeController::default());
        let busy = |now: u64| TickContext {
            now_seconds: now,
            user_busy: true,
            ..Default::default()
        };
        engine.tick_with(&config, &samples, &HashSet::new(), busy(0));
        let statuses = engine.tick_with(&config, &samples, &HashSet::new(), busy(600));
        assert_eq!(statuses[0].state, ActivityState::Active);
        assert_eq!(engine.controller.throttles, 0);

        // Once the game closes the quiet timer starts from that moment, not from when the group
        // first looked idle: time spent behind a full-screen application does not count.
        let statuses = engine.tick(&config, &samples, None, 1200);
        assert_eq!(statuses[0].state, ActivityState::Quiet);
        let statuses = engine.tick(&config, &samples, None, 1206);
        assert_eq!(statuses[0].state, ActivityState::Throttled);
    }

    #[test]
    fn suspending_trims_the_working_set_only_when_the_rule_asks() {
        let mut config = test_config(true);
        let samples = vec![process(10, None, "codex.exe", 0.0, 100)];
        let mut engine = Engine::new(FakeController::default());
        engine.tick(&config, &samples, None, 0);
        engine.tick(&config, &samples, None, 30);
        assert_eq!(engine.controller.suspends, 1);
        assert_eq!(engine.controller.trims, 0);

        config.rules[0].trim_working_set = true;
        let mut engine = Engine::new(FakeController::default());
        engine.tick(&config, &samples, None, 0);
        engine.tick(&config, &samples, None, 30);
        assert_eq!(engine.controller.suspends, 1);
        assert_eq!(engine.controller.trims, 1);
    }

    #[test]
    fn the_countdown_targets_the_action_that_is_actually_next() {
        let rule = &test_config(true).rules[0];
        assert_eq!(
            next_action_for(rule, ActivityState::Quiet, 2),
            Some((ManagedActionKind::Throttle, 3))
        );
        assert_eq!(
            next_action_for(rule, ActivityState::Throttled, 5),
            Some((ManagedActionKind::Suspend, 15))
        );
        assert_eq!(next_action_for(rule, ActivityState::Suspended, 30), None);
        // A throttled group under a rule that may not suspend has nothing left to wait for.
        let no_suspend = &test_config(false).rules[0];
        assert_eq!(
            next_action_for(no_suspend, ActivityState::Throttled, 5),
            None
        );
    }

    #[test]
    fn a_preview_reports_matches_and_exclusions_without_touching_anything() {
        let mut rule = ProcessRule {
            id: "preview".into(),
            name: "Preview".into(),
            matcher: RuleMatcher {
                process_name: Some("codex.exe".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let samples = vec![
            process(10, None, "codex.exe", 0.0, 0),
            process(11, Some(10), "node.exe", 0.0, 0),
            process(12, None, "unrelated.exe", 0.0, 0),
        ];

        let matches = preview_rule(&rule, &samples);
        let pids = matches.iter().map(|entry| entry.pid).collect::<Vec<_>>();
        assert_eq!(pids, vec![10, 11]);
        assert!(matches[0].is_root);
        assert!(!matches[1].is_root);
        assert!(matches.iter().all(|entry| !entry.excluded_by_rule));

        rule.exclusions.push(RuleMatcher {
            process_name: Some("codex.exe".into()),
            ..Default::default()
        });
        let matches = preview_rule(&rule, &samples);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].excluded_by_rule);
    }

    #[test]
    fn a_session_exclusion_restores_the_group_and_lasts_until_it_exits() {
        let config = test_config(false);
        let samples = vec![process(10, None, "codex.exe", 0.0, 100)];
        let mut engine = Engine::new(FakeController::default());
        engine.tick(&config, &samples, None, 0);
        assert_eq!(
            engine.tick(&config, &samples, None, 6)[0].state,
            ActivityState::Throttled
        );

        engine.exclude_group_for_session("codex", 10).unwrap();
        assert!(engine.is_held("codex", 10));
        assert_eq!(engine.controller.restores, 1);

        // Held groups keep reporting, but never get throttled again.
        let statuses = engine.tick(&config, &samples, None, 600);
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, ActivityState::Active);
        assert!(statuses[0].next_action.is_none());
        assert_eq!(engine.controller.throttles, 1);

        // The exclusion dies with the process, so a restart is managed normally.
        engine.tick(&config, &[], None, 610);
        assert!(!engine.is_held("codex", 10));
    }

    #[test]
    fn acting_on_a_group_whose_process_already_exited_reports_failure() {
        // The click and the worker command are separated in time, so the root can be gone by the
        // time the action runs. Reporting success there would tell the user an app is awake or out
        // of management when nothing happened.
        let mut engine = Engine::new(FakeController::default());
        assert!(engine.restore_group("codex", 10).is_err());
        assert!(engine.exclude_group_for_session("codex", 10).is_err());
        assert!(!engine.is_held("codex", 10));
    }

    #[test]
    fn restoring_one_group_leaves_it_managed() {
        let config = test_config(false);
        let samples = vec![process(10, None, "codex.exe", 0.0, 100)];
        let mut engine = Engine::new(FakeController::default());
        engine.tick(&config, &samples, None, 0);
        engine.tick(&config, &samples, None, 6);

        engine.restore_group("codex", 10).unwrap();
        assert!(!engine.is_held("codex", 10));
        assert_eq!(engine.controller.restores, 1);

        // The quiet timer restarts from the restore, so the delay has to elapse again.
        let statuses = engine.tick(&config, &samples, None, 10);
        assert_eq!(statuses[0].state, ActivityState::Quiet);
        let statuses = engine.tick(&config, &samples, None, 16);
        assert_eq!(statuses[0].state, ActivityState::Throttled);
        assert_eq!(engine.controller.throttles, 2);
    }

    #[test]
    fn durations_read_in_the_largest_useful_unit() {
        assert_eq!(format_duration(0), "0 秒");
        assert_eq!(format_duration(45), "45 秒");
        assert_eq!(format_duration(60), "1 分");
        assert_eq!(format_duration(90), "1 分");
        assert_eq!(format_duration(3600), "1 小时 0 分");
        assert_eq!(format_duration(3600 + 25 * 60), "1 小时 25 分");
    }
}
