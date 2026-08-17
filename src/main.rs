#![windows_subsystem = "windows"]

slint::include_modules!();

use lazy_process::{
    config::{AppConfig, ProcessRule, RuleMatcher, config_path, journal_path},
    engine::Engine,
    model::{ActivityState, GroupStatus, ProcessSample},
    platform::{
        ProcessSampler, WindowsResourceController, foreground_process_id, recover_suspended,
        run_elevated_helper, run_watchdog, spawn_watchdog,
    },
};
use slint::{CloseRequestResponse, Color, ComponentHandle, ModelRc, VecModel, Weak};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt::Write as _,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE},
        System::Threading::CreateMutexW,
        UI::{
            Input::KeyboardAndMouse::{
                MOD_ALT, MOD_CONTROL, MOD_NOREPEAT, MOD_SHIFT, RegisterHotKey, UnregisterHotKey,
                VK_F12,
            },
            WindowsAndMessaging::{GetMessageW, MSG, WM_HOTKEY},
        },
    },
    core::{HSTRING, PCWSTR},
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const HOTKEY_ID: i32 = 0x4c50;

#[derive(Clone)]
struct RuntimeState {
    config: Arc<Mutex<AppConfig>>,
    statuses: Arc<Mutex<Vec<GroupStatus>>>,
    candidates: Arc<Mutex<Vec<AppCandidate>>>,
    events: Arc<Mutex<VecDeque<EventEntry>>>,
    metrics: Arc<Mutex<VecDeque<MetricSample>>>,
    save_error: Arc<Mutex<Option<String>>>,
    config_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AppCandidate {
    name: String,
    path: PathBuf,
    pid: u32,
}

#[derive(Debug, Clone)]
struct EventEntry {
    time: String,
    message: String,
}

#[derive(Debug, Clone, Copy)]
struct MetricSample {
    cpu_percent: f32,
}

enum WorkerCommand {
    RestoreAll,
    Refresh,
    EnableElevation,
}

struct NamedMutex(HANDLE);

impl NamedMutex {
    fn acquire() -> Result<Option<Self>, String> {
        let name = HSTRING::from("Local\\LazyProcessControlPanel");
        let handle = unsafe { CreateMutexW(None, true, PCWSTR(name.as_ptr())) }
            .map_err(|error| error.to_string())?;
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            let _ = unsafe { CloseHandle(handle) };
            Ok(None)
        } else {
            Ok(Some(Self(handle)))
        }
    }
}

impl Drop for NamedMutex {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn main() {
    if let Err(error) = run() {
        show_error(&format!("Lazy Process 启动失败：{error}"));
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if let [command, parent_pid, journal] = args.as_slice()
        && command == "--watchdog"
    {
        let parent_pid = parent_pid
            .to_string_lossy()
            .parse()
            .map_err(|_| "watchdog PID 无效".to_owned())?;
        return run_watchdog(parent_pid, Path::new(journal));
    }
    if let [command, pipe_name, journal] = args.as_slice()
        && command == "--elevated-helper"
    {
        return run_elevated_helper(&pipe_name.to_string_lossy(), Path::new(journal));
    }
    if !args.is_empty() {
        return Err("不支持的启动参数".into());
    }

    let Some(_mutex) = NamedMutex::acquire()? else {
        return Ok(());
    };
    let config_path = config_path();
    let journal = journal_path();
    let recovery_errors = recover_suspended(&journal);
    let (config, config_error) = match AppConfig::load_or_create(&config_path) {
        Ok(config) => (config, None),
        Err(error) => (AppConfig::default(), Some(error.to_string())),
    };
    let state = RuntimeState {
        config: Arc::new(Mutex::new(config)),
        statuses: Arc::new(Mutex::new(Vec::new())),
        candidates: Arc::new(Mutex::new(Vec::new())),
        events: Arc::new(Mutex::new(VecDeque::new())),
        metrics: Arc::new(Mutex::new(VecDeque::new())),
        save_error: Arc::new(Mutex::new(None)),
        config_path,
    };
    if let Some(error) = config_error {
        push_event(
            &state,
            format!("配置加载失败，已使用内置预设且未覆盖原文件：{error}"),
        );
    }
    for error in recovery_errors {
        push_event(&state, format!("上次暂停状态恢复失败：{error}"));
    }

    let _watchdog =
        spawn_watchdog(&journal).map_err(|error| format!("无法启动恢复守护进程：{error}"))?;
    let panel = ControlPanel::new().map_err(|error| error.to_string())?;
    let tray = AppTray::new().map_err(|error| error.to_string())?;
    let stop = Arc::new(AtomicBool::new(false));
    let (worker_tx, worker_rx) = mpsc::channel();

    install_callbacks(&panel, &tray, &state, &worker_tx, &stop);
    panel
        .window()
        .on_close_requested(|| CloseRequestResponse::HideWindow);
    refresh_panel(&panel, &state);
    panel.show().map_err(|error| error.to_string())?;

    let worker = start_worker(
        panel.as_weak(),
        state.clone(),
        worker_rx,
        stop.clone(),
        journal,
    );
    let _hotkey = start_hotkey(worker_tx.clone(), state.clone());
    slint::run_event_loop().map_err(|error| error.to_string())?;
    stop.store(true, Ordering::Release);
    let _ = worker_tx.send(WorkerCommand::Refresh);
    let _ = worker.join();
    drop(tray);
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn install_callbacks(
    panel: &ControlPanel,
    tray: &AppTray,
    state: &RuntimeState,
    worker: &mpsc::Sender<WorkerCommand>,
    stop: &Arc<AtomicBool>,
) {
    let weak = panel.as_weak();
    tray.on_open(move || show_panel(&weak));
    let tx = worker.clone();
    tray.on_restore_all(move || {
        let _ = tx.send(WorkerCommand::RestoreAll);
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    tray.on_toggle_enabled(move || {
        mutate_config(&runtime, |config| {
            config.globally_enabled = !config.globally_enabled;
        });
        if let Some(panel) = weak.upgrade() {
            refresh_panel(&panel, &runtime);
        }
    });
    let stop_flag = stop.clone();
    tray.on_quit(move || {
        stop_flag.store(true, Ordering::Release);
        let _ = slint::quit_event_loop();
    });

    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_set_global_enabled(move |enabled| {
        mutate_config(&runtime, |config| config.globally_enabled = enabled);
        if let Some(panel) = weak.upgrade() {
            refresh_panel(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_set_start_with_windows(move |enabled| {
        match set_start_with_windows(enabled) {
            Ok(()) => mutate_config(&runtime, |config| config.start_with_windows = enabled),
            Err(error) => push_event(&runtime, format!("开机启动设置失败：{error}")),
        }
        if let Some(panel) = weak.upgrade() {
            refresh_panel(&panel, &runtime);
        }
    });
    let tx = worker.clone();
    panel.on_restore_all(move || {
        let _ = tx.send(WorkerCommand::RestoreAll);
    });
    let tx = worker.clone();
    panel.on_enable_elevation(move || {
        let _ = tx.send(WorkerCommand::EnableElevation);
    });
    let tx = worker.clone();
    panel.on_refresh_now(move || {
        let _ = tx.send(WorkerCommand::Refresh);
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_filter_apps(move |_| {
        if let Some(panel) = weak.upgrade() {
            refresh_candidate_model(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_page_selected(move |page| {
        if let Some(panel) = weak.upgrade() {
            if page == 2 {
                refresh_candidate_model(&panel, &runtime);
            } else if page == 3 {
                refresh_event_model(&panel, &runtime);
            }
        }
    });

    install_rule_callbacks(panel, state);

    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_add_app(move |index| {
        let candidate = usize::try_from(index)
            .ok()
            .and_then(|index| runtime.candidates.lock().ok()?.get(index).cloned());
        if let Some(candidate) = candidate {
            mutate_config(&runtime, |config| {
                let base = slug(&candidate.name);
                let mut id = format!("app-{base}");
                let mut suffix = 2;
                while config.rules.iter().any(|rule| rule.id == id) {
                    id = format!("app-{base}-{suffix}");
                    suffix += 1;
                }
                config.rules.push(ProcessRule {
                    id,
                    name: candidate.name.trim_end_matches(".exe").to_owned(),
                    matcher: RuleMatcher {
                        process_name: Some(candidate.name.clone()),
                        executable_path: Some(candidate.path.clone()),
                        ..Default::default()
                    },
                    ..Default::default()
                });
            });
            push_event(&runtime, format!("已添加 {} 的路径规则", candidate.name));
        }
        if let Some(panel) = weak.upgrade() {
            panel.set_page(1);
            refresh_panel(&panel, &runtime);
        }
    });
    let path = state.config_path.clone();
    panel.on_open_config(move || {
        let _ = Command::new("notepad.exe").arg(&path).spawn();
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_retry_save(move || {
        retry_config_save(&runtime);
        if let Some(panel) = weak.upgrade() {
            refresh_panel(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_dismiss_save_error(move || {
        clear_save_error(&runtime);
        if let Some(panel) = weak.upgrade() {
            refresh_panel(&panel, &runtime);
        }
    });
    panel.on_hide_window({
        let weak = panel.as_weak();
        move || {
            if let Some(panel) = weak.upgrade() {
                let _ = panel.hide();
            }
        }
    });
    let stop_flag = stop.clone();
    panel.on_exit_app(move || {
        stop_flag.store(true, Ordering::Release);
        let _ = slint::quit_event_loop();
    });
}

fn install_rule_callbacks(panel: &ControlPanel, state: &RuntimeState) {
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_set_rule_enabled(move |index, enabled| {
        mutate_rule(&runtime, index, |rule| rule.enabled = enabled);
        if let Some(panel) = weak.upgrade() {
            refresh_panel(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_set_rule_suspend(move |index, enabled| {
        mutate_rule(&runtime, index, |rule| rule.allow_suspend = enabled);
        push_event(
            &runtime,
            if enabled {
                "已为规则显式允许二级暂停".into()
            } else {
                "已关闭规则的二级暂停".into()
            },
        );
        if let Some(panel) = weak.upgrade() {
            refresh_panel(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_adjust_throttle(move |index, delta| {
        mutate_rule(&runtime, index, |rule| {
            let minutes = i64::try_from(rule.throttle_after_seconds / 60).unwrap_or(5);
            rule.throttle_after_seconds =
                u64::try_from((minutes + i64::from(delta)).clamp(1, 240)).unwrap_or(5) * 60;
            rule.suspend_after_seconds = rule
                .suspend_after_seconds
                .max(rule.throttle_after_seconds + 60);
        });
        if let Some(panel) = weak.upgrade() {
            refresh_panel(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_adjust_suspend(move |index, delta| {
        mutate_rule(&runtime, index, |rule| {
            let minutes = i64::try_from(rule.suspend_after_seconds / 60).unwrap_or(20);
            let minimum = i64::try_from(rule.throttle_after_seconds / 60 + 1).unwrap_or(2);
            rule.suspend_after_seconds =
                u64::try_from((minutes + i64::from(delta)).clamp(minimum, 480)).unwrap_or(20) * 60;
        });
        if let Some(panel) = weak.upgrade() {
            refresh_panel(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_remove_rule(move |index| {
        if let Ok(index) = usize::try_from(index) {
            mutate_config(&runtime, |config| {
                if config.rules.get(index).is_some_and(|rule| !rule.built_in) {
                    config.rules.remove(index);
                }
            });
        }
        if let Some(panel) = weak.upgrade() {
            refresh_panel(&panel, &runtime);
        }
    });
}

fn start_worker(
    panel: Weak<ControlPanel>,
    state: RuntimeState,
    commands: mpsc::Receiver<WorkerCommand>,
    stop: Arc<AtomicBool>,
    journal: PathBuf,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut sampler = ProcessSampler::new();
        let mut engine = Engine::new(WindowsResourceController::new(journal));
        let mut previous = HashMap::<(String, u32), ActivityState>::new();
        let mut idle_cycles = 0_u32;
        while !stop.load(Ordering::Acquire) {
            let config = state
                .config
                .lock()
                .map_or_else(|_| AppConfig::default(), |guard| guard.clone());
            let processes = sampler.sample();
            let candidates_changed = update_candidates(&state, &processes);
            let statuses = engine.tick_with_unresponsive(
                &config,
                &processes,
                foreground_process_id(),
                &lazy_process::platform::unresponsive_process_ids(),
                unix_seconds(),
            );
            log_transitions(&state, &mut previous, &statuses);
            record_metrics(&state, &statuses);
            if statuses.is_empty() {
                idle_cycles = idle_cycles.saturating_add(1);
            } else {
                idle_cycles = 0;
            }
            let interval =
                adaptive_sample_interval(&config, &statuses, processes.len(), idle_cycles);
            if let Ok(mut guard) = state.statuses.lock() {
                *guard = statuses;
            }
            let runtime = state.clone();
            let weak = panel.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(panel) = weak.upgrade() {
                    refresh_runtime_panel(&panel, &runtime);
                    if candidates_changed && panel.get_page() == 2 {
                        refresh_candidate_model(&panel, &runtime);
                    }
                }
            });
            match commands.recv_timeout(interval) {
                Ok(WorkerCommand::RestoreAll) => {
                    let errors = engine.restore_all();
                    if errors.is_empty() {
                        push_event(&state, "已手动恢复全部受管进程".into());
                    }
                    for error in errors {
                        push_event(&state, format!("恢复失败：{error}"));
                    }
                }
                Ok(WorkerCommand::EnableElevation) => match engine.enable_elevation() {
                    Ok(()) => push_event(&state, "管理员辅助进程已连接，本次运行有效".into()),
                    Err(error) => push_event(&state, format!("管理员辅助进程启动失败：{error}")),
                },
                Ok(WorkerCommand::Refresh) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        for error in engine.restore_all() {
            push_event(&state, format!("退出恢复失败：{error}"));
        }
    })
}

fn adaptive_sample_interval(
    config: &AppConfig,
    statuses: &[GroupStatus],
    process_count: usize,
    idle_cycles: u32,
) -> Duration {
    let base = config.sample_interval_seconds.clamp(1, 10);
    if !statuses.is_empty() {
        return Duration::from_secs(base);
    }
    let backoff = 1_u64 << idle_cycles.min(3);
    let interval = base.saturating_mul(backoff).clamp(1, 10);
    if process_count > 1_000 {
        Duration::from_secs(interval.max(5))
    } else {
        Duration::from_secs(interval)
    }
}

fn start_hotkey(
    sender: mpsc::Sender<WorkerCommand>,
    state: RuntimeState,
) -> thread::JoinHandle<()> {
    thread::spawn(move || unsafe {
        if RegisterHotKey(
            None,
            HOTKEY_ID,
            MOD_CONTROL | MOD_ALT | MOD_SHIFT | MOD_NOREPEAT,
            u32::from(VK_F12.0),
        )
        .is_err()
        {
            push_event(&state, "恢复快捷键注册失败，可能已被其他应用占用".into());
            return;
        }
        let mut message = MSG::default();
        while GetMessageW(&raw mut message, None, 0, 0).as_bool() {
            if message.message == WM_HOTKEY
                && message.wParam.0 == usize::try_from(HOTKEY_ID).unwrap_or(0)
            {
                let _ = sender.send(WorkerCommand::RestoreAll);
            }
        }
        let _ = UnregisterHotKey(None, HOTKEY_ID);
    })
}

fn update_candidates(state: &RuntimeState, processes: &[ProcessSample]) -> bool {
    let mut seen = HashSet::new();
    let mut candidates = processes
        .iter()
        .filter(|process| process.identity.pid > 4)
        .filter(|process| !process.identity.executable_path.as_os_str().is_empty())
        .filter(|process| {
            seen.insert(
                process
                    .identity
                    .executable_path
                    .to_string_lossy()
                    .to_lowercase(),
            )
        })
        .map(|process| AppCandidate {
            name: process.name.clone(),
            path: process.identity.executable_path.clone(),
            pid: process.identity.pid,
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|candidate| candidate.name.to_lowercase());
    candidates.truncate(200);
    let Ok(mut guard) = state.candidates.lock() else {
        return false;
    };
    if *guard == candidates {
        false
    } else {
        *guard = candidates;
        true
    }
}

fn log_transitions(
    state: &RuntimeState,
    previous: &mut HashMap<(String, u32), ActivityState>,
    statuses: &[GroupStatus],
) {
    let mut current = HashSet::new();
    for status in statuses {
        let key = (status.rule_id.clone(), status.root.pid);
        current.insert(key.clone());
        if previous.get(&key).is_some_and(|old| *old == status.state) {
            continue;
        }
        if previous.insert(key, status.state).is_some() || status.state != ActivityState::Active {
            push_event(
                state,
                format!(
                    "{} (PID {}) → {}",
                    status.root_name,
                    status.root.pid,
                    status.state.label()
                ),
            );
        }
    }
    previous.retain(|key, _| current.contains(key));
}

fn refresh_panel(panel: &ControlPanel, state: &RuntimeState) {
    let config = state
        .config
        .lock()
        .map_or_else(|_| AppConfig::default(), |guard| guard.clone());
    panel.set_globally_enabled(config.globally_enabled);
    panel.set_start_with_windows(config.start_with_windows);
    panel.set_config_path(state.config_path.display().to_string().into());
    let save_error = state
        .save_error
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_default();
    panel.set_save_error(save_error.into());
    let rules = config
        .rules
        .iter()
        .map(|rule| RuleRow {
            id: rule.id.clone().into(),
            name: rule.name.clone().into(),
            matcher: rule.matcher.summary().into(),
            enabled: rule.enabled,
            allow_suspend: rule.allow_suspend,
            throttle_minutes: i32::try_from(rule.throttle_after_seconds / 60).unwrap_or(i32::MAX),
            suspend_minutes: i32::try_from(rule.suspend_after_seconds / 60).unwrap_or(i32::MAX),
            built_in: rule.built_in,
        })
        .collect::<Vec<_>>();
    panel.set_rules(ModelRc::new(VecModel::from(rules)));

    refresh_runtime_panel(panel, state);
    refresh_candidate_model(panel, state);
    refresh_event_model(panel, state);
}

fn refresh_runtime_panel(panel: &ControlPanel, state: &RuntimeState) {
    let config = state
        .config
        .lock()
        .map_or_else(|_| AppConfig::default(), |guard| guard.clone());
    let statuses = state
        .statuses
        .lock()
        .map_or_else(|_| Vec::new(), |guard| guard.clone());
    let status_rows = statuses
        .iter()
        .map(|status| StatusRow {
            rule_id: status.rule_id.clone().into(),
            title: format!("{} · PID {}", status.root_name, status.root.pid).into(),
            state: status.state.label().into(),
            detail: status.detail.clone().into(),
            pid: i32::try_from(status.root.pid).unwrap_or(i32::MAX),
            process_count: i32::try_from(status.process_count).unwrap_or(i32::MAX),
            state_color: state_color(status.state),
        })
        .collect::<Vec<_>>();
    panel.set_statuses(ModelRc::new(VecModel::from(status_rows)));
    let metrics = state
        .metrics
        .lock()
        .map_or_else(|_| VecDeque::new(), |guard| guard.clone());
    let current_cpu = metrics.back().map_or(0.0, |sample| sample.cpu_percent);
    let peak_cpu = metrics
        .iter()
        .map(|sample| sample.cpu_percent)
        .fold(0.0_f32, f32::max);
    panel.set_cpu_chart_path(cpu_chart_path(&metrics).into());
    panel.set_cpu_current(format!("{current_cpu:.1}%").into());
    panel.set_cpu_peak(format!("{peak_cpu:.1}%").into());
    panel.set_chart_group_count(i32::try_from(statuses.len()).unwrap_or(i32::MAX));
    panel.set_chart_process_count(
        i32::try_from(
            statuses
                .iter()
                .map(|status| status.process_count)
                .sum::<usize>(),
        )
        .unwrap_or(i32::MAX),
    );
    panel.set_footer_status(
        format!(
            "{} 条规则 · {} 个匹配组",
            config.rules.iter().filter(|rule| rule.enabled).count(),
            statuses.len()
        )
        .into(),
    );
}

fn refresh_candidate_model(panel: &ControlPanel, state: &RuntimeState) {
    let candidates = state
        .candidates
        .lock()
        .map_or_else(|_| Vec::new(), |guard| guard.clone());
    let query = panel.get_app_filter().to_string();
    panel.set_apps(ModelRc::new(VecModel::from(
        candidates
            .iter()
            .enumerate()
            .filter(|(_, candidate)| candidate_matches(candidate, &query))
            .map(|(source_index, candidate)| AppRow {
                name: candidate.name.clone().into(),
                path: candidate.path.display().to_string().into(),
                pid: i32::try_from(candidate.pid).unwrap_or(i32::MAX),
                source_index: i32::try_from(source_index).unwrap_or(i32::MAX),
            })
            .collect::<Vec<_>>(),
    )));
    panel.set_selected_app(-1);
    panel.set_selected_app_source(-1);
}

fn candidate_matches(candidate: &AppCandidate, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }
    let searchable = format!(
        "{} {} {}",
        candidate.name,
        candidate.path.display(),
        candidate.pid
    )
    .to_lowercase();
    query
        .split_whitespace()
        .all(|term| searchable.contains(term))
}

fn record_metrics(state: &RuntimeState, statuses: &[GroupStatus]) {
    let cpu_percent = statuses.iter().map(|status| status.cpu_percent).sum();
    if let Ok(mut metrics) = state.metrics.lock() {
        metrics.push_back(MetricSample { cpu_percent });
        while metrics.len() > 60 {
            metrics.pop_front();
        }
    }
}

fn cpu_chart_path(metrics: &VecDeque<MetricSample>) -> String {
    if metrics.is_empty() {
        return "M 0 38 L 100 38".into();
    }
    let peak = metrics
        .iter()
        .map(|sample| sample.cpu_percent)
        .fold(0.0_f32, f32::max)
        .max(10.0);
    let divisor =
        f32::from(u16::try_from(metrics.len().saturating_sub(1).max(1)).unwrap_or(u16::MAX));
    let mut path = String::new();
    for (index, sample) in metrics.iter().enumerate() {
        let x = f32::from(u16::try_from(index).unwrap_or(u16::MAX)) * 100.0 / divisor;
        let ratio = (sample.cpu_percent / peak).clamp(0.0, 1.0);
        let y = 38.0 - ratio * 34.0;
        let command = if index == 0 { 'M' } else { 'L' };
        let _ = write!(path, "{command} {x:.2} {y:.2} ");
    }
    if metrics.len() == 1 {
        let y = 38.0 - (metrics[0].cpu_percent / peak).clamp(0.0, 1.0) * 34.0;
        let _ = write!(path, "L 100 {y:.2}");
    }
    path
}

fn refresh_event_model(panel: &ControlPanel, state: &RuntimeState) {
    let events = state
        .events
        .lock()
        .map_or_else(|_| VecDeque::new(), |guard| guard.clone());
    panel.set_events(ModelRc::new(VecModel::from(
        events
            .iter()
            .rev()
            .map(|event| EventRow {
                time: event.time.clone().into(),
                message: event.message.clone().into(),
            })
            .collect::<Vec<_>>(),
    )));
}

fn mutate_rule(state: &RuntimeState, index: i32, mutation: impl FnOnce(&mut ProcessRule)) {
    let Ok(index) = usize::try_from(index) else {
        return;
    };
    mutate_config(state, |config| {
        if let Some(rule) = config.rules.get_mut(index) {
            mutation(rule);
        }
    });
}

fn mutate_config(state: &RuntimeState, mutation: impl FnOnce(&mut AppConfig)) {
    let result = match state.config.lock() {
        Ok(mut config) => {
            mutation(&mut config);
            config.save_atomic(&state.config_path)
        }
        Err(_) => Err(std::io::Error::other("配置锁已损坏")),
    };
    match result {
        Ok(()) => clear_save_error(state),
        Err(error) => {
            set_save_error(state, error.to_string());
            push_event(state, format!("配置保存失败：{error}"));
        }
    }
}

fn retry_config_save(state: &RuntimeState) {
    let result = match state.config.lock() {
        Ok(config) => config.save_atomic(&state.config_path),
        Err(_) => Err(std::io::Error::other("配置锁已损坏")),
    };
    match result {
        Ok(()) => {
            clear_save_error(state);
            push_event(state, "配置已重试保存成功".into());
        }
        Err(error) => {
            set_save_error(state, error.to_string());
            push_event(state, format!("配置重试保存失败：{error}"));
        }
    }
}

fn set_save_error(state: &RuntimeState, error: String) {
    if let Ok(mut save_error) = state.save_error.lock() {
        *save_error = Some(error);
    }
}

fn clear_save_error(state: &RuntimeState) {
    if let Ok(mut save_error) = state.save_error.lock() {
        *save_error = None;
    }
}

fn push_event(state: &RuntimeState, message: String) {
    if let Ok(mut events) = state.events.lock() {
        events.push_back(EventEntry {
            time: format_time(unix_seconds()),
            message,
        });
        while events.len() > 200 {
            events.pop_front();
        }
    }
}

fn state_color(state: ActivityState) -> Color {
    match state {
        ActivityState::Active => Color::from_rgb_u8(43, 124, 75),
        ActivityState::Quiet => Color::from_rgb_u8(95, 111, 101),
        ActivityState::Throttled => Color::from_rgb_u8(183, 115, 31),
        ActivityState::Suspended => Color::from_rgb_u8(116, 76, 148),
        ActivityState::Unresponsive | ActivityState::Inaccessible => {
            Color::from_rgb_u8(173, 67, 55)
        }
    }
}

fn set_start_with_windows(enabled: bool) -> Result<(), String> {
    let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    let mut command = Command::new("reg.exe");
    if enabled {
        let executable = std::env::current_exe().map_err(|error| error.to_string())?;
        command
            .args(["ADD", key, "/v", "LazyProcess", "/t", "REG_SZ", "/d"])
            .arg(format!("\"{}\"", executable.display()))
            .arg("/f");
    } else {
        command.args(["DELETE", key, "/v", "LazyProcess", "/f"]);
    }
    let status = command
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| error.to_string())?;
    if status.success() || !enabled {
        Ok(())
    } else {
        Err(format!("reg.exe 返回 {status}"))
    }
}

fn show_panel(weak: &Weak<ControlPanel>) {
    if let Some(panel) = weak.upgrade() {
        let _ = panel.show();
        panel.window().request_redraw();
    }
}

fn slug(value: &str) -> String {
    let mut output = String::new();
    let mut hyphen = false;
    for character in value.to_ascii_lowercase().chars() {
        if character.is_ascii_alphanumeric() {
            output.push(character);
            hyphen = false;
        } else if !hyphen && !output.is_empty() {
            output.push('-');
            hyphen = true;
        }
    }
    output.trim_matches('-').to_owned()
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn format_time(seconds: u64) -> String {
    let day = seconds % 86_400;
    format!("{:02}:{:02}:{:02}", day / 3600, (day % 3600) / 60, day % 60)
}

fn show_error(message: &str) {
    let message = HSTRING::from(message);
    let title = HSTRING::from("Lazy Process");
    unsafe {
        let _ = windows::Win32::UI::WindowsAndMessaging::MessageBoxW(
            None,
            PCWSTR(message.as_ptr()),
            PCWSTR(title.as_ptr()),
            windows::Win32::UI::WindowsAndMessaging::MB_ICONERROR,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_is_stable() {
        assert_eq!(slug("Windows Terminal.exe"), "windows-terminal-exe");
    }

    #[test]
    fn candidate_filter_matches_name_path_pid_and_terms() {
        let candidate = AppCandidate {
            name: "Code.exe".into(),
            path: PathBuf::from(r"C:\Program Files\Microsoft VS Code\Code.exe"),
            pid: 4242,
        };
        assert!(candidate_matches(&candidate, "code"));
        assert!(candidate_matches(&candidate, "microsoft 4242"));
        assert!(candidate_matches(&candidate, ""));
        assert!(!candidate_matches(&candidate, "powershell"));
    }

    #[test]
    fn cpu_chart_path_spans_the_chart() {
        let metrics = VecDeque::from([
            MetricSample { cpu_percent: 0.0 },
            MetricSample { cpu_percent: 10.0 },
        ]);
        let path = cpu_chart_path(&metrics);
        assert!(path.starts_with("M 0.00 38.00"));
        assert!(path.contains("L 100.00 4.00"));
    }

    fn status(state: ActivityState) -> GroupStatus {
        GroupStatus {
            rule_id: "rule".into(),
            root: lazy_process::model::ProcessIdentity {
                pid: 10,
                started_at: 1,
                executable_path: PathBuf::from(r"C:\bin\app.exe"),
            },
            root_name: "app.exe".into(),
            process_count: 1,
            state,
            quiet_seconds: 0,
            cpu_percent: 0.0,
            detail: String::new(),
        }
    }

    #[test]
    fn adaptive_sampling_honors_config_for_active_groups() {
        let config = AppConfig {
            sample_interval_seconds: 8,
            ..Default::default()
        };
        assert_eq!(
            adaptive_sample_interval(&config, &[status(ActivityState::Active)], 100, 0),
            Duration::from_secs(8)
        );
    }

    #[test]
    fn adaptive_sampling_backs_off_without_matches() {
        let config = AppConfig::default();
        assert_eq!(
            adaptive_sample_interval(&config, &[], 100, 1),
            Duration::from_secs(4)
        );
        assert_eq!(
            adaptive_sample_interval(&config, &[], 1_500, 3),
            Duration::from_secs(10)
        );
        assert_eq!(
            adaptive_sample_interval(&config, &[status(ActivityState::Quiet)], 100, 0),
            Duration::from_secs(2)
        );
    }
}
