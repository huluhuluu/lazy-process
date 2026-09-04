#![windows_subsystem = "windows"]

slint::include_modules!();

use lazy_process::{
    config::{
        AppConfig, ProcessRule, RuleMatcher, ThemePreference, config_path, event_log_path,
        journal_path, journal_recovery_paths,
    },
    engine::{Engine, TickContext, preview_rule},
    model::{ActivityState, GroupStatus, ProcessIdentity, ProcessSample, SystemSnapshot},
    platform::{
        ProcessSampler, WatchdogRecovery, WindowsResourceController, acquire_application_lease,
        foreground_process_id, local_minute_and_weekday, recover_all_suspended,
        run_elevated_helper, run_watchdog, spawn_watchdog, user_is_busy,
    },
};
use slint::{CloseRequestResponse, Color, ComponentHandle, ModelRc, VecModel, Weak};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    ffi::OsString,
    fmt::Write as _,
    fs,
    io::Write as _,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, GetLastError, HANDLE,
            WAIT_OBJECT_0,
        },
        System::{
            Registry::{
                HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
                RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteValueW,
                RegGetValueW, RegSetValueExW,
            },
            SystemInformation::GetLocalTime,
            Threading::{CreateEventW, CreateMutexW, OpenEventW, SetEvent, WaitForSingleObject},
        },
        UI::{
            Controls::Dialogs::{
                GetOpenFileNameW, GetSaveFileNameW, OFN_EXPLORER, OFN_FILEMUSTEXIST,
                OFN_HIDEREADONLY, OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST, OPENFILENAMEW,
            },
            Input::KeyboardAndMouse::{
                MOD_ALT, MOD_CONTROL, MOD_NOREPEAT, MOD_SHIFT, RegisterHotKey, UnregisterHotKey,
                VK_F12,
            },
            WindowsAndMessaging::{GetMessageW, MSG, WM_HOTKEY},
        },
    },
    core::{HSTRING, PCWSTR, PWSTR},
};

const HOTKEY_ID: i32 = 0x4c50;
const WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
/// A second launch signals this instead of starting a second tray icon.
const SHOW_PANEL_EVENT: &str = "Local\\LazyProcessShowPanel";
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "LazyProcess";
const EVENT_HISTORY: usize = 200;
/// Above this the log is rewritten with only the entries the panel would show.
const EVENT_LOG_MAX_BYTES: u64 = 512 * 1024;

#[derive(Clone)]
struct RuntimeState {
    config: Arc<Mutex<AppConfig>>,
    statuses: Arc<Mutex<Vec<GroupStatus>>>,
    candidates: Arc<Mutex<Vec<AppCandidate>>>,
    events: Arc<Mutex<VecDeque<EventEntry>>>,
    metrics: Arc<Mutex<VecDeque<MetricSample>>>,
    save_error: Arc<Mutex<Option<String>>>,
    draft: Arc<Mutex<Option<RuleDraft>>>,
    /// The most recent full sample, for the process explorer and the rule preview. Held separately
    /// from `candidates`, which is deduplicated by path and therefore cannot list every process.
    sample: Arc<Mutex<Vec<ProcessSample>>>,
    snapshot: Arc<Mutex<SystemSnapshot>>,
    /// Pids currently managed by a rule, so the explorer can mark them.
    managed_pids: Arc<Mutex<HashSet<u32>>>,
    /// The process a kill confirmation is waiting on.
    kill_target: Arc<Mutex<Option<ProcessIdentity>>>,
    explorer_error: Arc<Mutex<Option<String>>>,
    config_path: PathBuf,
    event_log_path: PathBuf,
}

/// An in-progress rule edit. Kept out of the configuration until it validates so a half-typed
/// matcher never reaches the engine or the file on disk. `index` is `None` for a new rule.
#[derive(Debug, Clone)]
struct RuleDraft {
    index: Option<usize>,
    rule: ProcessRule,
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

impl EventEntry {
    /// Failures are highlighted in the log. Matched on the wording used by `push_event` call sites
    /// rather than a flag, so entries reloaded from an older log file are classified too.
    fn is_error(&self) -> bool {
        const MARKERS: [&str; 4] = ["失败", "出错", "无法", "已停用"];
        MARKERS.iter().any(|marker| self.message.contains(marker))
    }
}

#[derive(Debug, Clone, Copy)]
struct MetricSample {
    cpu_percent: f32,
}

enum WorkerCommand {
    RestoreAll,
    Refresh,
    EnableElevation,
    /// Every process-touching action runs on the worker, which owns the controller and its journal.
    Terminate(ProcessIdentity),
    RestoreGroup {
        rule_id: String,
        pid: u32,
    },
    ExcludeGroup {
        rule_id: String,
        pid: u32,
    },
}

struct NamedMutex(HANDLE);

impl NamedMutex {
    fn acquire() -> Result<Option<Self>, String> {
        let name = HSTRING::from("Local\\LazyProcessControlPanel");
        let handle = unsafe { CreateMutexW(None, false, PCWSTR(name.as_ptr())) }
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
    if run_internal_mode(&args)? {
        return Ok(());
    }

    let Some(_mutex) = NamedMutex::acquire()? else {
        // A tray application has no window to fall back on, so hand the request to the instance
        // that owns the tray icon instead of exiting without a trace.
        if !signal_running_instance() {
            show_error("Lazy Process 已在运行，但无法唤出它的窗口。请检查托盘图标。");
        }
        return Ok(());
    };
    let _application_lease = acquire_application_lease(Duration::ZERO)
        .map_err(|error| format!("另一个会话正在运行 Lazy Process：{error}"))?;
    let config_path = config_path();
    let event_log = event_log_path();
    let journal = journal_path();
    let recovery_paths = journal_recovery_paths();
    let watchdog_path = recovery_paths
        .first()
        .cloned()
        .unwrap_or_else(|| journal.clone());
    let _watchdog = spawn_watchdog(&watchdog_path, WatchdogRecovery::AllJournals)
        .map_err(|error| format!("无法启动恢复守护进程：{error}"))?;
    let recovery_errors = recover_all_suspended(&recovery_paths);
    let (mut config, config_error) = match AppConfig::load_or_create(&config_path) {
        Ok(config) => (config, None),
        Err(error) => {
            let config = AppConfig {
                globally_enabled: false,
                ..AppConfig::default()
            };
            (config, Some(error.to_string()))
        }
    };
    if !recovery_errors.is_empty() {
        config.globally_enabled = false;
    }
    let state = RuntimeState {
        config: Arc::new(Mutex::new(config)),
        statuses: Arc::new(Mutex::new(Vec::new())),
        candidates: Arc::new(Mutex::new(Vec::new())),
        events: Arc::new(Mutex::new(load_event_log(&event_log))),
        metrics: Arc::new(Mutex::new(VecDeque::new())),
        save_error: Arc::new(Mutex::new(None)),
        draft: Arc::new(Mutex::new(None)),
        sample: Arc::new(Mutex::new(Vec::new())),
        snapshot: Arc::new(Mutex::new(SystemSnapshot::default())),
        managed_pids: Arc::new(Mutex::new(HashSet::new())),
        kill_target: Arc::new(Mutex::new(None)),
        explorer_error: Arc::new(Mutex::new(None)),
        config_path,
        event_log_path: event_log,
    };
    let config_is_authoritative = config_error.is_none() && recovery_errors.is_empty();
    if let Some(error) = config_error {
        push_event(
            &state,
            format!("配置加载失败，监控已安全停用且未覆盖原文件：{error}"),
        );
    }
    for error in recovery_errors {
        push_event(&state, format!("上次进程状态恢复失败，监控已停用：{error}"));
    }
    if config_is_authoritative {
        // Skipped in the degraded cases on purpose. The in-memory configuration is then either a
        // default standing in for a file we refused to overwrite, or one with monitoring forced off
        // for this session only; saving either would destroy the user's settings.
        reconcile_start_with_windows(&state);
    }

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
        tray.as_weak(),
        state.clone(),
        worker_rx,
        stop.clone(),
        journal,
    );
    let _hotkey = start_hotkey(worker_tx.clone(), state.clone());
    start_show_panel_watcher(panel.as_weak(), stop.clone());
    slint::run_event_loop().map_err(|error| error.to_string())?;
    stop.store(true, Ordering::Release);
    let _ = worker_tx.send(WorkerCommand::Refresh);
    join_worker_with_timeout(worker);
    drop(tray);
    Ok(())
}

fn run_internal_mode(args: &[OsString]) -> Result<bool, String> {
    if let [
        command,
        parent_pid,
        parent_started_at_ticks,
        ready_event,
        recovery,
        journal,
    ] = args
        && command == "--watchdog"
    {
        let parent_pid = parent_pid
            .to_string_lossy()
            .parse()
            .map_err(|_| "watchdog PID 无效".to_owned())?;
        let parent_started_at_ticks = parent_started_at_ticks
            .to_string_lossy()
            .parse()
            .map_err(|_| "watchdog 父进程启动时间无效".to_owned())?;
        let recovery = match recovery.to_string_lossy().as_ref() {
            "all" => WatchdogRecovery::AllJournals,
            "single" => WatchdogRecovery::SingleJournal,
            _ => return Err("watchdog 恢复范围无效".into()),
        };
        run_watchdog(
            parent_pid,
            parent_started_at_ticks,
            &ready_event.to_string_lossy(),
            recovery,
            Path::new(journal),
        )?;
        return Ok(true);
    }
    if let [
        command,
        parent_pid,
        parent_started_at_ticks,
        pipe_name,
        cancel_event,
        ready_event,
        journal,
    ] = args
        && command == "--elevated-helper"
    {
        let parent_pid = parent_pid
            .to_string_lossy()
            .parse()
            .map_err(|_| "管理员辅助进程父 PID 无效".to_owned())?;
        let parent_started_at_ticks = parent_started_at_ticks
            .to_string_lossy()
            .parse()
            .map_err(|_| "管理员辅助进程父进程启动时间无效".to_owned())?;
        run_elevated_helper(
            parent_pid,
            parent_started_at_ticks,
            &pipe_name.to_string_lossy(),
            &cancel_event.to_string_lossy(),
            &ready_event.to_string_lossy(),
            Path::new(journal),
        )?;
        return Ok(true);
    }
    if args.is_empty() {
        Ok(false)
    } else {
        Err("不支持的启动参数".into())
    }
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
    let tray_weak = tray.as_weak();
    tray.on_toggle_enabled(move || {
        mutate_config(&runtime, |config| {
            config.globally_enabled = !config.globally_enabled;
        });
        if let Some(panel) = weak.upgrade() {
            refresh_panel(&panel, &runtime);
        }
        if let Some(tray) = tray_weak.upgrade() {
            refresh_tray(&tray, &runtime);
        }
    });
    let stop_flag = stop.clone();
    tray.on_quit(move || {
        stop_flag.store(true, Ordering::Release);
        let _ = slint::quit_event_loop();
    });

    let runtime = state.clone();
    let weak = panel.as_weak();
    let tray_weak = tray.as_weak();
    panel.on_set_global_enabled(move |enabled| {
        mutate_config(&runtime, |config| config.globally_enabled = enabled);
        if let Some(panel) = weak.upgrade() {
            refresh_panel(&panel, &runtime);
        }
        if let Some(tray) = tray_weak.upgrade() {
            refresh_tray(&tray, &runtime);
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
    install_editor_callbacks(panel, state);
    install_settings_callbacks(panel, state);
    install_explorer_callbacks(panel, state, worker);

    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_add_app(move |index| {
        let candidate = usize::try_from(index)
            .ok()
            .and_then(|index| runtime.candidates.lock().ok()?.get(index).cloned());
        if let Some(candidate) = candidate {
            mutate_config(&runtime, |config| {
                let id = unique_rule_id(config, &slug(&candidate.name));
                config.rules.push(ProcessRule {
                    id,
                    name: strip_executable_suffix(&candidate.name).to_owned(),
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
            panel.set_page(2);
            refresh_panel(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_browse_executable(move || {
        let Some(path) = pick_file(
            "选择要管理的程序",
            &["程序 (*.exe)", "*.exe", "所有文件 (*.*)", "*.*"],
            "",
            false,
        ) else {
            return;
        };
        let name = path
            .file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
        if name.is_empty() {
            return;
        }
        add_path_rule(&runtime, &name, &path);
        push_event(&runtime, format!("已添加 {name} 的路径规则"));
        if let Some(panel) = weak.upgrade() {
            panel.set_page(2);
            refresh_panel(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_add_process_rule(move |source_index| {
        let process = usize::try_from(source_index)
            .ok()
            .and_then(|index| runtime.sample.lock().ok()?.get(index).cloned());
        if let Some(process) = process {
            add_path_rule(&runtime, &process.name, &process.identity.executable_path);
            push_event(&runtime, format!("已添加 {} 的路径规则", process.name));
            if let Some(panel) = weak.upgrade() {
                panel.set_page(2);
                refresh_panel(&panel, &runtime);
            }
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

fn install_editor_callbacks(panel: &ControlPanel, state: &RuntimeState) {
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_edit_rule(move |index| {
        let rule = usize::try_from(index)
            .ok()
            .and_then(|index| Some((index, runtime.config.lock().ok()?.rules.get(index)?.clone())));
        if let Some((index, rule)) = rule {
            set_draft(
                &runtime,
                Some(RuleDraft {
                    index: Some(index),
                    rule,
                }),
            );
            if let Some(panel) = weak.upgrade() {
                open_editor(&panel, &runtime, "编辑规则");
            }
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_new_rule(move || {
        set_draft(
            &runtime,
            Some(RuleDraft {
                index: None,
                rule: ProcessRule {
                    name: String::new(),
                    matcher: RuleMatcher::default(),
                    ..Default::default()
                },
            }),
        );
        if let Some(panel) = weak.upgrade() {
            open_editor(&panel, &runtime, "新建规则");
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_save_draft(move || {
        if let Some(panel) = weak.upgrade() {
            commit_draft(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_cancel_draft(move || {
        set_draft(&runtime, None);
        if let Some(panel) = weak.upgrade() {
            close_editor(&panel);
        }
    });

    install_draft_field_callbacks(panel, state);
}

/// The per-field handlers. Split out so neither half of the editor wiring grows past the point of
/// being readable in one screen.
fn install_draft_field_callbacks(panel: &ControlPanel, state: &RuntimeState) {
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_set_draft_field(move |field, value| {
        mutate_draft(&runtime, |draft| {
            let value = value.to_string();
            let matcher = &mut draft.rule.matcher;
            match field.as_str() {
                "name" => value.trim().clone_into(&mut draft.rule.name),
                "process-name" => matcher.process_name = optional_text(&value),
                "executable-path" => {
                    matcher.executable_path = optional_text(&value).map(PathBuf::from);
                }
                "path-contains" => matcher.path_contains = optional_text(&value),
                "command-contains" => matcher.command_contains = optional_text(&value),
                "command-regex" => matcher.command_regex = optional_text(&value),
                "ancestor-name" => matcher.ancestor_process_name = optional_text(&value),
                // A half-typed time is left at its previous value rather than snapping to zero,
                // which would fight the user while they are still typing.
                "schedule-start" => {
                    if let Some(minute) = parse_minute(&value) {
                        draft.rule.schedule.get_or_insert_default().start_minute = minute;
                    }
                }
                "schedule-end" => {
                    if let Some(minute) = parse_minute(&value) {
                        draft.rule.schedule.get_or_insert_default().end_minute = minute;
                    }
                }
                _ => {}
            }
        });
        if let Some(panel) = weak.upgrade() {
            refresh_preview_model(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_set_draft_descendants(move |enabled| {
        mutate_draft(&runtime, |draft| draft.rule.include_descendants = enabled);
        if let Some(panel) = weak.upgrade() {
            refresh_preview_model(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    panel.on_set_draft_trim(move |enabled| {
        mutate_draft(&runtime, |draft| draft.rule.trim_working_set = enabled);
    });
    install_draft_schedule_callbacks(panel, state);
}

/// The schedule half of the editor. Split from the other field handlers only to keep each function
/// readable in one screen.
fn install_draft_schedule_callbacks(panel: &ControlPanel, state: &RuntimeState) {
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_set_draft_schedule_enabled(move |enabled| {
        mutate_draft(&runtime, |draft| {
            draft.rule.schedule = enabled.then(|| draft.rule.schedule.unwrap_or_default());
        });
        if let Some(panel) = weak.upgrade() {
            let schedule = read_draft(&runtime)
                .and_then(|draft| draft.rule.schedule)
                .unwrap_or_default();
            panel.set_draft_schedule_enabled(enabled);
            panel.set_draft_schedule_start(format_minute(schedule.start_minute).into());
            panel.set_draft_schedule_end(format_minute(schedule.end_minute).into());
            panel.set_draft_schedule_days(i32::from(schedule.days));
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_toggle_draft_schedule_day(move |day| {
        let Ok(day) = u8::try_from(day) else {
            return;
        };
        if day > 6 {
            return;
        }
        mutate_draft(&runtime, |draft| {
            let schedule = draft.rule.schedule.get_or_insert_default();
            let bit = 1_u8 << day;
            // Zero displays as "every day", so the first click has to start from all seven set,
            // otherwise turning one day off would look like turning one day on.
            if schedule.days == 0 {
                schedule.days = 0b0111_1111 & !bit;
            } else {
                schedule.days ^= bit;
            }
            // Clearing the last day would silently disable the rule, so treat it as "every day".
            if schedule.days == 0b0111_1111 {
                schedule.days = 0;
            }
        });
        if let Some(panel) = weak.upgrade() {
            let days = read_draft(&runtime)
                .and_then(|draft| draft.rule.schedule)
                .map_or(0, |schedule| schedule.days);
            panel.set_draft_schedule_days(i32::from(days));
        }
    });
    install_exclusion_callbacks(panel, state);
}

/// The exclusion list inside the editor.
fn install_exclusion_callbacks(panel: &ControlPanel, state: &RuntimeState) {
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_set_exclusion_field(move |index, field, value| {
        mutate_draft(&runtime, |draft| {
            let Ok(index) = usize::try_from(index) else {
                return;
            };
            let Some(matcher) = draft.rule.exclusions.get_mut(index) else {
                return;
            };
            let value = value.to_string();
            match field.as_str() {
                "process-name" => matcher.process_name = optional_text(&value),
                "path-contains" => matcher.path_contains = optional_text(&value),
                "command-contains" => matcher.command_contains = optional_text(&value),
                _ => {}
            }
        });
        if let Some(panel) = weak.upgrade() {
            refresh_preview_model(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_add_exclusion(move || {
        mutate_draft(&runtime, |draft| {
            draft.rule.exclusions.push(RuleMatcher::default());
        });
        if let Some(panel) = weak.upgrade() {
            refresh_exclusion_model(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_remove_exclusion(move |index| {
        mutate_draft(&runtime, |draft| {
            if let Ok(index) = usize::try_from(index)
                && index < draft.rule.exclusions.len()
            {
                draft.rule.exclusions.remove(index);
            }
        });
        if let Some(panel) = weak.upgrade() {
            refresh_exclusion_model(&panel, &runtime);
            refresh_preview_model(&panel, &runtime);
        }
    });
}

fn install_settings_callbacks(panel: &ControlPanel, state: &RuntimeState) {
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_adjust_sample_interval(move |delta| {
        mutate_config(&runtime, |config| {
            config.sample_interval_seconds =
                step_sample_interval(config.sample_interval_seconds, delta);
        });
        if let Some(panel) = weak.upgrade() {
            refresh_panel(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_adjust_cpu_threshold(move |delta| {
        mutate_config(&runtime, |config| {
            config.cpu_quiet_percent = step_cpu_threshold(config.cpu_quiet_percent, delta);
        });
        if let Some(panel) = weak.upgrade() {
            refresh_panel(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_adjust_io_threshold(move |delta| {
        mutate_config(&runtime, |config| {
            config.io_quiet_bytes_per_sample =
                step_io_threshold(config.io_quiet_bytes_per_sample, delta);
        });
        if let Some(panel) = weak.upgrade() {
            refresh_panel(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_set_theme(move |choice| {
        let theme = match choice {
            1 => ThemePreference::Light,
            2 => ThemePreference::Dark,
            _ => ThemePreference::System,
        };
        mutate_config(&runtime, |config| config.theme = theme);
        if let Some(panel) = weak.upgrade() {
            apply_theme(&panel, theme);
        }
    });
    let runtime = state.clone();
    panel.on_set_pause_while_fullscreen(move |enabled| {
        mutate_config(&runtime, |config| {
            config.pause_while_fullscreen = enabled;
        });
    });
    install_rule_library_callbacks(panel, state);
    let path = state.event_log_path.clone();
    panel.on_open_event_log(move || {
        let _ = Command::new("notepad.exe").arg(&path).spawn();
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_clear_event_log(move || {
        if let Ok(mut events) = runtime.events.lock() {
            events.clear();
            let _ = fs::remove_file(&runtime.event_log_path);
        }
        push_event(&runtime, "事件日志已清空".into());
        if let Some(panel) = weak.upgrade() {
            refresh_event_model(&panel, &runtime);
        }
    });
}

/// Restoring presets and moving rules between machines.
fn install_rule_library_callbacks(panel: &ControlPanel, state: &RuntimeState) {
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_restore_presets(move || {
        let mut restored = 0;
        mutate_config(&runtime, |config| {
            restored = config.restore_missing_presets();
        });
        push_event(
            &runtime,
            if restored == 0 {
                "预设规则已齐全，未做改动".to_owned()
            } else {
                format!("已补回 {restored} 条预设规则")
            },
        );
        if let Some(panel) = weak.upgrade() {
            refresh_panel(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    panel.on_export_rules(move || match export_rules(&runtime) {
        Ok(path) => push_event(&runtime, format!("规则已导出到 {}", path.display())),
        Err(error) => {
            push_event(&runtime, format!("规则导出失败：{error}"));
            set_explorer_error(&runtime, error);
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_import_rules(move || match import_rules(&runtime) {
        Ok(None) => {}
        Ok(Some(count)) => {
            push_event(&runtime, format!("已导入 {count} 条规则"));
            if let Some(panel) = weak.upgrade() {
                refresh_panel(&panel, &runtime);
            }
        }
        Err(error) => {
            push_event(&runtime, format!("规则导入失败：{error}"));
            set_explorer_error(&runtime, error);
        }
    });
}

/// The process explorer: filtering, sorting, per-group actions, and the two-step termination.
fn install_explorer_callbacks(
    panel: &ControlPanel,
    state: &RuntimeState,
    worker: &mpsc::Sender<WorkerCommand>,
) {
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_filter_processes(move |query| {
        if let Some(panel) = weak.upgrade() {
            panel.set_process_filter(query);
            // The selection is keyed to the sample, not the row, so it survives this.
            refresh_process_model(&panel, &runtime);
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_sort_processes(move |column| {
        if let Some(panel) = weak.upgrade() {
            // Clicking the active column flips direction; a new column starts at its own default,
            // which is descending for the numeric columns.
            if panel.get_process_sort() == column {
                panel.set_process_descending(!panel.get_process_descending());
            } else {
                panel.set_process_sort(column);
                panel.set_process_descending(
                    ProcessColumn::from_index(column).defaults_to_descending(),
                );
            }
            refresh_process_model(&panel, &runtime);
        }
    });
    install_kill_callbacks(panel, state, worker);
    let runtime = state.clone();
    let sender = worker.clone();
    panel.on_restore_group(move |index| {
        if let Some((rule_id, pid)) = group_at(&runtime, index) {
            let _ = sender.send(WorkerCommand::RestoreGroup { rule_id, pid });
        }
    });
    let runtime = state.clone();
    let sender = worker.clone();
    panel.on_exclude_group(move |index| {
        if let Some((rule_id, pid)) = group_at(&runtime, index) {
            let _ = sender.send(WorkerCommand::ExcludeGroup { rule_id, pid });
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_toggle_status(move |index| {
        if let Some(panel) = weak.upgrade() {
            // Clicking the open card closes it, so one click is always reversible.
            let expanded = if panel.get_expanded_status() == index {
                -1
            } else {
                index
            };
            panel.set_expanded_status(expanded);
            let statuses = runtime
                .statuses
                .lock()
                .map_or_else(|_| Vec::new(), |guard| guard.clone());
            refresh_member_model(&panel, &statuses);
        }
    });
}

/// The two-step termination: `ask-kill` opens the confirmation, and only `confirm-kill` acts.
fn install_kill_callbacks(
    panel: &ControlPanel,
    state: &RuntimeState,
    worker: &mpsc::Sender<WorkerCommand>,
) {
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_ask_kill(move |source_index| {
        let Ok(index) = usize::try_from(source_index) else {
            return;
        };
        let Some(process) = runtime
            .sample
            .lock()
            .ok()
            .and_then(|guard| guard.get(index).cloned())
        else {
            return;
        };
        if let Ok(mut guard) = runtime.kill_target.lock() {
            *guard = Some(process.identity.clone());
        }
        if let Some(panel) = weak.upgrade() {
            panel.set_kill_target(
                format!(
                    "{} · PID {}\n{}",
                    process.name,
                    process.identity.pid,
                    process.identity.executable_path.display()
                )
                .into(),
            );
            let managed = runtime
                .managed_pids
                .lock()
                .is_ok_and(|guard| guard.contains(&process.identity.pid));
            panel.set_kill_warning(if managed {
                "该进程正被规则管理，结束前会先恢复它的优先级和挂起状态。".into()
            } else {
                slint::SharedString::new()
            });
        }
    });
    let runtime = state.clone();
    let sender = worker.clone();
    let weak = panel.as_weak();
    panel.on_confirm_kill(move || {
        let target = runtime
            .kill_target
            .lock()
            .ok()
            .and_then(|mut guard| guard.take());
        if let Some(identity) = target {
            let _ = sender.send(WorkerCommand::Terminate(identity));
        }
        if let Some(panel) = weak.upgrade() {
            panel.set_kill_target(slint::SharedString::new());
            panel.set_kill_warning(slint::SharedString::new());
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_cancel_kill(move || {
        if let Ok(mut guard) = runtime.kill_target.lock() {
            *guard = None;
        }
        if let Some(panel) = weak.upgrade() {
            panel.set_kill_target(slint::SharedString::new());
            panel.set_kill_warning(slint::SharedString::new());
        }
    });
    let runtime = state.clone();
    let weak = panel.as_weak();
    panel.on_dismiss_explorer_error(move || {
        if let Ok(mut guard) = runtime.explorer_error.lock() {
            *guard = None;
        }
        if let Some(panel) = weak.upgrade() {
            panel.set_explorer_error(slint::SharedString::new());
        }
    });
}

/// Appends a rule matching one executable by full path. Shared by the running-app list, the
/// explorer, and the file picker, so all three produce the same shape of rule.
fn add_path_rule(state: &RuntimeState, name: &str, path: &Path) {
    let name = name.to_owned();
    let path = path.to_path_buf();
    mutate_config(state, |config| {
        let id = unique_rule_id(config, &slug(&name));
        config.rules.push(ProcessRule {
            id,
            name: strip_executable_suffix(&name).to_owned(),
            matcher: RuleMatcher {
                process_name: Some(name.clone()),
                executable_path: Some(path.clone()),
                ..Default::default()
            },
            ..Default::default()
        });
    });
}

/// The rule id and root pid of the status row at `index`, or `None` if the list moved underneath a
/// click, which a background refresh can do at any moment.
fn group_at(state: &RuntimeState, index: i32) -> Option<(String, u32)> {
    let index = usize::try_from(index).ok()?;
    let guard = state.statuses.lock().ok()?;
    let status = guard.get(index)?;
    Some((status.rule_id.clone(), status.root.pid))
}

fn open_editor(panel: &ControlPanel, state: &RuntimeState, title: &str) {
    let Some(draft) = read_draft(state) else {
        return;
    };
    let matcher = &draft.rule.matcher;
    panel.set_editor_title(title.into());
    panel.set_editor_error(slint::SharedString::new());
    panel.set_draft_name(draft.rule.name.clone().into());
    panel.set_draft_process_name(text_of(matcher.process_name.as_deref()));
    panel.set_draft_executable_path(
        matcher
            .executable_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default()
            .into(),
    );
    panel.set_draft_path_contains(text_of(matcher.path_contains.as_deref()));
    panel.set_draft_command_contains(text_of(matcher.command_contains.as_deref()));
    panel.set_draft_command_regex(text_of(matcher.command_regex.as_deref()));
    panel.set_draft_ancestor_name(text_of(matcher.ancestor_process_name.as_deref()));
    panel.set_draft_include_descendants(draft.rule.include_descendants);
    panel.set_draft_trim_working_set(draft.rule.trim_working_set);
    let schedule = draft.rule.schedule.unwrap_or_default();
    panel.set_draft_schedule_enabled(draft.rule.schedule.is_some());
    panel.set_draft_schedule_start(format_minute(schedule.start_minute).into());
    panel.set_draft_schedule_end(format_minute(schedule.end_minute).into());
    panel.set_draft_schedule_days(i32::from(schedule.days));
    refresh_exclusion_model(panel, state);
    refresh_preview_model(panel, state);
    panel.set_editor_open(true);
}

/// Minutes from midnight as HH:MM.
fn format_minute(minute: u16) -> String {
    format!("{:02}:{:02}", minute / 60, minute % 60)
}

/// Parses HH:MM, and also a bare hour so a half-typed field is still usable. Out-of-range values
/// return `None` and leave the stored minute alone.
fn parse_minute(value: &str) -> Option<u16> {
    let value = value.trim();
    let (hours, minutes) = match value.split_once(':') {
        Some((hours, minutes)) => (hours, minutes.trim()),
        None => (value, "0"),
    };
    let hours = hours.trim().parse::<u16>().ok()?;
    let minutes = if minutes.is_empty() {
        0
    } else {
        minutes.parse::<u16>().ok()?
    };
    (hours < 24 && minutes < 60).then(|| hours * 60 + minutes)
}

/// Runs the draft against the current sample so the editor can show what it would match. Read-only:
/// nothing here touches a process or the engine's state.
fn refresh_preview_model(panel: &ControlPanel, state: &RuntimeState) {
    let Some(draft) = read_draft(state) else {
        panel.set_draft_preview(ModelRc::new(VecModel::from(Vec::new())));
        panel.set_draft_preview_total(0);
        panel.set_draft_preview_note(slint::SharedString::new());
        return;
    };
    if !draft.rule.matcher.has_selector() {
        panel.set_draft_preview(ModelRc::new(VecModel::from(Vec::new())));
        panel.set_draft_preview_total(0);
        panel.set_draft_preview_note("填写任一条件后显示匹配结果".into());
        return;
    }
    let processes = state
        .sample
        .lock()
        .map_or_else(|_| Vec::new(), |guard| guard.clone());
    let matches = preview_rule(&draft.rule, &processes);
    let total = matches.len();
    let excluded = matches
        .iter()
        .filter(|entry| entry.excluded_by_rule)
        .count();
    let roots = matches
        .iter()
        .filter(|entry| entry.is_root && !entry.excluded_by_rule)
        .count();
    panel.set_draft_preview_total(i32::try_from(total).unwrap_or(i32::MAX));
    panel.set_draft_preview_note(
        format!(
            "{roots} 个宿主 · 共 {} 个进程 · {excluded} 个被排除",
            total - excluded
        )
        .into(),
    );
    panel.set_draft_preview(ModelRc::new(VecModel::from(
        matches
            .iter()
            .take(PREVIEW_ROWS)
            .map(|entry| PreviewRow {
                pid: i32::try_from(entry.pid).unwrap_or(i32::MAX),
                name: entry.name.clone().into(),
                path: entry.executable_path.display().to_string().into(),
                excluded: entry.excluded_by_rule,
            })
            .collect::<Vec<_>>(),
    )));
}

/// The preview is inside a scrolling dialog, so it shows a sample rather than every match.
const PREVIEW_ROWS: usize = 12;

fn close_editor(panel: &ControlPanel) {
    panel.set_editor_open(false);
    panel.set_editor_error(slint::SharedString::new());
}

fn refresh_exclusion_model(panel: &ControlPanel, state: &RuntimeState) {
    let exclusions = read_draft(state)
        .map(|draft| draft.rule.exclusions)
        .unwrap_or_default();
    panel.set_draft_exclusions(ModelRc::new(VecModel::from(
        exclusions
            .iter()
            .map(|matcher| ExclusionRow {
                process_name: text_of(matcher.process_name.as_deref()),
                path_contains: text_of(matcher.path_contains.as_deref()),
                command_contains: text_of(matcher.command_contains.as_deref()),
            })
            .collect::<Vec<_>>(),
    )));
}

fn commit_draft(panel: &ControlPanel, state: &RuntimeState) {
    let Some(draft) = read_draft(state) else {
        close_editor(panel);
        return;
    };
    let mut rule = draft.rule.clone();
    rule.name = rule.name.trim().to_owned();
    // An exclusion row the user added but left blank is not an error, it is just unused.
    rule.exclusions.retain(RuleMatcher::has_selector);
    let config = state
        .config
        .lock()
        .map_or_else(|_| AppConfig::default(), |guard| guard.clone());
    if draft.index.is_none() {
        rule.id = unique_rule_id(&config, &slug(&rule.name));
    }
    if let Err(error) = validate_rule_against(&config, draft.index, &rule) {
        panel.set_editor_error(error.into());
        return;
    }
    let index = draft.index;
    let saved = rule.clone();
    mutate_config(state, |config| match index {
        Some(index) => {
            if let Some(slot) = config.rules.get_mut(index) {
                *slot = saved;
            }
        }
        None => config.rules.push(saved),
    });
    if state.save_error.lock().is_ok_and(|guard| guard.is_some()) {
        // `mutate_config` rolled the change back and is already reporting why.
        return;
    }
    push_event(
        state,
        format!(
            "{}规则 {}",
            if index.is_some() {
                "已更新"
            } else {
                "已新建"
            },
            rule.name
        ),
    );
    set_draft(state, None);
    close_editor(panel);
    panel.set_page(1);
    refresh_panel(panel, state);
}

/// Validates the edited rule the same way a save would, by running the real configuration
/// validator over a trial copy. Anything it rejects is reported inline instead of being written.
fn validate_rule_against(
    config: &AppConfig,
    index: Option<usize>,
    rule: &ProcessRule,
) -> Result<(), String> {
    let mut trial = config.clone();
    match index {
        Some(index) => {
            let Some(slot) = trial.rules.get_mut(index) else {
                return Err("规则已不存在，请重新打开编辑器".into());
            };
            *slot = rule.clone();
        }
        None => trial.rules.push(rule.clone()),
    }
    trial.validate().map_err(|error| error.to_string())
}

fn unique_rule_id(config: &AppConfig, base: &str) -> String {
    let base = if base.is_empty() { "rule" } else { base };
    let mut id = format!("app-{base}");
    let mut suffix = 2;
    while config.rules.iter().any(|rule| rule.id == id) {
        id = format!("app-{base}-{suffix}");
        suffix += 1;
    }
    id
}

fn optional_text(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn text_of(value: Option<&str>) -> slint::SharedString {
    value.unwrap_or_default().into()
}

fn read_draft(state: &RuntimeState) -> Option<RuleDraft> {
    state.draft.lock().ok().and_then(|guard| guard.clone())
}

fn set_draft(state: &RuntimeState, draft: Option<RuleDraft>) {
    if let Ok(mut guard) = state.draft.lock() {
        *guard = draft;
    }
}

fn mutate_draft(state: &RuntimeState, mutation: impl FnOnce(&mut RuleDraft)) {
    if let Ok(mut guard) = state.draft.lock()
        && let Some(draft) = guard.as_mut()
    {
        mutation(draft);
    }
}

fn step_sample_interval(current: u64, delta: i32) -> u64 {
    current.saturating_add_signed(i64::from(delta)).clamp(1, 10)
}

fn step_cpu_threshold(current: f32, delta: i32) -> f32 {
    let stepped = current + f32::from(i8::try_from(delta).unwrap_or(0)) * 0.5;
    ((stepped * 10.0).round() / 10.0).clamp(0.0, 100.0)
}

/// The I/O threshold spans four orders of magnitude, so it steps through a ladder instead of a
/// fixed increment. Off-ladder values from a hand-edited configuration move to the next rung.
const IO_THRESHOLD_LADDER: [u64; 13] = [
    0,
    1 << 10,
    2 << 10,
    4 << 10,
    8 << 10,
    16 << 10,
    32 << 10,
    64 << 10,
    128 << 10,
    256 << 10,
    512 << 10,
    1 << 20,
    4 << 20,
];

fn step_io_threshold(current: u64, delta: i32) -> u64 {
    match delta.cmp(&0) {
        std::cmp::Ordering::Greater => IO_THRESHOLD_LADDER
            .into_iter()
            .find(|value| *value > current)
            .unwrap_or(current),
        std::cmp::Ordering::Less => IO_THRESHOLD_LADDER
            .into_iter()
            .rev()
            .find(|value| *value < current)
            .unwrap_or(0),
        std::cmp::Ordering::Equal => current,
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1 << 20 {
        format!("{} MiB", bytes / (1 << 20))
    } else if bytes >= 1 << 10 {
        format!("{} KiB", bytes / (1 << 10))
    } else {
        format!("{bytes} B")
    }
}

fn start_worker(
    panel: Weak<ControlPanel>,
    tray: Weak<AppTray>,
    state: RuntimeState,
    commands: mpsc::Receiver<WorkerCommand>,
    stop: Arc<AtomicBool>,
    journal: PathBuf,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let engine_clock = Instant::now();
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
            let snapshot = sampler.system_snapshot(&processes);
            let candidates_changed = update_candidates(&state, &processes);
            let (minute_of_day, weekday) = local_minute_and_weekday();
            // Checked only when the option is on, so the extra shell call is skipped entirely for
            // anyone who turned the behaviour off.
            let user_busy = config.pause_while_fullscreen && user_is_busy();
            let statuses = engine.tick_with(
                &config,
                &processes,
                &lazy_process::platform::unresponsive_process_ids(),
                TickContext {
                    foreground_pid: foreground_process_id(),
                    now_seconds: engine_clock.elapsed().as_secs(),
                    minute_of_day,
                    weekday,
                    user_busy,
                },
            );
            log_transitions(&state, &mut previous, &statuses);
            record_metrics(&state, &statuses);
            let process_count = processes.len();
            publish_sample(&state, processes, snapshot, &statuses);
            if statuses.is_empty() {
                idle_cycles = idle_cycles.saturating_add(1);
            } else {
                idle_cycles = 0;
            }
            let interval = adaptive_sample_interval(&config, &statuses, process_count, idle_cycles);
            if let Ok(mut guard) = state.statuses.lock() {
                *guard = statuses;
            }
            let runtime = state.clone();
            let weak = panel.clone();
            let tray_weak = tray.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(panel) = weak.upgrade() {
                    panel.set_user_busy(user_busy);
                    refresh_runtime_panel(&panel, &runtime);
                    // Both models are large, so they are only rebuilt for the visible page.
                    if panel.get_page() == 1 {
                        refresh_process_model(&panel, &runtime);
                    }
                    if candidates_changed && panel.get_page() == 3 {
                        refresh_candidate_model(&panel, &runtime);
                    }
                }
                if let Some(tray) = tray_weak.upgrade() {
                    refresh_tray(&tray, &runtime);
                }
            });
            match commands.recv_timeout(interval) {
                Ok(command) => handle_worker_command(&state, &mut engine, command),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        for error in engine.restore_all() {
            push_event(&state, format!("退出恢复失败：{error}"));
        }
    })
}

/// Runs one command on the worker thread, which owns the controller and therefore the journal.
/// Every failure is both logged and surfaced in a dialog, because these are all user-initiated.
fn handle_worker_command(
    state: &RuntimeState,
    engine: &mut Engine<WindowsResourceController>,
    command: WorkerCommand,
) {
    match command {
        WorkerCommand::RestoreAll => {
            let errors = engine.restore_all();
            if errors.is_empty() {
                push_event(state, "已手动恢复全部受管进程".into());
            }
            for error in errors {
                push_event(state, format!("恢复失败：{error}"));
            }
        }
        WorkerCommand::EnableElevation => match engine.enable_elevation() {
            Ok(()) => push_event(state, "管理员辅助进程已连接，本次运行有效".into()),
            Err(error) => push_event(state, format!("管理员辅助进程启动失败：{error}")),
        },
        WorkerCommand::Terminate(identity) => {
            let name = identity
                .executable_path
                .file_name()
                .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
            // Restore first: terminating a suspended process would leave its journal entry
            // pointing at a dead pid, and a throttled one can be slow to unwind.
            let _ = engine.restore_group_containing(&identity);
            match engine.controller_mut().terminate_process(&identity) {
                Ok(()) => {
                    push_event(state, format!("已手动结束 {name} (PID {})", identity.pid));
                }
                Err(error) => {
                    let message = format!("结束 {name} (PID {}) 失败：{error}", identity.pid);
                    push_event(state, message.clone());
                    set_explorer_error(state, message);
                }
            }
        }
        WorkerCommand::RestoreGroup { rule_id, pid } => {
            if let Err(error) = engine.restore_group(&rule_id, pid) {
                let message = format!("恢复 PID {pid} 失败：{error}");
                push_event(state, message.clone());
                set_explorer_error(state, message);
            } else {
                push_event(state, format!("已手动恢复 PID {pid}"));
            }
        }
        WorkerCommand::ExcludeGroup { rule_id, pid } => {
            if let Err(error) = engine.exclude_group_for_session(&rule_id, pid) {
                let message = format!("排除 PID {pid} 时恢复失败：{error}");
                push_event(state, message.clone());
                set_explorer_error(state, message);
            } else {
                push_event(state, format!("PID {pid} 本次运行不再被管理"));
            }
        }
        WorkerCommand::Refresh => {}
    }
}

fn join_worker_with_timeout(worker: thread::JoinHandle<()>) {
    let deadline = Instant::now() + WORKER_SHUTDOWN_TIMEOUT;
    while !worker.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(25));
    }
    if worker.is_finished() {
        let _ = worker.join();
    }
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
        loop {
            // GetMessageW returns -1 on error, which `as_bool()` reports as true. Treating that
            // as "has a message" would spin without blocking and pin a core, so match explicitly.
            match GetMessageW(&raw mut message, None, 0, 0).0 {
                0 => break,
                -1 => {
                    push_event(&state, "恢复快捷键消息循环出错，快捷键已停用".into());
                    break;
                }
                _ => {}
            }
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

/// Hands the tick's sample to the UI thread. The managed pid set is derived here, while the
/// statuses are still at hand, so the explorer does not have to re-walk the group tree.
fn publish_sample(
    state: &RuntimeState,
    processes: Vec<ProcessSample>,
    snapshot: SystemSnapshot,
    statuses: &[GroupStatus],
) {
    if let Ok(mut guard) = state.managed_pids.lock() {
        *guard = statuses
            .iter()
            .filter(|status| {
                matches!(
                    status.state,
                    ActivityState::Throttled | ActivityState::Suspended
                )
            })
            .flat_map(|status| status.members.iter().map(|member| member.pid))
            .collect();
    }
    if let Ok(mut guard) = state.sample.lock() {
        *guard = processes;
    }
    if let Ok(mut guard) = state.snapshot.lock() {
        *guard = snapshot;
    }
}

/// Columns the explorer can sort by. The order matches the header indices in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessColumn {
    Pid,
    Name,
    Cpu,
    Memory,
    Threads,
    Runtime,
    Status,
}

impl ProcessColumn {
    fn from_index(index: i32) -> Self {
        match index {
            0 => Self::Pid,
            1 => Self::Name,
            3 => Self::Memory,
            4 => Self::Threads,
            5 => Self::Runtime,
            6 => Self::Status,
            // CPU is both the default and the fallback for an out-of-range index.
            _ => Self::Cpu,
        }
    }

    /// Descending is the useful default for the numeric columns; names read better ascending.
    const fn defaults_to_descending(self) -> bool {
        !matches!(self, Self::Name | Self::Pid | Self::Status)
    }
}

fn process_matches(process: &ProcessSample, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }
    let searchable = format!(
        "{} {} {}",
        process.name,
        process.identity.executable_path.display(),
        process.identity.pid
    )
    .to_lowercase();
    query
        .split_whitespace()
        .all(|term| searchable.contains(term))
}

fn sort_processes(processes: &mut [&ProcessSample], column: ProcessColumn, descending: bool) {
    match column {
        ProcessColumn::Pid => processes.sort_by_key(|process| process.identity.pid),
        ProcessColumn::Name => {
            processes.sort_by_key(|process| (process.name.to_lowercase(), process.identity.pid));
        }
        ProcessColumn::Cpu => processes.sort_by(|left, right| {
            left.cpu_percent
                .total_cmp(&right.cpu_percent)
                .then(left.identity.pid.cmp(&right.identity.pid))
        }),
        ProcessColumn::Memory => processes.sort_by_key(|process| process.memory_bytes),
        ProcessColumn::Threads => processes.sort_by_key(|process| process.thread_count),
        ProcessColumn::Runtime => processes.sort_by_key(|process| process.run_time_seconds),
        ProcessColumn::Status => {
            processes.sort_by_key(|process| (process.os_suspended, process.identity.pid));
        }
    }
    if descending {
        processes.reverse();
    }
}

fn refresh_process_model(panel: &ControlPanel, state: &RuntimeState) {
    let processes = state
        .sample
        .lock()
        .map_or_else(|_| Vec::new(), |guard| guard.clone());
    let managed = state
        .managed_pids
        .lock()
        .map_or_else(|_| HashSet::new(), |guard| guard.clone());
    let snapshot = state
        .snapshot
        .lock()
        .map_or_else(|_| SystemSnapshot::default(), |guard| *guard);

    panel.set_system_cpu(format!("{:.1}%", snapshot.cpu_percent).into());
    panel.set_system_cpu_fraction(snapshot.cpu_percent / 100.0);
    panel.set_system_memory(
        format!(
            "{} / {}",
            format_bytes(snapshot.memory_used_bytes),
            format_bytes(snapshot.memory_total_bytes)
        )
        .into(),
    );
    panel.set_system_memory_fraction(snapshot.memory_percent() / 100.0);
    panel.set_system_summary(
        format!(
            "{} 个逻辑处理器 · {} 个受管进程",
            snapshot.cpu_count,
            managed.len()
        )
        .into(),
    );
    panel.set_process_total(i32::try_from(processes.len()).unwrap_or(i32::MAX));

    let query = panel.get_process_filter().to_string();
    let column = ProcessColumn::from_index(panel.get_process_sort());
    let descending = panel.get_process_descending();
    let previous_source = panel.get_selected_process_source();
    let mut matched = processes
        .iter()
        .filter(|process| process_matches(process, &query))
        .collect::<Vec<_>>();
    sort_processes(&mut matched, column, descending);

    // The source index refers to the unfiltered sample, so a selection survives both filtering and
    // re-sorting. Anything else would move the row out from under a pending "结束进程" click.
    let index_of = processes
        .iter()
        .enumerate()
        .map(|(index, process)| (process.identity.pid, index))
        .collect::<HashMap<_, _>>();
    let rows = matched
        .iter()
        .map(|process| {
            let pid = process.identity.pid;
            ProcessRow {
                pid: i32::try_from(pid).unwrap_or(i32::MAX),
                name: process.name.clone().into(),
                path: process
                    .identity
                    .executable_path
                    .display()
                    .to_string()
                    .into(),
                cpu: format!("{:.1}%", process.cpu_percent).into(),
                memory: format_bytes(process.memory_bytes).into(),
                threads: i32::try_from(process.thread_count).unwrap_or(i32::MAX),
                runtime: format_run_time(process.run_time_seconds).into(),
                status: if process.os_suspended {
                    "已暂停".into()
                } else if managed.contains(&pid) {
                    "受管".into()
                } else {
                    "运行中".into()
                },
                managed: managed.contains(&pid),
                suspended: process.os_suspended,
                source_index: index_of
                    .get(&pid)
                    .and_then(|index| i32::try_from(*index).ok())
                    .unwrap_or(-1),
            }
        })
        .collect::<Vec<_>>();
    let selected_row = rows
        .iter()
        .position(|row| row.source_index == previous_source)
        .filter(|_| previous_source >= 0);
    panel.set_processes(ModelRc::new(VecModel::from(rows)));
    if let Some(row) = selected_row {
        panel.set_selected_process(i32::try_from(row).unwrap_or(-1));
    } else {
        panel.set_selected_process(-1);
        panel.set_selected_process_source(-1);
    }
}

/// The explorer's uptime column: compact enough for a 74px cell.
fn format_run_time(seconds: u64) -> String {
    let minutes = seconds / 60;
    if minutes < 60 {
        return format!("{minutes} 分");
    }
    let hours = minutes / 60;
    if hours < 24 {
        format!("{hours} 时 {} 分", minutes % 60)
    } else {
        format!("{} 天 {} 时", hours / 24, hours % 24)
    }
}

fn set_explorer_error(state: &RuntimeState, error: String) {
    if let Ok(mut guard) = state.explorer_error.lock() {
        *guard = Some(error);
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
    panel.set_event_log_path(state.event_log_path.display().to_string().into());
    panel.set_sample_interval_text(format!("{} 秒", config.sample_interval_seconds).into());
    panel.set_cpu_threshold_text(format!("{:.1}%", config.cpu_quiet_percent).into());
    panel.set_io_threshold_text(format_bytes(config.io_quiet_bytes_per_sample).into());
    panel.set_pause_while_fullscreen(config.pause_while_fullscreen);
    apply_theme(panel, config.theme);
    panel.set_candidate_cap(i32::try_from(MAX_CANDIDATE_ROWS).unwrap_or(i32::MAX));
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
    refresh_process_model(panel, state);
    refresh_event_model(panel, state);
}

/// Resolves the preference to a concrete palette and pushes it to the `Theme` global.
fn apply_theme(panel: &ControlPanel, preference: ThemePreference) {
    let choice = match preference {
        ThemePreference::System => 0,
        ThemePreference::Light => 1,
        ThemePreference::Dark => 2,
    };
    panel.set_theme_choice(choice);
    let dark = match preference {
        ThemePreference::Light => false,
        ThemePreference::Dark => true,
        ThemePreference::System => system_prefers_dark(),
    };
    panel.global::<Theme>().set_dark(dark);
}

/// Windows records the app colour mode as `AppsUseLightTheme`, where 0 means dark. A missing value
/// means light, which is the pre-dark-mode default.
fn system_prefers_dark() -> bool {
    read_registry_dword(
        r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        "AppsUseLightTheme",
    )
    .is_some_and(|value| value == 0)
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
            title: format!("{} · PID {}", status.root_name, status.root.pid).into(),
            state: status.state.label().into(),
            detail: status.detail.clone().into(),
            process_count: i32::try_from(status.process_count).unwrap_or(i32::MAX),
            state_color: state_color(status.state),
            cpu: format!("CPU {:.1}%", status.cpu_percent).into(),
            memory: format_bytes(status.memory_bytes).into(),
            countdown: status
                .next_action
                .map(|(action, remaining)| {
                    format!("{} 还需 {}", action.label(), format_wait(remaining))
                })
                .unwrap_or_default()
                .into(),
            managed: matches!(
                status.state,
                ActivityState::Throttled | ActivityState::Suspended | ActivityState::Inaccessible
            ),
        })
        .collect::<Vec<_>>();
    panel.set_statuses(ModelRc::new(VecModel::from(status_rows)));
    refresh_member_model(panel, &statuses);
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
    // 60 samples at the configured interval. Was a fixed string until the interval became
    // configurable, at which point it started lying by up to a factor of five.
    let window_seconds = config.sample_interval_seconds.saturating_mul(60);
    panel.set_chart_window_text(format!("最近约 {} 分钟", window_seconds.div_ceil(60)).into());
    let kill_target = state
        .kill_target
        .lock()
        .ok()
        .and_then(|guard| guard.clone());
    if let Some(identity) = kill_target {
        let managed = state
            .managed_pids
            .lock()
            .is_ok_and(|guard| guard.contains(&identity.pid));
        panel.set_kill_warning(if managed {
            "该进程正被规则管理，结束前会先恢复它的优先级和挂起状态。".into()
        } else {
            slint::SharedString::new()
        });
    } else {
        panel.set_kill_target(slint::SharedString::new());
        panel.set_kill_warning(slint::SharedString::new());
    }
    let explorer_error = state
        .explorer_error
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_default();
    panel.set_explorer_error(explorer_error.into());
}

/// The expanded card's member list. Only one group is ever expanded, so a single model holds the
/// rows for whichever card that is.
fn refresh_member_model(panel: &ControlPanel, statuses: &[GroupStatus]) {
    let expanded = panel.get_expanded_status();
    let members = usize::try_from(expanded)
        .ok()
        .and_then(|index| statuses.get(index))
        .map(|status| {
            status
                .members
                .iter()
                .map(|member| MemberRow {
                    pid: i32::try_from(member.pid).unwrap_or(i32::MAX),
                    name: member.name.clone().into(),
                    cpu: format!("{:.1}%", member.cpu_percent).into(),
                    memory: format_bytes(member.memory_bytes).into(),
                    depth: i32::try_from(member.depth).unwrap_or(0),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    panel.set_status_members(ModelRc::new(VecModel::from(members)));
}

/// Countdowns in the status header. Kept coarse: a second-by-second number in a list that redraws
/// every few seconds reads as noise.
fn format_wait(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds} 秒")
    } else {
        format!("{} 分", seconds.div_ceil(60))
    }
}

/// Rows shown at once on the "add app" page. The filter runs over every candidate first so a
/// search can still reach entries that fall outside this window.
const MAX_CANDIDATE_ROWS: usize = 200;

/// The tray icon is the only surface visible when the window is hidden, so it carries the counts
/// that would otherwise require opening the panel.
fn refresh_tray(tray: &AppTray, state: &RuntimeState) {
    let enabled = state
        .config
        .lock()
        .is_ok_and(|config| config.globally_enabled);
    let statuses = state
        .statuses
        .lock()
        .map_or_else(|_| Vec::new(), |guard| guard.clone());
    let managed = statuses
        .iter()
        .filter(|status| {
            matches!(
                status.state,
                ActivityState::Throttled | ActivityState::Suspended
            )
        })
        .count();
    tray.set_tray_tooltip(
        format!(
            "Lazy Process · {} · {} 组匹配 · {managed} 组已降载",
            if enabled { "监控中" } else { "已暂停" },
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
    let previous_source = panel.get_selected_app_source();
    let matched = candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| candidate_matches(candidate, &query))
        .take(MAX_CANDIDATE_ROWS)
        .collect::<Vec<_>>();
    // Keep the user's selection if that app is still listed; a background refresh must not clear
    // it out from under a pending "add rule" click.
    let selected_row = matched
        .iter()
        .position(|(source_index, _)| {
            i32::try_from(*source_index).unwrap_or(i32::MAX) == previous_source
        })
        .filter(|_| previous_source >= 0);
    panel.set_apps(ModelRc::new(VecModel::from(
        matched
            .into_iter()
            .map(|(source_index, candidate)| AppRow {
                name: candidate.name.clone().into(),
                path: candidate.path.display().to_string().into(),
                pid: i32::try_from(candidate.pid).unwrap_or(i32::MAX),
                source_index: i32::try_from(source_index).unwrap_or(i32::MAX),
            })
            .collect::<Vec<_>>(),
    )));
    if let Some(row) = selected_row {
        panel.set_selected_app(i32::try_from(row).unwrap_or(-1));
    } else {
        panel.set_selected_app(-1);
        panel.set_selected_app_source(-1);
    }
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
                is_error: event.is_error(),
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
            let previous = config.clone();
            mutation(&mut config);
            match config.save_atomic(&state.config_path) {
                Ok(()) => Ok(()),
                Err(error) => {
                    *config = previous;
                    Err(error)
                }
            }
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
    let entry = EventEntry {
        time: local_time_of_day(),
        message,
    };
    if let Ok(mut events) = state.events.lock() {
        // Appending under the same lock keeps the file in the same order as the panel and stops two
        // threads from interleaving a line.
        append_event_log(&state.event_log_path, &entry);
        events.push_back(entry);
        while events.len() > EVENT_HISTORY {
            events.pop_front();
        }
    }
}

/// Writes one `timestamp<TAB>message` line. Log failures are swallowed on purpose: reporting them
/// through `push_event` would recurse, and losing a log line must never disturb the monitor.
fn append_event_log(path: &Path, entry: &EventEntry) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if fs::metadata(path).is_ok_and(|metadata| metadata.len() > EVENT_LOG_MAX_BYTES) {
        trim_event_log(path);
    }
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{}\t{}", local_timestamp(), entry.message);
    }
}

/// Rewrites the log with only the entries the panel would show, so an always-on session cannot
/// grow the file without bound.
fn trim_event_log(path: &Path) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let kept = text
        .lines()
        .rev()
        .take(EVENT_HISTORY)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n");
    let temporary = path.with_extension("log.tmp");
    if fs::write(&temporary, format!("{kept}\n")).is_ok() {
        let _ = lazy_process::config::replace_file_atomic(&temporary, path);
    }
    let _ = fs::remove_file(&temporary);
}

/// Restores the tail of the log so the event page is not blank after a restart. A malformed line is
/// skipped rather than failing the load, and the displayed column keeps the time of day only.
fn load_event_log(path: &Path) -> VecDeque<EventEntry> {
    let Ok(text) = fs::read_to_string(path) else {
        return VecDeque::new();
    };
    let mut entries = text
        .lines()
        .rev()
        .take(EVENT_HISTORY)
        .filter_map(|line| {
            let (timestamp, message) = line.split_once('\t')?;
            let time = timestamp
                .split_once(' ')
                .map_or(timestamp, |(_, time)| time);
            Some(EventEntry {
                time: time.to_owned(),
                message: message.to_owned(),
            })
        })
        .collect::<Vec<_>>();
    entries.reverse();
    VecDeque::from(entries)
}

/// The common file dialog. Returns `None` when the user cancels, which is not an error.
///
/// `GetOpenFileNameW` is used rather than the newer `IFileDialog` because it needs no COM
/// initialisation on this thread and the picker here has no requirements beyond one path.
fn pick_file(title: &str, filter: &[&str], default_name: &str, save: bool) -> Option<PathBuf> {
    // The filter is a NUL-separated, double-NUL-terminated list of label/pattern pairs.
    let mut filter_wide = Vec::new();
    for part in filter {
        filter_wide.extend(part.encode_utf16());
        filter_wide.push(0);
    }
    filter_wide.push(0);
    let title = wide(title);
    // Must stay writable and NUL-terminated: the dialog writes the chosen path back into it.
    let mut buffer = vec![0_u16; 1024];
    for (slot, unit) in buffer.iter_mut().zip(default_name.encode_utf16()) {
        *slot = unit;
    }
    let mut options = OPENFILENAMEW {
        lStructSize: u32::try_from(size_of::<OPENFILENAMEW>()).unwrap_or(0),
        lpstrFilter: PCWSTR(filter_wide.as_ptr()),
        lpstrFile: PWSTR(buffer.as_mut_ptr()),
        nMaxFile: u32::try_from(buffer.len()).unwrap_or(0),
        lpstrTitle: PCWSTR(title.as_ptr()),
        Flags: if save {
            OFN_EXPLORER | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST
        } else {
            OFN_EXPLORER | OFN_HIDEREADONLY | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST
        },
        ..Default::default()
    };
    // SAFETY: every pointer field refers to a local that outlives the call, and the path buffer is
    // writable with its length declared in `nMaxFile`.
    let chosen = unsafe {
        if save {
            GetSaveFileNameW(&raw mut options)
        } else {
            GetOpenFileNameW(&raw mut options)
        }
    };
    if !chosen.as_bool() {
        return None;
    }
    let length = buffer.iter().position(|unit| *unit == 0).unwrap_or(0);
    (length > 0).then(|| PathBuf::from(String::from_utf16_lossy(&buffer[..length])))
}

const RULES_FILTER: [&str; 4] = ["规则文件 (*.json)", "*.json", "所有文件 (*.*)", "*.*"];

/// Writes the rule list, without the global thresholds, so a file can be shared without carrying
/// one machine's sampling settings to another.
fn export_rules(state: &RuntimeState) -> Result<PathBuf, String> {
    let config = state
        .config
        .lock()
        .map_err(|_| "配置状态已损坏".to_owned())?
        .clone();
    let Some(path) = pick_file("导出规则", &RULES_FILTER, "lazy-process-rules.json", true)
    else {
        return Err("已取消".into());
    };
    let text = serde_json::to_string_pretty(&config.rules).map_err(|error| error.to_string())?;
    fs::write(&path, text).map_err(|error| error.to_string())?;
    Ok(path)
}

/// Merges an exported file into the current configuration. Rules whose id already exists are
/// renamed rather than overwriting, so an import cannot silently replace something the user tuned.
fn import_rules(state: &RuntimeState) -> Result<Option<usize>, String> {
    let Some(path) = pick_file("导入规则", &RULES_FILTER, "", false) else {
        return Ok(None);
    };
    let text = fs::read_to_string(&path).map_err(|error| error.to_string())?;
    let imported: Vec<ProcessRule> =
        serde_json::from_str(&text).map_err(|error| format!("文件格式无法解析：{error}"))?;
    if imported.is_empty() {
        return Err("文件中没有规则".into());
    }
    let mut added = 0;
    let mut failure = None;
    mutate_config(state, |config| {
        for mut rule in imported {
            if config.rules.iter().any(|existing| existing.id == rule.id) {
                rule.id = unique_rule_id(config, &rule.id);
            }
            // An imported preset is no longer the built-in one, so it must stay deletable.
            rule.built_in = false;
            config.rules.push(rule);
            added += 1;
        }
        if let Err(error) = config.validate() {
            failure = Some(error.to_string());
        }
    });
    if let Some(error) = failure {
        // The rules were already merged, so undo by dropping exactly what was added.
        mutate_config(state, |config| {
            let keep = config.rules.len().saturating_sub(added);
            config.rules.truncate(keep);
        });
        return Err(format!("导入的规则无效，已撤销：{error}"));
    }
    Ok(Some(added))
}

fn read_registry_dword(subkey: &str, name: &str) -> Option<u32> {
    let subkey = wide(subkey);
    let name = wide(name);
    let mut value = 0_u32;
    let mut size = u32::try_from(size_of::<u32>()).ok()?;
    // SAFETY: both strings are NUL-terminated, and the out pointers match the requested size.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(name.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some((&raw mut value).cast()),
            Some(&raw mut size),
        )
    };
    status.is_ok().then_some(value)
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
    if enabled {
        let executable = std::env::current_exe().map_err(|error| error.to_string())?;
        // Quoted so a path containing spaces still starts as one command.
        write_registry_string(
            RUN_KEY,
            RUN_VALUE,
            Some(&format!("\"{}\"", executable.display())),
        )
    } else {
        write_registry_string(RUN_KEY, RUN_VALUE, None)
    }
}

/// What startup reconciliation should do about the autostart entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AutostartAction {
    /// Registry and configuration already agree.
    None,
    /// The entry exists but points somewhere else, so rewrite it to this executable.
    RewritePath,
    /// The entry is gone; the configuration should stop claiming otherwise.
    SyncConfigOff,
    /// The entry exists although the configuration says it should not.
    SyncConfigOn,
}

/// The registry, not the configuration file, decides whether the app really starts with Windows.
/// Another tool (or a reinstall into a new directory) can change it behind our back, and a checkbox
/// that disagrees with reality is worse than no checkbox.
fn autostart_action(
    stored: Option<&str>,
    configured: bool,
    expected: Option<&str>,
) -> AutostartAction {
    match (stored, configured) {
        (Some(stored), true) => {
            // A replacement character means the value did not survive decoding, so a comparison
            // would report a spurious mismatch and rewrite the entry on every start.
            let comparable = !stored.contains('\u{fffd}');
            match expected {
                Some(expected) if comparable && !stored.eq_ignore_ascii_case(expected) => {
                    AutostartAction::RewritePath
                }
                _ => AutostartAction::None,
            }
        }
        (None, true) => AutostartAction::SyncConfigOff,
        (Some(_), false) => AutostartAction::SyncConfigOn,
        (None, false) => AutostartAction::None,
    }
}

fn reconcile_start_with_windows(state: &RuntimeState) {
    let stored = read_registry_string(RUN_KEY, RUN_VALUE);
    let configured = state
        .config
        .lock()
        .is_ok_and(|config| config.start_with_windows);
    let expected = std::env::current_exe()
        .ok()
        .map(|path| format!("\"{}\"", path.display()));
    match autostart_action(stored.as_deref(), configured, expected.as_deref()) {
        AutostartAction::None => {}
        AutostartAction::RewritePath => match set_start_with_windows(true) {
            Ok(()) => push_event(state, "开机启动指向的路径已更新为当前程序".into()),
            Err(error) => push_event(state, format!("开机启动路径更新失败：{error}")),
        },
        AutostartAction::SyncConfigOff => {
            mutate_config(state, |config| config.start_with_windows = false);
            push_event(state, "开机启动项已被移除，设置已同步为关闭".into());
        }
        AutostartAction::SyncConfigOn => {
            mutate_config(state, |config| config.start_with_windows = true);
            push_event(state, "检测到已存在开机启动项，设置已同步为开启".into());
        }
    }
}

/// Writes or deletes a `REG_SZ` value under `HKEY_CURRENT_USER`. `None` deletes it, and deleting a
/// value that was never there is treated as success because it is the state the caller asked for.
fn write_registry_string(subkey: &str, name: &str, value: Option<&str>) -> Result<(), String> {
    let subkey = wide(subkey);
    let name = wide(name);
    let mut key = HKEY::default();
    unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &raw mut key,
            None,
        )
    }
    .ok()
    .map_err(|error| format!("无法打开启动项注册表键：{error}"))?;
    let result = match value {
        Some(value) => {
            let data = wide(value);
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    data.as_ptr().cast::<u8>(),
                    std::mem::size_of_val(&*data),
                )
            };
            unsafe { RegSetValueExW(key, PCWSTR(name.as_ptr()), None, REG_SZ, Some(bytes)) }
        }
        None => unsafe { RegDeleteValueW(key, PCWSTR(name.as_ptr())) },
    };
    let _ = unsafe { RegCloseKey(key) };
    if value.is_none() && result == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    result
        .ok()
        .map_err(|error| format!("注册表写入失败：{error}"))
}

/// Reads a `REG_SZ` value as UTF-16, which `reg.exe` output cannot round-trip for paths outside the
/// console code page.
fn read_registry_string(subkey: &str, name: &str) -> Option<String> {
    let subkey = wide(subkey);
    let name = wide(name);
    let mut size = 0_u32;
    unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(name.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&raw mut size),
        )
    }
    .ok()
    .ok()?;
    let mut buffer = vec![0_u16; (size as usize).div_ceil(2)];
    unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(name.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&raw mut size),
        )
    }
    .ok()
    .ok()?;
    let text = buffer
        .split(|unit| *unit == 0)
        .next()
        .map(String::from_utf16_lossy)?;
    Some(text)
}

fn wide(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Hands a duplicate launch over to the running instance. Auto-reset event, so the watcher wakes
/// exactly once per launch.
fn signal_running_instance() -> bool {
    let name = wide(SHOW_PANEL_EVENT);
    let Ok(event) = (unsafe {
        OpenEventW(
            windows::Win32::System::Threading::EVENT_MODIFY_STATE,
            false,
            PCWSTR(name.as_ptr()),
        )
    }) else {
        return false;
    };
    let signaled = unsafe { SetEvent(event) }.is_ok();
    let _ = unsafe { CloseHandle(event) };
    signaled
}

fn start_show_panel_watcher(panel: Weak<ControlPanel>, stop: Arc<AtomicBool>) {
    thread::spawn(move || {
        let name = wide(SHOW_PANEL_EVENT);
        let Ok(event) = (unsafe { CreateEventW(None, false, false, PCWSTR(name.as_ptr())) }) else {
            return;
        };
        // A bounded wait rather than an infinite one, so the thread notices shutdown on its own.
        while !stop.load(Ordering::Acquire) {
            if unsafe { WaitForSingleObject(event, 400) } == WAIT_OBJECT_0 {
                let weak = panel.clone();
                let _ = slint::invoke_from_event_loop(move || show_panel(&weak));
            }
        }
        let _ = unsafe { CloseHandle(event) };
    });
}

fn show_panel(weak: &Weak<ControlPanel>) {
    if let Some(panel) = weak.upgrade() {
        let _ = panel.show();
        panel.window().request_redraw();
    }
}

/// Drops a single trailing `.exe`, case-insensitively. `trim_end_matches` would strip repeated
/// suffixes ("a.exe.exe" to "a") and would not match ".EXE" at all.
fn strip_executable_suffix(value: &str) -> &str {
    let candidate = value.get(value.len().saturating_sub(4)..);
    if candidate.is_some_and(|suffix| suffix.eq_ignore_ascii_case(".exe")) {
        &value[..value.len() - 4]
    } else {
        value
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

/// Wall-clock time of day in the user's own time zone. Formatting the UTC epoch directly would
/// offset every event by the local UTC offset.
fn local_time_of_day() -> String {
    let now = unsafe { GetLocalTime() };
    format!("{:02}:{:02}:{:02}", now.wHour, now.wMinute, now.wSecond)
}

/// The log keeps the date as well, so a restored entry can still be placed on a calendar even
/// though the panel column only shows the time.
fn local_timestamp() -> String {
    let now = unsafe { GetLocalTime() };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond
    )
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
    fn executable_suffix_is_stripped_once_and_case_insensitively() {
        assert_eq!(strip_executable_suffix("Code.exe"), "Code");
        assert_eq!(strip_executable_suffix("Code.EXE"), "Code");
        assert_eq!(strip_executable_suffix("app.exe.exe"), "app.exe");
        assert_eq!(strip_executable_suffix("pwsh"), "pwsh");
        assert_eq!(strip_executable_suffix(".exe"), "");
        // Must not slice through a multi-byte character.
        assert_eq!(strip_executable_suffix("记事本"), "记事本");
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
                started_at_ticks: 1,
                executable_path: PathBuf::from(r"C:\bin\app.exe"),
            },
            root_name: "app.exe".into(),
            process_count: 1,
            state,
            quiet_seconds: 0,
            cpu_percent: 0.0,
            memory_bytes: 0,
            detail: String::new(),
            members: Vec::new(),
            next_action: None,
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

    #[test]
    fn sample_interval_stays_inside_the_validated_range() {
        assert_eq!(step_sample_interval(2, 1), 3);
        assert_eq!(step_sample_interval(1, -1), 1);
        assert_eq!(step_sample_interval(10, 1), 10);
        // A hand-edited value outside the range is pulled back in rather than saturating.
        assert_eq!(step_sample_interval(0, -1), 1);
        assert_eq!(step_sample_interval(99, 1), 10);
    }

    // Exact comparison is the point here: `step_cpu_threshold` rounds to one decimal place, so the
    // values it returns are expected to be exactly representable.
    #[allow(clippy::float_cmp)]
    #[test]
    fn cpu_threshold_steps_by_half_a_percent_and_clamps() {
        assert_eq!(step_cpu_threshold(1.0, 1), 1.5);
        assert_eq!(step_cpu_threshold(1.5, -1), 1.0);
        assert_eq!(step_cpu_threshold(0.0, -1), 0.0);
        assert_eq!(step_cpu_threshold(100.0, 1), 100.0);
        // Repeated stepping must not accumulate binary rounding error.
        let mut value = 0.0;
        for _ in 0..10 {
            value = step_cpu_threshold(value, 1);
        }
        assert_eq!(value, 5.0);
    }

    #[test]
    fn io_threshold_walks_the_ladder_from_off_ladder_values() {
        assert_eq!(step_io_threshold(0, 1), 1024);
        assert_eq!(step_io_threshold(4096, 1), 8192);
        assert_eq!(step_io_threshold(4096, -1), 2048);
        assert_eq!(step_io_threshold(0, -1), 0);
        assert_eq!(step_io_threshold(4 << 20, 1), 4 << 20);
        // 3000 bytes is on no rung; stepping moves to the neighbouring rungs.
        assert_eq!(step_io_threshold(3000, 1), 4096);
        assert_eq!(step_io_threshold(3000, -1), 2048);
        // Above the top rung, stepping down still lands on a valid rung.
        assert_eq!(step_io_threshold(8 << 20, -1), 4 << 20);
    }

    #[test]
    fn byte_sizes_use_the_largest_whole_unit() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(4096), "4 KiB");
        assert_eq!(format_bytes(1 << 20), "1 MiB");
        assert_eq!(format_bytes(4 << 20), "4 MiB");
    }

    #[test]
    fn rule_ids_do_not_collide() {
        let mut config = AppConfig {
            rules: Vec::new(),
            ..Default::default()
        };
        let first = unique_rule_id(&config, "code");
        assert_eq!(first, "app-code");
        config.rules.push(ProcessRule {
            id: first,
            ..Default::default()
        });
        let second = unique_rule_id(&config, "code");
        assert_eq!(second, "app-code-2");
        // An unnamed rule still gets a usable id.
        assert_eq!(unique_rule_id(&config, ""), "app-rule");
    }

    fn draft_rule(matcher: RuleMatcher) -> ProcessRule {
        ProcessRule {
            id: "app-test".into(),
            name: "Test".into(),
            matcher,
            ..Default::default()
        }
    }

    #[test]
    fn a_draft_without_any_selector_is_rejected() {
        let config = AppConfig {
            rules: Vec::new(),
            ..Default::default()
        };
        let rule = draft_rule(RuleMatcher {
            ancestor_process_name: Some("WindowsTerminal.exe".into()),
            ..Default::default()
        });
        let error = validate_rule_against(&config, None, &rule)
            .expect_err("an ancestor alone must not select processes");
        assert!(error.contains("至少需要一个"), "unexpected error: {error}");
    }

    #[test]
    fn a_draft_with_a_broken_regex_is_rejected_before_saving() {
        let config = AppConfig {
            rules: Vec::new(),
            ..Default::default()
        };
        let rule = draft_rule(RuleMatcher {
            command_regex: Some("(unclosed".into()),
            ..Default::default()
        });
        assert!(validate_rule_against(&config, None, &rule).is_err());
    }

    #[test]
    fn a_draft_with_one_condition_and_an_exclusion_is_accepted() {
        let config = AppConfig {
            rules: Vec::new(),
            ..Default::default()
        };
        let mut rule = draft_rule(RuleMatcher {
            command_contains: Some("--serve".into()),
            ancestor_process_name: Some("WindowsTerminal.exe".into()),
            ..Default::default()
        });
        rule.exclusions.push(RuleMatcher {
            path_contains: Some(r"\System32\".into()),
            ..Default::default()
        });
        validate_rule_against(&config, None, &rule).expect("draft should validate");
    }

    #[test]
    fn editing_a_missing_row_reports_instead_of_writing() {
        let config = AppConfig {
            rules: Vec::new(),
            ..Default::default()
        };
        let rule = draft_rule(RuleMatcher {
            process_name: Some("code.exe".into()),
            ..Default::default()
        });
        assert!(validate_rule_against(&config, Some(3), &rule).is_err());
    }

    /// A log path that removes itself when the test ends.
    struct TempLog(PathBuf);

    impl TempLog {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("lazy-process-test-{name}.log"));
            let _ = fs::remove_file(&path);
            Self(path)
        }
    }

    impl Drop for TempLog {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_file(self.0.with_extension("log.tmp"));
        }
    }

    #[test]
    fn events_survive_a_restart_and_keep_their_order() {
        let log = TempLog::new("events");
        for index in 0..3 {
            append_event_log(
                &log.0,
                &EventEntry {
                    time: "10:00:00".into(),
                    message: format!("事件 {index}"),
                },
            );
        }
        let restored = load_event_log(&log.0);
        assert_eq!(restored.len(), 3);
        assert_eq!(
            restored.front().map(|entry| entry.message.as_str()),
            Some("事件 0")
        );
        assert_eq!(
            restored.back().map(|entry| entry.message.as_str()),
            Some("事件 2")
        );
        // The stored timestamp carries the date; the panel column shows only the time.
        assert_eq!(restored[0].time.len(), "00:00:00".len());
    }

    #[test]
    fn a_missing_or_malformed_log_loads_as_empty_without_failing() {
        let log = TempLog::new("malformed");
        assert!(load_event_log(&log.0).is_empty());
        fs::write(&log.0, "no tab separator here\n").expect("write log");
        assert!(load_event_log(&log.0).is_empty());
    }

    #[test]
    fn a_long_log_is_trimmed_to_the_displayed_history() {
        let log = TempLog::new("trim");
        let mut text = String::new();
        for index in 0..(EVENT_HISTORY + 50) {
            let _ = writeln!(text, "2026-08-25 10:00:00\t事件 {index}");
        }
        fs::write(&log.0, text).expect("write log");
        trim_event_log(&log.0);
        let restored = load_event_log(&log.0);
        assert_eq!(restored.len(), EVENT_HISTORY);
        // Trimming keeps the newest entries.
        assert_eq!(
            restored.back().map(|entry| entry.message.as_str()),
            Some(format!("事件 {}", EVENT_HISTORY + 49).as_str())
        );
    }

    #[test]
    fn autostart_follows_the_registry_not_the_configuration() {
        let current = r#""C:\Apps\lazy-process.exe""#;
        // Agreement in both directions needs no action.
        assert_eq!(
            autostart_action(Some(current), true, Some(current)),
            AutostartAction::None
        );
        assert_eq!(
            autostart_action(None, false, Some(current)),
            AutostartAction::None
        );
        // Case differences in a Windows path are not a mismatch.
        assert_eq!(
            autostart_action(Some(r#""c:\apps\LAZY-PROCESS.exe""#), true, Some(current)),
            AutostartAction::None
        );
        // Moved or reinstalled elsewhere.
        assert_eq!(
            autostart_action(Some(r#""D:\Old\lazy-process.exe""#), true, Some(current)),
            AutostartAction::RewritePath
        );
        // Removed by another tool, or added by one.
        assert_eq!(
            autostart_action(None, true, Some(current)),
            AutostartAction::SyncConfigOff
        );
        assert_eq!(
            autostart_action(Some(current), false, Some(current)),
            AutostartAction::SyncConfigOn
        );
        // An undecodable stored value or an unknown executable must not trigger a rewrite loop.
        assert_eq!(
            autostart_action(Some("\"C:\\Apps\\lazy\u{fffd}.exe\""), true, Some(current)),
            AutostartAction::None
        );
        assert_eq!(
            autostart_action(Some(r#""D:\Old\lazy-process.exe""#), true, None),
            AutostartAction::None
        );
    }

    #[test]
    fn registry_strings_read_back_as_utf16() {
        // HKCU\Environment\TEMP exists on every Windows user profile and is only read here.
        let value = read_registry_string("Environment", "TEMP");
        assert!(value.is_some_and(|value| !value.is_empty()));
        assert!(read_registry_string("Environment", "LazyProcessMissingValue").is_none());
    }

    /// Writes to a scratch key of its own rather than the real `Run` key, and removes it again.
    #[test]
    fn registry_writes_round_trip_including_non_ascii_paths() {
        let subkey = r"Software\LazyProcessTest";
        let name = "RoundTrip";
        let value = r#""D:\程序 files\lazy-process.exe""#;
        write_registry_string(subkey, name, Some(value)).expect("write should succeed");
        assert_eq!(read_registry_string(subkey, name).as_deref(), Some(value));
        write_registry_string(subkey, name, None).expect("delete should succeed");
        assert!(read_registry_string(subkey, name).is_none());
        // Deleting twice is not an error.
        write_registry_string(subkey, name, None).expect("second delete should succeed");
        // Leave no scratch key behind in the user's registry.
        let wide_subkey = wide(subkey);
        let _ = unsafe {
            windows::Win32::System::Registry::RegDeleteKeyW(
                HKEY_CURRENT_USER,
                PCWSTR(wide_subkey.as_ptr()),
            )
        };
        assert!(read_registry_string(subkey, name).is_none());
    }

    #[test]
    fn times_round_trip_and_partial_input_is_rejected_without_losing_the_value() {
        assert_eq!(parse_minute("22:30"), Some(22 * 60 + 30));
        assert_eq!(parse_minute(" 6:05 "), Some(6 * 60 + 5));
        // A bare hour is accepted so the field is usable mid-typing.
        assert_eq!(parse_minute("9"), Some(9 * 60));
        assert_eq!(parse_minute("9:"), Some(9 * 60));
        assert_eq!(parse_minute("24:00"), None);
        assert_eq!(parse_minute("12:60"), None);
        assert_eq!(parse_minute(""), None);
        assert_eq!(parse_minute("abc"), None);

        assert_eq!(format_minute(0), "00:00");
        assert_eq!(format_minute(22 * 60 + 5), "22:05");
        assert_eq!(format_minute(1439), "23:59");
    }

    fn sample(pid: u32, name: &str, cpu: f32, memory: u64, threads: u32) -> ProcessSample {
        ProcessSample {
            identity: ProcessIdentity {
                pid,
                started_at: 1,
                started_at_ticks: 1,
                executable_path: PathBuf::from(format!(r"C:\bin\{name}")),
            },
            parent_pid: None,
            name: name.to_owned(),
            command_line: name.to_owned(),
            cpu_percent: cpu,
            io_bytes: 0,
            memory_bytes: memory,
            virtual_memory_bytes: memory * 2,
            run_time_seconds: 60,
            thread_count: threads,
            os_suspended: false,
        }
    }

    #[test]
    fn the_explorer_sorts_by_the_requested_column_in_both_directions() {
        let processes = [
            sample(30, "b.exe", 5.0, 300, 3),
            sample(10, "c.exe", 50.0, 100, 9),
            sample(20, "a.exe", 0.5, 200, 1),
        ];

        let mut rows = processes.iter().collect::<Vec<_>>();
        sort_processes(&mut rows, ProcessColumn::Cpu, true);
        assert_eq!(
            rows.iter().map(|row| row.identity.pid).collect::<Vec<_>>(),
            vec![10, 30, 20]
        );

        let mut rows = processes.iter().collect::<Vec<_>>();
        sort_processes(&mut rows, ProcessColumn::Name, false);
        assert_eq!(
            rows.iter().map(|row| row.name.as_str()).collect::<Vec<_>>(),
            vec!["a.exe", "b.exe", "c.exe"]
        );

        let mut rows = processes.iter().collect::<Vec<_>>();
        sort_processes(&mut rows, ProcessColumn::Memory, true);
        assert_eq!(
            rows.iter().map(|row| row.memory_bytes).collect::<Vec<_>>(),
            vec![300, 200, 100]
        );

        let mut rows = processes.iter().collect::<Vec<_>>();
        sort_processes(&mut rows, ProcessColumn::Threads, false);
        assert_eq!(
            rows.iter().map(|row| row.thread_count).collect::<Vec<_>>(),
            vec![1, 3, 9]
        );
    }

    #[test]
    fn the_explorer_filter_matches_name_path_and_pid() {
        let process = sample(1234, "code.exe", 1.0, 100, 4);
        assert!(process_matches(&process, ""));
        assert!(process_matches(&process, "code"));
        assert!(process_matches(&process, "CODE"));
        assert!(process_matches(&process, "1234"));
        assert!(process_matches(&process, r"c:\bin"));
        // Every term has to match, so two words narrow rather than widen.
        assert!(process_matches(&process, "code bin"));
        assert!(!process_matches(&process, "code missing"));
        assert!(!process_matches(&process, "notepad"));
    }

    #[test]
    fn a_new_sort_column_starts_descending_only_where_that_reads_better() {
        assert!(ProcessColumn::from_index(2).defaults_to_descending());
        assert!(ProcessColumn::from_index(3).defaults_to_descending());
        assert!(ProcessColumn::from_index(4).defaults_to_descending());
        assert!(!ProcessColumn::from_index(1).defaults_to_descending());
        assert!(!ProcessColumn::from_index(0).defaults_to_descending());
        // An index the UI does not have falls back to the default column rather than panicking.
        assert_eq!(ProcessColumn::from_index(99), ProcessColumn::Cpu);
    }

    #[test]
    fn failures_are_flagged_in_the_event_log() {
        let error = EventEntry {
            time: "10:00:00".into(),
            message: "结束 app.exe (PID 10) 失败：拒绝访问".into(),
        };
        assert!(error.is_error());
        let disabled = EventEntry {
            time: "10:00:00".into(),
            message: "上次进程状态恢复失败，监控已停用：x".into(),
        };
        assert!(disabled.is_error());
        let routine = EventEntry {
            time: "10:00:00".into(),
            message: "app.exe (PID 10) → 低耗".into(),
        };
        assert!(!routine.is_error());
    }

    #[test]
    fn run_times_and_waits_stay_short_enough_for_their_columns() {
        assert_eq!(format_run_time(30), "0 分");
        assert_eq!(format_run_time(90 * 60), "1 时 30 分");
        assert_eq!(format_run_time(50 * 3600), "2 天 2 时");
        assert_eq!(format_wait(45), "45 秒");
        // Rounded up, so a countdown never displays as "0 分" while still waiting.
        assert_eq!(format_wait(61), "2 分");
    }
}
