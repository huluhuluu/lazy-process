use crate::{
    config::{application_lease_path, journal_candidate_paths, replace_file_atomic},
    engine::ResourceController,
    model::{ProcessIdentity, ProcessSample, SystemSnapshot},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    ffi::c_void,
    fs,
    io::{self, Write},
    os::windows::{fs::OpenOptionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_ALREADY_EXISTS, ERROR_INVALID_PARAMETER, ERROR_PIPE_CONNECTED,
            FILETIME, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, HLOCAL, HWND, LPARAM,
            LocalFree, STILL_ACTIVE, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_SHARE_NONE,
            OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION,
            SECURITY_SQOS_PRESENT, WriteFile,
        },
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                TH32CS_SNAPPROCESS,
            },
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
                GetNamedPipeServerProcessId, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_TYPE_MESSAGE, PIPE_WAIT, PeekNamedPipe,
            },
            ProcessStatus::EmptyWorkingSet,
            SystemInformation::GetLocalTime,
            Threading::{
                BELOW_NORMAL_PRIORITY_CLASS, CreateEventW, EVENT_MODIFY_STATE, ExitProcess,
                GetExitCodeProcess, GetPriorityClass, GetProcessId, GetProcessInformation,
                GetProcessTimes, INFINITE, OpenEventW, OpenProcess, PROCESS_ACCESS_RIGHTS,
                PROCESS_NAME_FORMAT, PROCESS_POWER_THROTTLING_CURRENT_VERSION,
                PROCESS_POWER_THROTTLING_EXECUTION_SPEED, PROCESS_POWER_THROTTLING_STATE,
                PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION, PROCESS_SET_QUOTA,
                PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE, ProcessPowerThrottling,
                QueryFullProcessImageNameW, SYNCHRONIZATION_ACCESS_RIGHTS, SetEvent,
                SetPriorityClass, SetProcessInformation, TerminateProcess, WaitForSingleObject,
            },
        },
        UI::Shell::{
            QUNS_BUSY, QUNS_PRESENTATION_MODE, QUNS_RUNNING_D3D_FULL_SCREEN, SEE_MASK_FLAG_NO_UI,
            SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
            SHQueryUserNotificationState, ShellExecuteExW,
        },
        UI::WindowsAndMessaging::{
            EnumWindows, GetForegroundWindow, GetWindowThreadProcessId, IsHungAppWindow, SW_HIDE,
        },
    },
    core::{BOOL, HRESULT, HSTRING, PCWSTR, PWSTR},
};

const WINDOWS_TO_UNIX_SECONDS: u64 = 11_644_473_600;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const PROCESS_SYNCHRONIZE: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0010_0000);
const EVENT_SYNCHRONIZE: SYNCHRONIZATION_ACCESS_RIGHTS = SYNCHRONIZATION_ACCESS_RIGHTS(0x0010_0000);
const JOURNAL_LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const BROKER_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const HELPER_READY_TIMEOUT: Duration = Duration::from_secs(45);
const WATCHDOG_READY_TIMEOUT: Duration = Duration::from_secs(5);
const HELPER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const ERROR_SHARING_VIOLATION_CODE: i32 = 32;
static JOURNAL_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

unsafe extern "system" {
    fn NtSuspendProcess(process: HANDLE) -> i32;
    fn NtResumeProcess(process: HANDLE) -> i32;
}

#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(
        algorithm: *mut c_void,
        buffer: *mut u8,
        buffer_length: u32,
        flags: u32,
    ) -> i32;
}

const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

#[derive(Debug)]
pub struct ProcessSampler {
    system: System,
    own_pid: u32,
    metadata: HashMap<(u32, u64, u64), CachedProcessMetadata>,
}

#[derive(Debug, Clone)]
struct CachedProcessMetadata {
    executable_path: PathBuf,
    parent_pid: Option<u32>,
    name: String,
    command_line: String,
}

impl ProcessSampler {
    #[must_use]
    pub fn new() -> Self {
        Self {
            system: System::new(),
            own_pid: std::process::id(),
            metadata: HashMap::new(),
        }
    }

    pub fn sample(&mut self) -> Vec<ProcessSample> {
        // `System::refresh_processes` leaves `cmd` at `UpdateKind::Never`, which would make every
        // command line empty and silently disable the command matchers. Request it explicitly;
        // `OnlyIfNotSet` reads each command line once and then reuses it.
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory()
                .with_disk_usage()
                .with_exe(UpdateKind::OnlyIfNotSet)
                .with_cmd(UpdateKind::OnlyIfNotSet),
        );
        let mut present = HashSet::new();
        let mut samples = Vec::with_capacity(self.system.processes().len());
        for (pid, process) in self.system.processes() {
            let pid = pid.as_u32();
            if pid == self.own_pid {
                continue;
            }
            let started_at = process.start_time();
            let Some(executable_path) = process.exe() else {
                continue;
            };
            let Some(started_at_ticks) = exact_process_start_ticks(pid) else {
                continue;
            };
            let key = (pid, started_at, started_at_ticks);
            present.insert(key);
            let command_line = || {
                process
                    .cmd()
                    .iter()
                    .map(|part| part.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            let entry = self
                .metadata
                .entry(key)
                .or_insert_with(|| CachedProcessMetadata {
                    executable_path: executable_path.to_path_buf(),
                    parent_pid: process.parent().map(sysinfo::Pid::as_u32),
                    name: process.name().to_string_lossy().into_owned(),
                    command_line: command_line(),
                });
            // A command line can be momentarily unreadable when a process is very young or the
            // machine is busy. Caching that empty result would disable this process's command
            // matchers for its whole lifetime, so keep retrying until one arrives.
            if entry.command_line.is_empty() {
                entry.command_line = command_line();
            }
            let metadata = entry.clone();
            let disk = process.disk_usage();
            samples.push(ProcessSample {
                identity: ProcessIdentity {
                    pid,
                    started_at,
                    started_at_ticks,
                    executable_path: metadata.executable_path,
                },
                parent_pid: metadata.parent_pid,
                name: metadata.name,
                command_line: metadata.command_line,
                cpu_percent: process.cpu_usage(),
                io_bytes: disk
                    .total_read_bytes
                    .saturating_add(disk.total_written_bytes),
                memory_bytes: process.memory(),
                virtual_memory_bytes: process.virtual_memory(),
                run_time_seconds: process.run_time(),
                thread_count: 0,
                os_suspended: false,
            });
        }
        self.metadata.retain(|key, _| present.contains(key));
        // sysinfo does not expose a thread count on Windows, so fill it in from a single toolhelp
        // snapshot rather than opening one handle per process.
        let threads = thread_counts();
        if !threads.is_empty() {
            for sample in &mut samples {
                sample.thread_count = threads.get(&sample.identity.pid).copied().unwrap_or(0);
            }
        }
        samples
    }

    /// Machine-wide totals for the explorer header. Uses the CPU and memory data refreshed by
    /// `sample`, so call it right after a sample rather than on its own.
    pub fn system_snapshot(&mut self, samples: &[ProcessSample]) -> SystemSnapshot {
        self.system.refresh_memory();
        let cpu_count = std::thread::available_parallelism().map_or(0, std::num::NonZero::get);
        // Per-process CPU is reported per core by sysinfo, so a saturated 16-core machine sums to
        // 1600. Normalise to a machine-wide percentage instead of reading the global CPU list,
        // which would need its own refresh and a warm-up interval.
        let busy: f32 = samples.iter().map(|sample| sample.cpu_percent).sum();
        let cpu_percent = if cpu_count == 0 {
            busy
        } else {
            #[allow(clippy::cast_precision_loss)]
            let divisor = cpu_count as f32;
            (busy / divisor).min(100.0)
        };
        SystemSnapshot {
            cpu_percent,
            memory_used_bytes: self.system.used_memory(),
            memory_total_bytes: self.system.total_memory(),
            process_count: samples.len(),
            cpu_count,
        }
    }
}

/// Thread count per pid from one toolhelp snapshot. Returns an empty map on failure, which the
/// caller treats as "unknown" rather than "no threads".
fn thread_counts() -> HashMap<u32, u32> {
    let mut counts = HashMap::new();
    let Ok(snapshot) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return counts;
    };
    let snapshot = OwnedHandle(snapshot);
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(size_of::<PROCESSENTRY32W>()).unwrap_or(0),
        ..Default::default()
    };
    // SAFETY: the snapshot handle is live and `entry` is a correctly sized local.
    if unsafe { Process32FirstW(snapshot.0, &raw mut entry) }.is_err() {
        return counts;
    }
    loop {
        counts.insert(entry.th32ProcessID, entry.cntThreads);
        // SAFETY: same invariants as the first call; iteration stops on the first error.
        if unsafe { Process32NextW(snapshot.0, &raw mut entry) }.is_err() {
            break;
        }
    }
    counts
}

/// True when the user is presenting, gaming full screen, or otherwise should not be interrupted.
/// Used to hold off throttling: a full-screen game makes every background group look idle.
#[must_use]
pub fn user_is_busy() -> bool {
    // SAFETY: the shell call takes no input and writes one out parameter.
    match unsafe { SHQueryUserNotificationState() } {
        Ok(state) => {
            state == QUNS_BUSY
                || state == QUNS_PRESENTATION_MODE
                || state == QUNS_RUNNING_D3D_FULL_SCREEN
        }
        // Session 0 and locked desktops fail here. Reporting "not busy" keeps the normal
        // schedule running instead of silently pausing all management.
        Err(_) => false,
    }
}

/// Local minute of day and weekday, with Sunday as 0, for rule schedules.
#[must_use]
pub fn local_minute_and_weekday() -> (u16, u8) {
    // SAFETY: GetLocalTime only writes to its returned struct.
    let now = unsafe { GetLocalTime() };
    let minute = now.wHour.saturating_mul(60).saturating_add(now.wMinute);
    (minute, u8::try_from(now.wDayOfWeek).unwrap_or(0))
}

fn exact_process_start_ticks(pid: u32) -> Option<u64> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let handle = OwnedHandle(handle);
    process_start_ticks(handle.0).ok()
}

fn identity_key(identity: &ProcessIdentity) -> (u32, u64, u64) {
    (identity.pid, identity.started_at, identity.started_at_ticks)
}

impl Default for ProcessSampler {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
pub fn foreground_process_id() -> Option<u32> {
    // SAFETY: foreground HWND is owned by the OS; the PID out pointer is valid for the call.
    unsafe {
        let window: HWND = GetForegroundWindow();
        if window.0.is_null() {
            return None;
        }
        let mut pid = 0;
        GetWindowThreadProcessId(window, Some(&raw mut pid));
        (pid != 0).then_some(pid)
    }
}

#[must_use]
pub fn unresponsive_process_ids() -> HashSet<u32> {
    unsafe extern "system" fn visit(window: HWND, context: LPARAM) -> BOOL {
        // SAFETY: EnumWindows receives a pointer to a live HashSet for the duration of the call.
        let hung = unsafe { &mut *(context.0 as *mut HashSet<u32>) };
        if unsafe { IsHungAppWindow(window) }.as_bool() {
            let mut pid = 0;
            unsafe { GetWindowThreadProcessId(window, Some(&raw mut pid)) };
            if pid != 0 {
                hung.insert(pid);
            }
        }
        true.into()
    }

    let mut hung = HashSet::new();
    let context = LPARAM((&raw mut hung).cast::<c_void>() as isize);
    // SAFETY: callback and context stay valid until EnumWindows returns.
    let _ = unsafe { EnumWindows(Some(visit), context) };
    hung
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspensionRecord {
    pub identity: ProcessIdentity,
    #[serde(default)]
    priority_class: u32,
    #[serde(default)]
    power_control_mask: u32,
    #[serde(default)]
    power_state_mask: u32,
    #[serde(default)]
    power_state_recorded: bool,
    #[serde(default = "legacy_record_was_suspended")]
    suspended: bool,
    #[serde(default)]
    original_state_recorded: bool,
}

const fn legacy_record_was_suspended() -> bool {
    true
}

#[derive(Debug)]
enum JournalLoadError {
    Read(io::Error),
    Invalid(serde_json::Error),
}

impl std::fmt::Display for JournalLoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(error) => write!(formatter, "恢复日志读取失败：{error}"),
            Self::Invalid(error) => write!(formatter, "恢复日志无效：{error}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BrokerAction {
    Throttle,
    Suspend,
    Restore,
    RestoreAll,
}

#[derive(Debug, Serialize, Deserialize)]
struct BrokerRequest {
    action: BrokerAction,
    processes: Vec<ProcessIdentity>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BrokerResponse {
    error: Option<String>,
}

#[derive(Debug)]
struct ElevatedBroker {
    requests: mpsc::Sender<BrokerCall>,
    process: OwnedHandle,
    cancel_event: OwnedHandle,
    stop: Arc<AtomicBool>,
}

#[derive(Debug)]
struct BrokerCall {
    action: BrokerAction,
    processes: Vec<ProcessIdentity>,
    response: mpsc::SyncSender<Result<(), String>>,
}

#[derive(Debug)]
struct ElevatedBrokerConnection {
    pipe: OwnedHandle,
    stop: Arc<AtomicBool>,
}

impl ElevatedBrokerConnection {
    fn send(&mut self, action: BrokerAction, processes: &[ProcessIdentity]) -> Result<(), String> {
        if self.is_cancelled() {
            return Err("管理员辅助进程连接已取消".to_owned());
        }
        let request = BrokerRequest {
            action,
            processes: processes.to_vec(),
        };
        write_frame(
            self.pipe.0,
            &serde_json::to_vec(&request).map_err(|error| error.to_string())?,
        )?;
        let response: BrokerResponse = serde_json::from_slice(&self.read_frame_until_response()?)
            .map_err(|error| error.to_string())?;
        response.error.map_or(Ok(()), Err)
    }

    fn is_cancelled(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    fn read_frame_until_response(&self) -> Result<Vec<u8>, String> {
        let mut length = [0_u8; 4];
        self.read_exact_until_response(&mut length)?;
        let length = usize::try_from(u32::from_le_bytes(length)).unwrap_or(usize::MAX);
        if length > 1024 * 1024 {
            return Err("本地管道消息超过 1 MiB 上限".into());
        }
        let mut payload = vec![0; length];
        self.read_exact_until_response(&mut payload)?;
        Ok(payload)
    }

    fn read_exact_until_response(&self, buffer: &mut [u8]) -> Result<(), String> {
        let mut offset = 0;
        while offset < buffer.len() {
            if self.is_cancelled() {
                return Err("管理员辅助进程连接已取消".to_owned());
            }
            let mut available = 0;
            unsafe { PeekNamedPipe(self.pipe.0, None, 0, None, Some(&raw mut available), None) }
                .map_err(|error| error.to_string())?;
            let remaining = u32::try_from(buffer.len() - offset).unwrap_or(u32::MAX);
            if available < remaining {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            let mut read = 0;
            unsafe {
                ReadFile(
                    self.pipe.0,
                    Some(&mut buffer[offset..]),
                    Some(&raw mut read),
                    None,
                )
            }
            .map_err(|error| error.to_string())?;
            if read == 0 {
                return Err("本地管道连接已关闭".into());
            }
            offset = offset.saturating_add(usize::try_from(read).unwrap_or(0));
        }
        Ok(())
    }
}

impl ElevatedBroker {
    fn new(pipe: OwnedHandle, process: OwnedHandle, cancel_event: OwnedHandle) -> Self {
        let (requests, receiver) = mpsc::channel::<BrokerCall>();
        let stop = Arc::new(AtomicBool::new(false));
        let mut connection = ElevatedBrokerConnection {
            pipe,
            stop: stop.clone(),
        };
        thread::spawn(move || {
            while !connection.stop.load(Ordering::Acquire) {
                match receiver.recv_timeout(Duration::from_millis(50)) {
                    Ok(call) => {
                        let result = connection.send(call.action, &call.processes);
                        let _ = call.response.send(result);
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });
        Self {
            requests,
            process,
            cancel_event,
            stop,
        }
    }

    fn send(&mut self, action: BrokerAction, processes: &[ProcessIdentity]) -> Result<(), String> {
        self.send_with_timeout(action, processes, BROKER_RESPONSE_TIMEOUT)
    }

    fn send_with_timeout(
        &mut self,
        action: BrokerAction,
        processes: &[ProcessIdentity],
        timeout: Duration,
    ) -> Result<(), String> {
        if self.stop.load(Ordering::Acquire) {
            return Err("管理员辅助进程连接已关闭".to_owned());
        }
        let (response, receiver) = mpsc::sync_channel(1);
        self.requests
            .send(BrokerCall {
                action,
                processes: processes.to_vec(),
                response,
            })
            .map_err(|_| "管理员辅助进程连接已关闭".to_owned())?;
        receiver
            .recv_timeout(timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => "管理员辅助进程响应超时".to_owned(),
                mpsc::RecvTimeoutError::Disconnected => "管理员辅助进程连接已关闭".to_owned(),
            })?
    }

    fn is_alive(&self) -> bool {
        let mut exit_code = 0;
        unsafe { GetExitCodeProcess(self.process.0, &raw mut exit_code) }.is_ok()
            && exit_code == STILL_ACTIVE.0.cast_unsigned()
    }
}

impl Drop for ElevatedBroker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = unsafe { SetEvent(self.cancel_event.0) };
        let timeout = u32::try_from(HELPER_SHUTDOWN_TIMEOUT.as_millis()).unwrap_or(u32::MAX);
        if unsafe { WaitForSingleObject(self.process.0, timeout) } != WAIT_OBJECT_0 {
            let _ = unsafe { TerminateProcess(self.process.0, 1) };
        }
    }
}

#[derive(Debug)]
pub struct WindowsResourceController {
    originals: HashMap<(u32, u64, u64), SuspensionRecord>,
    journal_path: PathBuf,
    journal_lease: Option<JournalLease>,
    journal_loaded: bool,
    elevated: Option<ElevatedBroker>,
    elevated_owned: HashSet<(u32, u64, u64)>,
}

impl WindowsResourceController {
    #[must_use]
    pub fn new(journal_path: PathBuf) -> Self {
        let mut controller = Self {
            originals: HashMap::new(),
            journal_path,
            journal_lease: None,
            journal_loaded: false,
            elevated: None,
            elevated_owned: HashSet::new(),
        };
        let _ = controller.ensure_journal_loaded();
        controller
    }

    fn ensure_journal_loaded(&mut self) -> Result<(), String> {
        if self.journal_loaded {
            return Ok(());
        }
        if self.journal_lease.is_none() {
            // A lock failure is transient: a previous instance's watchdog may still be recovering.
            // Report it to the caller but retry on the next call instead of disabling the
            // controller for the rest of the session.
            match JournalLease::acquire(&self.journal_path, JOURNAL_LOCK_TIMEOUT) {
                Ok(lease) => self.journal_lease = Some(lease),
                Err(error) => return Err(format!("恢复日志锁定失败：{error}")),
            }
        }
        let records =
            read_journal_records(&self.journal_path).map_err(|error| error.to_string())?;
        for record in records {
            let key = identity_key(&record.identity);
            self.originals.entry(key).or_insert(record);
        }
        self.journal_loaded = true;
        Ok(())
    }

    fn remember(&mut self, identity: &ProcessIdentity, handle: HANDLE) -> Result<bool, String> {
        let key = identity_key(identity);
        if self.originals.contains_key(&key) {
            return Ok(false);
        }
        let priority_class = unsafe { GetPriorityClass(handle) };
        if priority_class == 0 {
            return Err(format!(
                "PID {} 原始优先级读取失败：{}",
                identity.pid,
                windows::core::Error::from_thread()
            ));
        }
        let mut power = PROCESS_POWER_THROTTLING_STATE {
            Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
            ControlMask: 0,
            StateMask: 0,
        };
        let power_state_recorded = unsafe {
            GetProcessInformation(
                handle,
                ProcessPowerThrottling,
                (&raw mut power).cast::<c_void>(),
                u32::try_from(size_of::<PROCESS_POWER_THROTTLING_STATE>()).unwrap_or(u32::MAX),
            )
        }
        .is_ok();
        self.originals.insert(
            key,
            SuspensionRecord {
                identity: identity.clone(),
                priority_class,
                power_control_mask: power.ControlMask,
                power_state_mask: power.StateMask,
                power_state_recorded,
                suspended: false,
                original_state_recorded: true,
            },
        );
        Ok(true)
    }

    fn write_journal(&self) -> io::Result<()> {
        if !self.journal_loaded {
            return Err(io::Error::other("现有恢复日志尚未成功读取，拒绝覆盖原文件"));
        }
        let records = self.originals.values().cloned().collect::<Vec<_>>();
        write_journal_records(&self.journal_path, &records)
    }

    fn rollback_failed_suspend(
        &mut self,
        key: (u32, u64, u64),
        inserted: bool,
        was_suspended: bool,
    ) -> io::Result<()> {
        if inserted {
            self.originals.remove(&key);
        } else if let Some(state) = self.originals.get_mut(&key) {
            state.suspended = was_suspended;
        }
        self.write_journal()
    }

    fn open_verified(
        identity: &ProcessIdentity,
        access: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS,
    ) -> Result<OwnedHandle, String> {
        let handle = unsafe {
            OpenProcess(
                access | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                identity.pid,
            )
        }
        .map_err(|error| format!("PID {} 无法访问：{error}", identity.pid))?;
        let handle = OwnedHandle(handle);
        verify_identity(handle.0, identity)?;
        Ok(handle)
    }

    fn send_elevated(
        &mut self,
        action: BrokerAction,
        processes: &[ProcessIdentity],
    ) -> Result<(), String> {
        let result = self
            .elevated
            .as_mut()
            .ok_or_else(|| "管理员辅助进程尚未启用".to_owned())?
            .send(action, processes);
        if result.is_err() {
            self.elevated.take();
            self.elevated_owned.clear();
        }
        result
    }

    #[cfg(test)]
    fn send_elevated_with_timeout(
        &mut self,
        action: BrokerAction,
        processes: &[ProcessIdentity],
        timeout: Duration,
    ) -> Result<(), String> {
        let result = self
            .elevated
            .as_mut()
            .ok_or_else(|| "管理员辅助进程尚未启用".to_owned())?
            .send_with_timeout(action, processes, timeout);
        if result.is_err() {
            self.elevated.take();
            self.elevated_owned.clear();
        }
        result
    }

    fn handoff_to_elevated(
        &mut self,
        action: BrokerAction,
        candidates: Vec<(ProcessIdentity, String)>,
    ) -> Vec<String> {
        if self.elevated.is_none() {
            return candidates.into_iter().map(|(_, error)| error).collect();
        }

        let mut errors = Vec::new();
        let mut identities = Vec::new();
        for (identity, source_error) in candidates {
            let key = identity_key(&identity);
            if self.originals.contains_key(&key)
                && let Err(error) = self.restore_one(key)
            {
                errors.push(format!(
                    "PID {} 无法在转交管理员辅助进程前恢复普通权限状态：{error}；原错误：{source_error}",
                    identity.pid
                ));
                continue;
            }
            identities.push(identity);
        }
        if !identities.is_empty() {
            match self.send_elevated(action, &identities) {
                Ok(()) => {
                    self.elevated_owned
                        .extend(identities.iter().map(identity_key));
                }
                Err(error) => errors.push(format!("管理员辅助进程：{error}")),
            }
        }
        errors
    }

    /// Terminates a process on an explicit user request. Deliberately not part of
    /// [`ResourceController`]: the engine never kills anything, only a click in the explorer does.
    /// The identity is re-verified against the handle first, so a pid recycled between the click
    /// and this call cannot be hit by mistake.
    pub fn terminate_process(&mut self, identity: &ProcessIdentity) -> Result<(), String> {
        let handle = Self::open_verified(identity, PROCESS_TERMINATE)?;
        // SAFETY: the handle is live and verified to be the process the user selected.
        unsafe { TerminateProcess(handle.0, 1) }
            .map_err(|error| format!("PID {} 无法结束：{error}", identity.pid))?;
        // A journal entry for a dead process is harmless, because restore re-verifies the identity
        // before touching anything. Drop it anyway so the recovery pass has nothing to retry.
        let key = identity_key(identity);
        if self.originals.remove(&key).is_some() {
            let _ = self.write_journal();
        }
        self.elevated_owned.remove(&key);
        Ok(())
    }

    fn restore_one(&mut self, key: (u32, u64, u64)) -> Result<(), String> {
        let Some(mut original) = self.originals.get(&key).cloned() else {
            return Ok(());
        };
        let mut errors = Vec::new();
        while record_needs_restore(&original) {
            let stage = restore_record_stage(&mut original);
            self.originals.insert(key, original.clone());
            if let Err(error) = self.write_journal() {
                errors.push(format!("恢复日志进度写入失败：{error}"));
                break;
            }
            if let Err(error) = stage {
                errors.push(error);
                break;
            }
        }

        if errors.is_empty() && !record_needs_restore(&original) {
            self.originals.remove(&key);
            if let Err(error) = self.write_journal() {
                self.originals.insert(key, original);
                errors.push(format!("恢复日志清理失败：{error}"));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("；"))
        }
    }
}

impl ResourceController for WindowsResourceController {
    fn throttle(&mut self, processes: &[ProcessIdentity]) -> Result<(), String> {
        self.ensure_journal_loaded()?;
        let mut errors = Vec::new();
        let mut elevated = Vec::new();
        let mut pending = Vec::new();
        // Record every original state first, then persist the whole batch with a single write.
        // A journal entry for a process that has not been touched yet is safe: recovery only
        // restores it to the value already stored there.
        for identity in processes {
            if self.elevated_owned.contains(&identity_key(identity)) {
                elevated.push((identity.clone(), "进程当前由管理员辅助进程管理".into()));
                continue;
            }
            match Self::open_verified(identity, PROCESS_SET_INFORMATION) {
                Ok(handle) => match self.remember(identity, handle.0) {
                    Ok(inserted) => pending.push((identity.clone(), handle, inserted)),
                    Err(error) => elevated.push((identity.clone(), error)),
                },
                Err(error) => elevated.push((identity.clone(), error)),
            }
        }

        if !pending.is_empty()
            && let Err(error) = self.write_journal()
        {
            for (identity, _, inserted) in &pending {
                if *inserted {
                    self.originals.remove(&identity_key(identity));
                }
            }
            let _ = self.write_journal();
            errors.push(format!("恢复日志写入失败：{error}"));
            pending.clear();
        }

        for (identity, handle, _) in pending {
            if let Err(error) = unsafe { SetPriorityClass(handle.0, BELOW_NORMAL_PRIORITY_CLASS) } {
                errors.push(format!("PID {}：{error}", identity.pid));
                continue;
            }
            if self
                .originals
                .get(&identity_key(&identity))
                .is_some_and(|record| record.power_state_recorded)
            {
                let power = PROCESS_POWER_THROTTLING_STATE {
                    Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
                    ControlMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
                    StateMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
                };
                if let Err(error) = unsafe {
                    SetProcessInformation(
                        handle.0,
                        ProcessPowerThrottling,
                        (&raw const power).cast::<c_void>(),
                        u32::try_from(size_of::<PROCESS_POWER_THROTTLING_STATE>())
                            .unwrap_or(u32::MAX),
                    )
                } {
                    errors.push(format!("PID {} 电源状态设置失败：{error}", identity.pid));
                }
            }
        }

        if !elevated.is_empty() {
            errors.extend(self.handoff_to_elevated(BrokerAction::Throttle, elevated));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("；"))
        }
    }

    fn suspend(&mut self, processes: &[ProcessIdentity]) -> Result<(), String> {
        self.ensure_journal_loaded()?;
        let mut errors = Vec::new();
        let mut elevated = Vec::new();
        let mut pending = Vec::new();
        // Mark the whole batch as suspended and persist it with a single write before suspending
        // anything, so a crash mid-batch always leaves a journal that covers every process.
        for identity in processes {
            if self.elevated_owned.contains(&identity_key(identity)) {
                elevated.push((identity.clone(), "进程当前由管理员辅助进程管理".into()));
                continue;
            }
            match Self::open_verified(identity, PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION) {
                Ok(handle) => {
                    let key = identity_key(identity);
                    let inserted = match self.remember(identity, handle.0) {
                        Ok(inserted) => inserted,
                        Err(error) => {
                            elevated.push((identity.clone(), error));
                            continue;
                        }
                    };
                    if self
                        .originals
                        .get(&key)
                        .is_some_and(|state| state.suspended)
                    {
                        continue;
                    }
                    if let Some(state) = self.originals.get_mut(&key) {
                        state.suspended = true;
                    }
                    pending.push((identity.clone(), handle, inserted));
                }
                Err(error) => elevated.push((identity.clone(), error)),
            }
        }

        if !pending.is_empty()
            && let Err(error) = self.write_journal()
        {
            for (identity, _, inserted) in &pending {
                let key = identity_key(identity);
                if *inserted {
                    self.originals.remove(&key);
                } else if let Some(state) = self.originals.get_mut(&key) {
                    state.suspended = false;
                }
            }
            let _ = self.write_journal();
            errors.push(format!("恢复日志写入失败：{error}"));
            pending.clear();
        }

        // Suspend roots before descendants to prevent new children from appearing mid-operation.
        for (identity, handle, inserted) in pending {
            let status = unsafe { NtSuspendProcess(handle.0) };
            if status < 0 {
                let failure = format!("PID {} 暂停失败：NTSTATUS {status:#x}", identity.pid);
                if let Err(error) =
                    self.rollback_failed_suspend(identity_key(&identity), inserted, false)
                {
                    errors.push(format!("{failure}；恢复日志回滚失败：{error}"));
                } else {
                    elevated.push((identity.clone(), failure));
                }
            }
        }

        if !elevated.is_empty() {
            errors.extend(self.handoff_to_elevated(BrokerAction::Suspend, elevated));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("；"))
        }
    }

    fn restore(&mut self, processes: &[ProcessIdentity]) -> Result<(), String> {
        let mut errors = Vec::new();
        let elevated = processes
            .iter()
            .filter(|identity| self.elevated_owned.contains(&identity_key(identity)))
            .cloned()
            .collect::<Vec<_>>();
        if !elevated.is_empty() {
            match self.send_elevated(BrokerAction::Restore, &elevated) {
                Ok(()) => {
                    for identity in &elevated {
                        self.elevated_owned.remove(&identity_key(identity));
                    }
                }
                Err(error) => errors.push(format!("管理员辅助进程：{error}")),
            }
        }
        match self.ensure_journal_loaded() {
            Ok(()) => {
                let requested = processes.iter().map(identity_key).collect::<HashSet<_>>();
                let keys = self
                    .originals
                    .keys()
                    .filter(|key| requested.contains(key))
                    .copied()
                    .collect::<Vec<_>>();
                // NtResumeProcess is safe for either order once the whole group is ready.
                for key in keys {
                    if let Err(error) = self.restore_one(key) {
                        errors.push(error);
                    }
                }
            }
            Err(error) => errors.push(error),
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("；"))
        }
    }

    fn restore_all(&mut self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.elevated.is_some() {
            match self.send_elevated(BrokerAction::RestoreAll, &[]) {
                Ok(()) => self.elevated_owned.clear(),
                Err(error) => errors.push(format!("管理员辅助进程：{error}")),
            }
        }
        match self.ensure_journal_loaded() {
            Ok(()) => {
                let keys = self.originals.keys().copied().collect::<Vec<_>>();
                errors.extend(
                    keys.into_iter()
                        .filter_map(|key| self.restore_one(key).err()),
                );
            }
            Err(error) => errors.push(error),
        }
        errors
    }

    fn trim_working_set(&mut self, processes: &[ProcessIdentity]) -> Result<(), String> {
        let mut errors = Vec::new();
        for identity in processes {
            // PROCESS_SET_QUOTA is what EmptyWorkingSet needs. It is not part of
            // PROCESS_SET_INFORMATION, so ask for it explicitly.
            let handle = match Self::open_verified(identity, PROCESS_SET_QUOTA) {
                Ok(handle) => handle,
                Err(error) => {
                    errors.push(error);
                    continue;
                }
            };
            // SAFETY: the handle is live, verified to be the intended process, and opened with
            // PROCESS_SET_QUOTA. Pages are written to the page file, not discarded.
            if let Err(error) = unsafe { EmptyWorkingSet(handle.0) } {
                errors.push(format!("PID {} 内存回收失败：{error}", identity.pid));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("；"))
        }
    }

    fn enable_elevation(&mut self) -> Result<(), String> {
        if self
            .elevated
            .as_ref()
            .is_some_and(|broker| !broker.is_alive())
        {
            self.elevated.take();
            self.elevated_owned.clear();
        }
        if self.elevated.is_none() {
            self.elevated = Some(start_elevated_broker(&self.journal_path)?);
        }
        Ok(())
    }
}

impl Drop for WindowsResourceController {
    fn drop(&mut self) {
        let _ = self.restore_all();
    }
}

#[derive(Debug)]
struct OwnedHandle(HANDLE);

// SAFETY: Windows kernel handles are process-wide. OwnedHandle has unique ownership and is only
// moved between threads, so its Drop still closes the handle exactly once.
unsafe impl Send for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[derive(Debug)]
struct PendingHelper {
    process: Option<OwnedHandle>,
}

impl PendingHelper {
    fn new(process: OwnedHandle) -> Self {
        Self {
            process: Some(process),
        }
    }

    fn handle(&self) -> HANDLE {
        self.process
            .as_ref()
            .map_or(HANDLE::default(), |process| process.0)
    }

    fn into_process(mut self) -> Result<OwnedHandle, String> {
        self.process
            .take()
            .ok_or_else(|| "管理员辅助进程句柄已释放".to_owned())
    }
}

impl Drop for PendingHelper {
    fn drop(&mut self) {
        if let Some(process) = &self.process {
            let _ = unsafe { TerminateProcess(process.0, 1) };
        }
    }
}

#[derive(Debug)]
struct JournalLease {
    _file: fs::File,
}

#[derive(Debug)]
pub struct ApplicationLease {
    _file: fs::File,
}

#[derive(Debug)]
struct LocalAllocation(HLOCAL);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(Some(self.0));
        }
    }
}

fn create_cross_account_event(name: &str) -> Result<OwnedHandle, String> {
    let sddl = HSTRING::from("D:(A;;GA;;;BA)(A;;GA;;;SY)(A;;GA;;;OW)");
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
    }
    .map_err(|error| format!("无法创建管理员取消事件安全描述符：{error}"))?;
    let allocation = LocalAllocation(HLOCAL(descriptor.0));
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };
    let name = HSTRING::from(name);
    let event = unsafe {
        CreateEventW(
            Some(&raw mut attributes),
            true,
            false,
            PCWSTR(name.as_ptr()),
        )
    }
    .map_err(|error| format!("无法创建管理员协作事件：{error}"))?;
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        drop(OwnedHandle(event));
        return Err("管理员协作事件名称已被占用".into());
    }
    drop(allocation);
    Ok(OwnedHandle(event))
}

fn wait_for_helper_ready(
    ready_event: HANDLE,
    process: HANDLE,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        match unsafe { WaitForSingleObject(process, 0) } {
            WAIT_OBJECT_0 => return Err("管理员辅助进程在就绪前已退出".into()),
            WAIT_TIMEOUT => {}
            result => return Err(format!("检查管理员辅助进程状态失败：{result:?}")),
        }
        match unsafe { WaitForSingleObject(ready_event, 0) } {
            WAIT_OBJECT_0 => return Ok(()),
            WAIT_TIMEOUT => {}
            result => return Err(format!("等待管理员辅助进程就绪事件失败：{result:?}")),
        }
        if Instant::now() >= deadline {
            return Err(format!("管理员辅助进程未在 {} 秒内就绪", timeout.as_secs()));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

impl JournalLease {
    fn acquire(journal_path: &Path, timeout: Duration) -> io::Result<Self> {
        acquire_file_lease(journal_path, timeout).map(|file| Self { _file: file })
    }
}

pub fn acquire_application_lease(timeout: Duration) -> io::Result<ApplicationLease> {
    acquire_file_lease(&application_lease_path(), timeout)
        .map(|file| ApplicationLease { _file: file })
}

fn acquire_file_lease(path: &Path, timeout: Duration) -> io::Result<fs::File> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let lock_path = path.with_extension("lock");
    let deadline = Instant::now() + timeout;
    loop {
        match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .open(&lock_path)
        {
            Ok(file) => return Ok(file),
            Err(error)
                if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION_CODE)
                    && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error),
        }
    }
}

fn start_elevated_broker(journal_path: &Path) -> Result<ElevatedBroker, String> {
    let parent_pid = std::process::id();
    let parent_started_at_ticks =
        exact_process_start_ticks(parent_pid).ok_or_else(|| "无法确认主进程启动时间".to_owned())?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let pipe_name = format!(r"\\.\pipe\lazy-process-{parent_pid}-{nonce:x}");
    let cancel_event_name = format!("Local\\LazyProcessHelperCancel-{parent_pid}-{nonce:x}");
    let ready_event_name = format!("Local\\LazyProcessHelperReady-{parent_pid}-{nonce:x}");
    let cancel_event = create_cross_account_event(&cancel_event_name)?;
    let ready_event = create_cross_account_event(&ready_event_name)?;
    let elevated_journal = elevated_journal_path(journal_path);
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let parameters = format!(
        "--elevated-helper {parent_pid} {parent_started_at_ticks} \"{pipe_name}\" \"{cancel_event_name}\" \"{ready_event_name}\" \"{}\"",
        elevated_journal.display()
    );
    let operation = HSTRING::from("runas");
    let executable = HSTRING::from(executable.as_path());
    let parameters = HSTRING::from(parameters);
    let mut execute_info = SHELLEXECUTEINFOW {
        cbSize: u32::try_from(size_of::<SHELLEXECUTEINFOW>()).unwrap_or(u32::MAX),
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: PCWSTR(operation.as_ptr()),
        lpFile: PCWSTR(executable.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    unsafe { ShellExecuteExW(&raw mut execute_info) }
        .map_err(|error| format!("管理员授权被取消或无法启动辅助进程：{error}"))?;
    if execute_info.hProcess.is_invalid() {
        return Err("管理员辅助进程未返回有效句柄".into());
    }
    let pending_helper = PendingHelper::new(OwnedHandle(execute_info.hProcess));
    let helper_pid = unsafe { GetProcessId(pending_helper.handle()) };
    if helper_pid == 0 {
        return Err("无法确认管理员辅助进程 PID".into());
    }

    let pipe_name = HSTRING::from(pipe_name);
    for _ in 0..150 {
        if unsafe { WaitForSingleObject(pending_helper.handle(), 0) } == WAIT_OBJECT_0 {
            return Err("管理员辅助进程在建立连接前已退出".into());
        }
        let pipe = unsafe {
            CreateFileW(
                PCWSTR(pipe_name.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                None,
            )
        };
        if let Ok(pipe) = pipe {
            let pipe = OwnedHandle(pipe);
            let mut server_pid = 0;
            unsafe { GetNamedPipeServerProcessId(pipe.0, &raw mut server_pid) }
                .map_err(|error| format!("无法确认管理员管道服务进程：{error}"))?;
            if server_pid != helper_pid {
                return Err(format!(
                    "管理员管道服务进程不匹配：预期 PID {helper_pid}，实际 PID {server_pid}"
                ));
            }
            wait_for_helper_ready(ready_event.0, pending_helper.handle(), HELPER_READY_TIMEOUT)?;
            match unsafe { WaitForSingleObject(pending_helper.handle(), 0) } {
                WAIT_TIMEOUT => {}
                WAIT_OBJECT_0 => return Err("管理员辅助进程在就绪握手后已退出".into()),
                result => return Err(format!("确认管理员辅助进程存活失败：{result:?}")),
            }
            let process = pending_helper.into_process()?;
            return Ok(ElevatedBroker::new(pipe, process, cancel_event));
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err("管理员辅助进程未在 30 秒内建立本地连接".into())
}

pub fn run_elevated_helper(
    expected_client_pid: u32,
    expected_client_started_at_ticks: u64,
    pipe_name: &str,
    cancel_event_name: &str,
    ready_event_name: &str,
    journal_path: &Path,
) -> Result<(), String> {
    if !journal_path.is_absolute()
        || journal_path.file_name() != Some(std::ffi::OsStr::new("suspended-elevated.json"))
    {
        return Err("拒绝管理员辅助进程使用非应用恢复日志路径".into());
    }
    let pipe_name = HSTRING::from(pipe_name);
    let pipe = unsafe {
        CreateNamedPipeW(
            PCWSTR(pipe_name.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            64 * 1024,
            64 * 1024,
            0,
            None,
        )
    };
    if pipe.is_invalid() {
        return Err(windows::core::Error::from_thread().to_string());
    }
    let pipe = OwnedHandle(pipe);
    if let Err(error) = unsafe { ConnectNamedPipe(pipe.0, None) }
        && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED
    {
        return Err(error.to_string());
    }
    let mut client_pid = 0;
    unsafe { GetNamedPipeClientProcessId(pipe.0, &raw mut client_pid) }
        .map_err(|error| format!("无法确认本地管道客户端：{error}"))?;
    if client_pid != expected_client_pid {
        return Err(format!(
            "拒绝未知本地管道客户端：预期 PID {expected_client_pid}，实际 PID {client_pid}"
        ));
    }
    verify_elevated_client(expected_client_pid, expected_client_started_at_ticks)?;

    let cancel_event_name = HSTRING::from(cancel_event_name);
    let cancel_event =
        unsafe { OpenEventW(EVENT_SYNCHRONIZE, false, PCWSTR(cancel_event_name.as_ptr())) }
            .map_err(|error| format!("无法打开管理员取消事件：{error}"))?;
    let cancel_event = OwnedHandle(cancel_event);
    let ready_event_name = HSTRING::from(ready_event_name);
    let ready_event =
        unsafe { OpenEventW(EVENT_MODIFY_STATE, false, PCWSTR(ready_event_name.as_ptr())) }
            .map_err(|error| format!("无法打开管理员就绪事件：{error}"))?;
    let ready_event = OwnedHandle(ready_event);

    let _watchdog = spawn_watchdog(journal_path, WatchdogRecovery::SingleJournal)
        .map_err(|error| format!("无法启动管理员恢复守护进程：{error}"))?;
    let recovery_errors = recover_suspended(journal_path);
    if !recovery_errors.is_empty() {
        return Err(recovery_errors.join("；"));
    }

    let mut controller = WindowsResourceController::new(journal_path.to_path_buf());
    controller.ensure_journal_loaded()?;
    unsafe { SetEvent(ready_event.0) }
        .map_err(|error| format!("无法通知管理员辅助进程已就绪：{error}"))?;
    run_elevated_requests(pipe.0, cancel_event.0, &mut controller)?;
    let errors = controller.restore_all();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("；"))
    }
}

fn run_elevated_requests(
    pipe: HANDLE,
    cancel_event: HANDLE,
    controller: &mut WindowsResourceController,
) -> Result<(), String> {
    loop {
        if unsafe { WaitForSingleObject(cancel_event, 0) } == WAIT_OBJECT_0 {
            let _ = controller.restore_all();
            unsafe { ExitProcess(0) };
        }
        let mut available = 0;
        if unsafe { PeekNamedPipe(pipe, None, 0, None, Some(&raw mut available), None) }.is_err() {
            break;
        }
        if available == 0 {
            thread::sleep(Duration::from_millis(10));
            continue;
        }
        let Ok(frame) = read_frame(pipe) else { break };
        let response = match serde_json::from_slice::<BrokerRequest>(&frame) {
            Ok(request) => {
                let result = match request.action {
                    BrokerAction::Throttle => controller.throttle(&request.processes),
                    BrokerAction::Suspend => controller.suspend(&request.processes),
                    BrokerAction::Restore => controller.restore(&request.processes),
                    BrokerAction::RestoreAll => {
                        let errors = controller.restore_all();
                        if errors.is_empty() {
                            Ok(())
                        } else {
                            Err(errors.join("；"))
                        }
                    }
                };
                BrokerResponse {
                    error: result.err(),
                }
            }
            Err(error) => BrokerResponse {
                error: Some(format!("管理员请求无效：{error}")),
            },
        };
        let bytes = serde_json::to_vec(&response).map_err(|error| error.to_string())?;
        write_frame(pipe, &bytes)?;
    }
    Ok(())
}

fn verify_elevated_client(expected_pid: u32, expected_started_at_ticks: u64) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, expected_pid) }
        .map_err(|error| format!("无法验证主进程：{error}"))?;
    let handle = OwnedHandle(handle);
    verify_application_process(handle.0, expected_started_at_ticks)
}

fn verify_application_process(
    handle: HANDLE,
    expected_started_at_ticks: u64,
) -> Result<(), String> {
    if expected_started_at_ticks == 0 {
        return Err("父进程缺少精确启动时间".into());
    }
    if process_start_ticks(handle)? != expected_started_at_ticks {
        return Err("主进程 PID 已被复用".into());
    }
    let actual = query_process_image_path(handle)?;
    let expected = std::env::current_exe().map_err(|error| error.to_string())?;
    if !actual
        .as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.as_os_str().to_string_lossy())
    {
        return Err("拒绝非 Lazy Process 主程序连接管理员辅助进程".into());
    }
    Ok(())
}

fn current_parent_pid() -> Option<u32> {
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::All, true);
    system
        .process(sysinfo::Pid::from_u32(std::process::id()))
        .and_then(sysinfo::Process::parent)
        .map(sysinfo::Pid::as_u32)
}

fn write_frame(pipe: HANDLE, payload: &[u8]) -> Result<(), String> {
    let length = u32::try_from(payload.len()).map_err(|_| "本地管道消息过大".to_owned())?;
    write_all(pipe, &length.to_le_bytes())?;
    write_all(pipe, payload)
}

fn write_all(pipe: HANDLE, mut payload: &[u8]) -> Result<(), String> {
    while !payload.is_empty() {
        let mut written = 0;
        unsafe { WriteFile(pipe, Some(payload), Some(&raw mut written), None) }
            .map_err(|error| error.to_string())?;
        if written == 0 {
            return Err("本地管道连接已关闭".into());
        }
        payload = &payload[usize::try_from(written).unwrap_or(payload.len())..];
    }
    Ok(())
}

fn read_frame(pipe: HANDLE) -> Result<Vec<u8>, String> {
    let mut length = [0_u8; 4];
    read_exact(pipe, &mut length)?;
    let length = usize::try_from(u32::from_le_bytes(length)).unwrap_or(usize::MAX);
    if length > 1024 * 1024 {
        return Err("本地管道消息超过 1 MiB 上限".into());
    }
    let mut payload = vec![0; length];
    read_exact(pipe, &mut payload)?;
    Ok(payload)
}

fn read_exact(pipe: HANDLE, mut buffer: &mut [u8]) -> Result<(), String> {
    while !buffer.is_empty() {
        let mut read = 0;
        unsafe { ReadFile(pipe, Some(buffer), Some(&raw mut read), None) }
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("本地管道连接已关闭".into());
        }
        let offset = usize::try_from(read).unwrap_or(buffer.len());
        buffer = &mut buffer[offset..];
    }
    Ok(())
}

fn verify_identity(handle: HANDLE, expected: &ProcessIdentity) -> Result<(), String> {
    if identity_matches(handle, expected)? {
        Ok(())
    } else {
        Err(format!("PID {} 已退出或被其他进程复用", expected.pid))
    }
}

fn identity_matches(handle: HANDLE, expected: &ProcessIdentity) -> Result<bool, String> {
    let started_at_ticks = process_start_ticks(handle)?;
    if expected.started_at_ticks != 0 && started_at_ticks != expected.started_at_ticks {
        return Ok(false);
    }
    if expected.started_at_ticks == 0
        && filetime_ticks_unix_seconds(started_at_ticks) != expected.started_at
    {
        return Ok(false);
    }
    let actual = query_process_image_path(handle)?;
    if !actual
        .as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.executable_path.as_os_str().to_string_lossy())
    {
        return Ok(false);
    }
    Ok(true)
}

fn query_process_image_path(handle: HANDLE) -> Result<PathBuf, String> {
    let mut buffer = vec![0_u16; 32_768];
    let mut length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
    unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT::default(),
            PWSTR(buffer.as_mut_ptr()),
            &raw mut length,
        )
    }
    .map_err(|error| error.to_string())?;
    Ok(PathBuf::from(String::from_utf16_lossy(
        &buffer[..usize::try_from(length).unwrap_or(0)],
    )))
}

fn process_start_ticks(handle: HANDLE) -> Result<u64, String> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(
            handle,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    }
    .map_err(|error| error.to_string())?;
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

fn filetime_ticks_unix_seconds(ticks: u64) -> u64 {
    ticks
        .saturating_div(10_000_000)
        .saturating_sub(WINDOWS_TO_UNIX_SECONDS)
}

fn record_needs_restore(record: &SuspensionRecord) -> bool {
    record.suspended || record.original_state_recorded
}

fn restore_record_stage(record: &mut SuspensionRecord) -> Result<(), String> {
    if !record_needs_restore(record) {
        return Ok(());
    }
    let access = if record.suspended {
        PROCESS_SUSPEND_RESUME
    } else {
        PROCESS_SET_INFORMATION
    };
    let handle = match WindowsResourceController::open_verified(&record.identity, access) {
        Ok(handle) => handle,
        Err(error) => {
            if identity_is_gone_or_reused(&record.identity) {
                record.suspended = false;
                record.original_state_recorded = false;
                return Ok(());
            }
            return Err(error);
        }
    };
    if record.suspended {
        let status = unsafe { NtResumeProcess(handle.0) };
        if status < 0 {
            return Err(format!(
                "PID {} 恢复失败：NTSTATUS {status:#x}",
                record.identity.pid
            ));
        }
        record.suspended = false;
        return Ok(());
    }

    let mut errors = Vec::new();
    if record.original_state_recorded {
        let mut original_state_restored = true;
        if record.priority_class != 0
            && let Err(error) = unsafe {
                SetPriorityClass(
                    handle.0,
                    windows::Win32::System::Threading::PROCESS_CREATION_FLAGS(
                        record.priority_class,
                    ),
                )
            }
        {
            original_state_restored = false;
            errors.push(format!(
                "PID {} 优先级恢复失败：{error}",
                record.identity.pid
            ));
        }
        if record.power_state_recorded {
            let power = PROCESS_POWER_THROTTLING_STATE {
                Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
                ControlMask: record.power_control_mask | PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
                StateMask: record.power_state_mask,
            };
            if let Err(error) = unsafe {
                SetProcessInformation(
                    handle.0,
                    ProcessPowerThrottling,
                    (&raw const power).cast::<c_void>(),
                    u32::try_from(size_of::<PROCESS_POWER_THROTTLING_STATE>()).unwrap_or(u32::MAX),
                )
            } {
                original_state_restored = false;
                errors.push(format!(
                    "PID {} 电源状态恢复失败：{error}",
                    record.identity.pid
                ));
            }
        }
        if original_state_restored {
            record.original_state_recorded = false;
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("；"))
    }
}

fn identity_is_gone_or_reused(expected: &ProcessIdentity) -> bool {
    let handle =
        match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, expected.pid) } {
            Ok(handle) => OwnedHandle(handle),
            Err(error) => {
                return error.code() == HRESULT::from_win32(ERROR_INVALID_PARAMETER.0);
            }
        };
    let mut exit_code = 0;
    match unsafe { GetExitCodeProcess(handle.0, &raw mut exit_code) } {
        Ok(()) if exit_code != STILL_ACTIVE.0.cast_unsigned() => true,
        Ok(()) => matches!(identity_matches(handle.0, expected), Ok(false)),
        Err(_) => false,
    }
}

fn read_journal_records(journal_path: &Path) -> Result<Vec<SuspensionRecord>, JournalLoadError> {
    let bytes = match fs::read(journal_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(JournalLoadError::Read(error)),
    };
    serde_json::from_slice(&bytes).map_err(JournalLoadError::Invalid)
}

fn write_journal_records(journal_path: &Path, records: &[SuspensionRecord]) -> io::Result<()> {
    if records.is_empty() {
        return match fs::remove_file(journal_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        };
    }
    if let Some(parent) = journal_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let sequence = JOURNAL_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let temporary = journal_path.with_extension(format!(
        "json.{}.{nonce:x}.{sequence}.tmp",
        std::process::id()
    ));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec_pretty(records).map_err(io::Error::other)?)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        replace_file_atomic(&temporary, journal_path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn recover_records_with(
    journal_path: &Path,
    mut records: Vec<SuspensionRecord>,
    mut restore_stage: impl FnMut(&mut SuspensionRecord) -> Result<(), String>,
) -> Vec<String> {
    let mut errors = Vec::new();
    if records.is_empty() {
        if let Err(error) = write_journal_records(journal_path, &records) {
            errors.push(format!("恢复日志清理失败：{error}"));
        }
        return errors;
    }
    let mut index = 0;
    while index < records.len() {
        let mut stage_failed = false;
        while record_needs_restore(&records[index]) {
            let restore_error = restore_stage(&mut records[index]).err();
            if let Err(error) = write_journal_records(journal_path, &records) {
                errors.extend(restore_error);
                errors.push(format!("恢复日志进度写入失败：{error}"));
                return errors;
            }
            if let Some(error) = restore_error {
                errors.push(error);
                stage_failed = true;
                break;
            }
        }

        if stage_failed || record_needs_restore(&records[index]) {
            index += 1;
        } else {
            // Keep a completed marker on disk before removing it. A failed cleanup therefore
            // cannot cause a later recovery to repeat either restoration stage.
            let completed = records.remove(index);
            if let Err(error) = write_journal_records(journal_path, &records) {
                records.insert(index, completed);
                errors.push(format!("恢复日志清理失败：{error}"));
                break;
            }
        }
    }
    errors
}

#[must_use]
pub fn recover_suspended(journal_path: &Path) -> Vec<String> {
    let _lease = match JournalLease::acquire(journal_path, JOURNAL_LOCK_TIMEOUT) {
        Ok(lease) => lease,
        Err(error) => return vec![format!("恢复日志锁定失败：{error}")],
    };
    let records = match read_journal_records(journal_path) {
        Ok(records) => records,
        Err(error) => return vec![error.to_string()],
    };
    recover_records_with(journal_path, records, restore_record_stage)
}

#[must_use]
pub fn recover_all_suspended(journal_paths: &[PathBuf]) -> Vec<String> {
    recover_all_suspended_with(journal_paths, restore_record_stage)
}

fn recover_all_suspended_with(
    journal_paths: &[PathBuf],
    mut restore_stage: impl FnMut(&mut SuspensionRecord) -> Result<(), String>,
) -> Vec<String> {
    let mut seen_paths = HashSet::new();
    let paths = journal_paths
        .iter()
        .filter(|path| seen_paths.insert((*path).clone()))
        .cloned()
        .collect::<Vec<_>>();
    let mut lock_paths = paths.clone();
    lock_paths.sort();
    let mut leases = Vec::with_capacity(lock_paths.len());
    let mut errors = Vec::new();
    for path in &lock_paths {
        match JournalLease::acquire(path, JOURNAL_LOCK_TIMEOUT) {
            Ok(lease) => leases.push(lease),
            Err(error) => {
                errors.push(format!("{}：恢复日志锁定失败：{error}", path.display()));
                return errors;
            }
        }
    }

    let mut resumed = HashSet::new();
    for path in &paths {
        let mut records = match read_journal_records(path) {
            Ok(records) => records,
            Err(error) => {
                errors.push(format!("{}：{error}", path.display()));
                continue;
            }
        };
        for record in &mut records {
            if resumed.contains(&identity_key(&record.identity)) {
                record.suspended = false;
            }
        }
        let path_errors = recover_records_with(path, records, |record| {
            let was_suspended = record.suspended;
            let result = restore_stage(record);
            if was_suspended && !record.suspended {
                resumed.insert(identity_key(&record.identity));
            }
            result
        });
        errors.extend(
            path_errors
                .into_iter()
                .map(|error| format!("{}：{error}", path.display())),
        );
    }
    drop(leases);
    errors
}

#[must_use]
pub fn elevated_journal_path(journal_path: &Path) -> PathBuf {
    journal_path.with_file_name("suspended-elevated.json")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogRecovery {
    AllJournals,
    SingleJournal,
}

impl WatchdogRecovery {
    #[must_use]
    pub const fn argument(self) -> &'static str {
        match self {
            Self::AllJournals => "all",
            Self::SingleJournal => "single",
        }
    }
}

fn watchdog_ready_event_name() -> io::Result<String> {
    let mut nonce = [0_u8; size_of::<u128>()];
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            nonce.as_mut_ptr(),
            u32::try_from(nonce.len()).unwrap_or(u32::MAX),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(io::Error::other(format!(
            "无法生成 watchdog 就绪事件随机名称：NTSTATUS 0x{:08x}",
            status.cast_unsigned()
        )));
    }
    Ok(format!(
        "Local\\LazyProcessWatchdogReady-{}-{:032x}",
        std::process::id(),
        u128::from_le_bytes(nonce)
    ))
}

fn create_watchdog_ready_event(name: &str) -> io::Result<OwnedHandle> {
    let name = HSTRING::from(name);
    let event = unsafe { CreateEventW(None, true, false, PCWSTR(name.as_ptr())) }?;
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        drop(OwnedHandle(event));
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "watchdog 就绪事件名称已被占用",
        ));
    }
    Ok(OwnedHandle(event))
}

pub fn spawn_watchdog(journal_path: &Path, recovery: WatchdogRecovery) -> io::Result<Child> {
    let ready_event_name = watchdog_ready_event_name()?;
    let ready_event = create_watchdog_ready_event(&ready_event_name)?;
    let parent_started_at_ticks = exact_process_start_ticks(std::process::id())
        .ok_or_else(|| io::Error::other("无法确认 watchdog 父进程启动时间"))?;
    let mut child = Command::new(std::env::current_exe()?)
        .arg("--watchdog")
        .arg(std::process::id().to_string())
        .arg(parent_started_at_ticks.to_string())
        .arg(&ready_event_name)
        .arg(recovery.argument())
        .arg(journal_path)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + WATCHDOG_READY_TIMEOUT;
    loop {
        match unsafe { WaitForSingleObject(ready_event.0, 0) } {
            WAIT_OBJECT_0 => return Ok(child),
            WAIT_TIMEOUT => {}
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::other(format!(
                    "等待 watchdog 就绪事件失败：{result:?}"
                )));
            }
        }
        if let Some(status) = child.try_wait()? {
            return Err(io::Error::other(format!(
                "watchdog 在认证父进程前退出：{status}"
            )));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "watchdog 未在 5 秒内完成父进程认证",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

pub fn run_watchdog(
    parent_pid: u32,
    parent_started_at_ticks: u64,
    ready_event_name: &str,
    recovery: WatchdogRecovery,
    journal_path: &Path,
) -> Result<(), String> {
    let trusted_name = journal_path.file_name().is_some_and(|name| {
        name == std::ffi::OsStr::new("suspended.json")
            || name == std::ffi::OsStr::new("suspended-elevated.json")
    });
    if !journal_path.is_absolute() || !trusted_name {
        return Err("拒绝 watchdog 使用非应用恢复日志路径".into());
    }
    if current_parent_pid() != Some(parent_pid) {
        return Err("拒绝非父进程启动 watchdog".into());
    }
    let parent = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            parent_pid,
        )
    }
    .map_err(|error| format!("无法验证 watchdog 父进程 PID {parent_pid}：{error}"))?;
    let parent = OwnedHandle(parent);
    verify_application_process(parent.0, parent_started_at_ticks)?;
    let ready_event_name = HSTRING::from(ready_event_name);
    let ready_event =
        unsafe { OpenEventW(EVENT_MODIFY_STATE, false, PCWSTR(ready_event_name.as_ptr())) }
            .map_err(|error| format!("无法打开 watchdog 就绪事件：{error}"))?;
    let ready_event = OwnedHandle(ready_event);
    unsafe { SetEvent(ready_event.0) }
        .map_err(|error| format!("无法通知 watchdog 已就绪：{error}"))?;
    let result = unsafe { WaitForSingleObject(parent.0, INFINITE) };
    if result != WAIT_OBJECT_0 {
        return Err(format!("等待主进程失败：{result:?}"));
    }
    let errors = match recovery {
        WatchdogRecovery::AllJournals => {
            let _application_lease = acquire_application_lease(JOURNAL_LOCK_TIMEOUT)
                .map_err(|error| format!("无法取得应用恢复所有权：{error}"))?;
            recover_all_suspended(&journal_candidate_paths())
        }
        WatchdogRecovery::SingleJournal => recover_suspended(journal_path),
    };
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("；"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn spawn_sleeping_pwsh(seconds: u32) -> Child {
        Command::new("pwsh.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-Command",
                &format!("Start-Sleep -Seconds {seconds}"),
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .expect("pwsh test child should start")
    }

    fn identity_for(pid: u32) -> ProcessIdentity {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut sampler = ProcessSampler::new();
        loop {
            if let Some(sample) = sampler
                .sample()
                .into_iter()
                .find(|sample| sample.identity.pid == pid)
            {
                return sample.identity;
            }
            assert!(
                Instant::now() < deadline,
                "test child did not appear in sampler"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// A journal path that removes itself, and the `.lock` file `acquire_file_lease` creates
    /// alongside it, when the test ends. Without this every run leaves stray files in TEMP.
    struct TestJournal(PathBuf);

    impl TestJournal {
        fn new(name: &str) -> Self {
            Self(
                std::env::temp_dir()
                    .join(format!("lazy-process-{name}-{}.json", std::process::id())),
            )
        }
    }

    impl std::ops::Deref for TestJournal {
        type Target = Path;

        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl AsRef<Path> for TestJournal {
        fn as_ref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestJournal {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_dir(&self.0);
            let _ = fs::remove_file(self.0.with_extension("lock"));
        }
    }

    fn test_journal(name: &str) -> TestJournal {
        TestJournal::new(name)
    }

    fn test_record(pid: u32) -> SuspensionRecord {
        SuspensionRecord {
            identity: ProcessIdentity {
                pid,
                started_at: u64::from(pid),
                started_at_ticks: u64::from(pid),
                executable_path: PathBuf::from(format!(r"C:\missing\process-{pid}.exe")),
            },
            priority_class: 1,
            power_control_mask: 0,
            power_state_mask: 0,
            power_state_recorded: false,
            suspended: true,
            original_state_recorded: true,
        }
    }

    fn simulate_controller_crash(mut controller: WindowsResourceController) {
        drop(controller.journal_lease.take());
        std::mem::forget(controller);
    }

    fn power_state_for(identity: &ProcessIdentity) -> PROCESS_POWER_THROTTLING_STATE {
        let handle =
            WindowsResourceController::open_verified(identity, PROCESS_ACCESS_RIGHTS(0)).unwrap();
        let mut power = PROCESS_POWER_THROTTLING_STATE {
            Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
            ControlMask: 0,
            StateMask: 0,
        };
        unsafe {
            GetProcessInformation(
                handle.0,
                ProcessPowerThrottling,
                (&raw mut power).cast::<c_void>(),
                u32::try_from(size_of::<PROCESS_POWER_THROTTLING_STATE>()).unwrap(),
            )
            .unwrap();
        }
        power
    }

    /// `System::refresh_processes` leaves `cmd` at `UpdateKind::Never`, which would make every
    /// sampled command line empty and silently break the `command_contains` / `command_regex`
    /// matchers.
    #[test]
    fn sampled_processes_carry_their_command_line() {
        let mut child = spawn_sleeping_pwsh(20);
        let identity = identity_for(child.id());
        let mut sampler = ProcessSampler::new();

        // A busy machine can briefly fail to yield a command line; the sampler must not cache
        // that empty result, so retrying has to converge.
        let mut found = String::new();
        let mut population = (0, 0);
        for _ in 0..10 {
            let batch = sampler.sample();
            population = (
                batch
                    .iter()
                    .filter(|entry| !entry.command_line.is_empty())
                    .count(),
                batch.len(),
            );
            if let Some(entry) = batch
                .iter()
                .find(|entry| entry.identity.pid == identity.pid)
                && !entry.command_line.is_empty()
            {
                found = entry.command_line.clone();
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }

        let _ = child.kill();
        let _ = child.wait();

        assert!(found.contains("Start-Sleep"), "command line was {found:?}");
        assert!(
            population.0 > population.1 / 2,
            "only {}/{} samples had a command line",
            population.0,
            population.1
        );
    }

    #[test]
    fn priority_is_restored_to_its_original_value() {
        let mut child = spawn_sleeping_pwsh(20);
        let identity = identity_for(child.id());
        let handle =
            WindowsResourceController::open_verified(&identity, PROCESS_SET_INFORMATION).unwrap();
        let original = unsafe { GetPriorityClass(handle.0) };
        drop(handle);
        let original_power = power_state_for(&identity);

        let journal = test_journal("priority");
        let mut controller = WindowsResourceController::new(journal.to_path_buf());
        controller
            .throttle(std::slice::from_ref(&identity))
            .unwrap();
        let throttled =
            WindowsResourceController::open_verified(&identity, PROCESS_SET_INFORMATION).unwrap();
        assert_eq!(
            unsafe { GetPriorityClass(throttled.0) },
            BELOW_NORMAL_PRIORITY_CLASS.0
        );
        drop(throttled);
        assert_ne!(
            power_state_for(&identity).StateMask & PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
            original_power.StateMask & PROCESS_POWER_THROTTLING_EXECUTION_SPEED
        );
        controller.restore(std::slice::from_ref(&identity)).unwrap();
        let restored =
            WindowsResourceController::open_verified(&identity, PROCESS_SET_INFORMATION).unwrap();
        assert_eq!(unsafe { GetPriorityClass(restored.0) }, original);
        let restored_power = power_state_for(&identity);
        assert_eq!(
            restored_power.StateMask & PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
            original_power.StateMask & PROCESS_POWER_THROTTLING_EXECUTION_SPEED
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn watchdog_recovers_throttling_after_an_unclean_exit() {
        let mut child = spawn_sleeping_pwsh(20);
        let identity = identity_for(child.id());
        let original = unsafe {
            let handle =
                WindowsResourceController::open_verified(&identity, PROCESS_SET_INFORMATION)
                    .unwrap();
            GetPriorityClass(handle.0)
        };
        let journal = test_journal("throttle-recovery");
        let mut controller = WindowsResourceController::new(journal.to_path_buf());
        controller
            .throttle(std::slice::from_ref(&identity))
            .unwrap();
        assert!(journal.exists());
        simulate_controller_crash(controller);

        assert!(recover_suspended(&journal).is_empty());
        let restored =
            WindowsResourceController::open_verified(&identity, PROCESS_SET_INFORMATION).unwrap();
        assert_eq!(unsafe { GetPriorityClass(restored.0) }, original);
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn recovery_discards_records_for_processes_that_already_exited() {
        let mut child = spawn_sleeping_pwsh(20);
        let identity = identity_for(child.id());
        let journal = test_journal("exited-process");
        let mut controller = WindowsResourceController::new(journal.to_path_buf());
        controller
            .throttle(std::slice::from_ref(&identity))
            .unwrap();
        simulate_controller_crash(controller);

        child.kill().unwrap();
        child.wait().unwrap();

        assert!(recover_suspended(&journal).is_empty());
        assert!(!journal.exists());
    }

    #[test]
    fn identity_verification_rejects_a_one_second_difference() {
        let mut child = spawn_sleeping_pwsh(20);
        let mut identity = identity_for(child.id());
        identity.started_at_ticks = 0;
        identity.started_at = identity.started_at.saturating_add(1);

        assert!(
            WindowsResourceController::open_verified(&identity, PROCESS_QUERY_LIMITED_INFORMATION)
                .is_err()
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn identity_verification_rejects_a_different_exact_start_tick() {
        let mut child = spawn_sleeping_pwsh(20);
        let mut identity = identity_for(child.id());
        identity.started_at_ticks = identity.started_at_ticks.saturating_add(1);

        assert!(
            WindowsResourceController::open_verified(&identity, PROCESS_QUERY_LIMITED_INFORMATION)
                .is_err()
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn controller_holds_the_journal_lease_for_its_lifetime() {
        let journal = test_journal("controller-lease");
        let controller = WindowsResourceController::new(journal.to_path_buf());
        assert!(controller.journal_loaded);

        assert!(JournalLease::acquire(&journal, Duration::from_millis(20)).is_err());
        drop(controller);
        assert!(JournalLease::acquire(&journal, Duration::from_millis(20)).is_ok());
    }

    #[test]
    fn application_lease_is_shared_across_journal_paths() {
        let first = acquire_application_lease(Duration::from_millis(20)).unwrap();
        assert!(acquire_application_lease(Duration::from_millis(20)).is_err());
        drop(first);
        assert!(acquire_application_lease(Duration::from_millis(20)).is_ok());
    }

    #[test]
    fn duplicate_identity_is_not_restored_twice_across_journals() {
        let first = test_journal("duplicate-first");
        let second = test_journal("duplicate-second");
        let records = vec![test_record(606)];
        write_journal_records(&first, &records).unwrap();
        write_journal_records(&second, &records).unwrap();

        let mut resume_calls = 0;
        let mut resource_restore_calls = 0;
        let errors = recover_all_suspended_with(
            &[
                first.to_path_buf(),
                second.to_path_buf(),
                first.to_path_buf(),
            ],
            |record| {
                if record.suspended {
                    resume_calls += 1;
                    record.suspended = false;
                } else if record.original_state_recorded {
                    resource_restore_calls += 1;
                    record.original_state_recorded = false;
                }
                Ok(())
            },
        );
        assert!(errors.is_empty());
        assert_eq!(resume_calls, 1);
        assert_eq!(resource_restore_calls, 2);
        assert!(!first.exists());
        assert!(!second.exists());
    }

    #[test]
    fn non_adjacent_duplicate_journal_path_is_processed_once() {
        let first = test_journal("duplicate-path-first");
        let second = test_journal("duplicate-path-second");
        write_journal_records(&first, &[test_record(707)]).unwrap();
        let _ = fs::remove_file(&second);

        let mut resource_restore_calls = 0;
        let errors = recover_all_suspended_with(
            &[
                first.to_path_buf(),
                second.to_path_buf(),
                first.to_path_buf(),
            ],
            |record| {
                if record.suspended {
                    record.suspended = false;
                    Ok(())
                } else {
                    resource_restore_calls += 1;
                    Err("保留日志以检测重复处理".into())
                }
            },
        );

        assert_eq!(resource_restore_calls, 1);
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn elevated_handoff_restores_and_releases_normal_ownership_first() {
        let mut child = spawn_sleeping_pwsh(20);
        let identity = identity_for(child.id());
        let handle =
            WindowsResourceController::open_verified(&identity, PROCESS_SET_INFORMATION).unwrap();
        let original_priority = unsafe { GetPriorityClass(handle.0) };
        drop(handle);

        let journal = test_journal("elevated-handoff");
        let mut controller = WindowsResourceController::new(journal.to_path_buf());
        controller
            .throttle(std::slice::from_ref(&identity))
            .unwrap();

        let expected_identity = identity.clone();
        let (requests, receiver) = mpsc::channel::<BrokerCall>();
        let broker_worker = thread::spawn(move || {
            while let Ok(call) = receiver.recv() {
                if matches!(call.action, BrokerAction::Suspend) {
                    let restored = WindowsResourceController::open_verified(
                        &expected_identity,
                        PROCESS_QUERY_LIMITED_INFORMATION,
                    )
                    .unwrap();
                    assert_eq!(unsafe { GetPriorityClass(restored.0) }, original_priority);
                }
                let _ = call.response.send(Ok(()));
            }
        });
        controller.elevated = Some(ElevatedBroker {
            requests,
            process: OwnedHandle(HANDLE::default()),
            cancel_event: OwnedHandle(HANDLE::default()),
            stop: Arc::new(AtomicBool::new(false)),
        });

        let errors = controller.handoff_to_elevated(
            BrokerAction::Suspend,
            vec![(identity.clone(), "需要管理员权限".into())],
        );
        assert!(errors.is_empty());
        assert!(!controller.originals.contains_key(&identity_key(&identity)));
        assert!(controller.elevated_owned.contains(&identity_key(&identity)));

        controller.suspend(std::slice::from_ref(&identity)).unwrap();
        assert!(!controller.originals.contains_key(&identity_key(&identity)));

        drop(controller.elevated.take());
        broker_worker.join().unwrap();
        drop(controller);
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn a_timed_out_broker_is_invalidated() {
        let journal = test_journal("broker-timeout");
        let mut controller = WindowsResourceController::new(journal.to_path_buf());
        let (requests, receiver) = mpsc::channel::<BrokerCall>();
        let (release, wait_for_release) = mpsc::channel();
        let broker_worker = thread::spawn(move || {
            let call = receiver.recv().unwrap();
            wait_for_release.recv().unwrap();
            drop(call);
        });
        controller.elevated = Some(ElevatedBroker {
            requests,
            process: OwnedHandle(HANDLE::default()),
            cancel_event: OwnedHandle(HANDLE::default()),
            stop: Arc::new(AtomicBool::new(false)),
        });

        let error = controller
            .send_elevated_with_timeout(BrokerAction::RestoreAll, &[], Duration::from_millis(20))
            .unwrap_err();
        assert!(error.contains("响应超时"));
        assert!(controller.elevated.is_none());

        release.send(()).unwrap();
        broker_worker.join().unwrap();
        drop(controller);
    }

    #[test]
    fn failed_suspend_rollback_is_persisted_immediately() {
        let journal = test_journal("suspend-rollback");
        let mut controller = WindowsResourceController::new(journal.to_path_buf());
        let record = test_record(505);
        let key = identity_key(&record.identity);
        controller.originals.insert(key, record);
        controller.write_journal().unwrap();

        controller
            .rollback_failed_suspend(key, false, false)
            .unwrap();

        let persisted = read_journal_records(&journal).unwrap();
        assert_eq!(persisted.len(), 1);
        assert!(!persisted[0].suspended);
        drop(controller);
    }

    #[test]
    fn stale_legacy_temporary_file_does_not_block_journal_writes() {
        let journal = test_journal("stale-temp");
        let stale = journal.with_extension("json.tmp");
        fs::write(&stale, b"stale").unwrap();

        write_journal_records(&journal, &[test_record(303)]).unwrap();

        assert_eq!(read_journal_records(&journal).unwrap().len(), 1);
        assert_eq!(fs::read(&stale).unwrap(), b"stale");
        fs::remove_file(stale).unwrap();
    }

    #[test]
    fn helper_rejects_a_non_application_journal_before_connecting() {
        let journal = test_journal("untrusted-helper-path");
        let error = run_elevated_helper(1, 1, r"\\.\pipe\unused", "", "", &journal).unwrap_err();
        assert!(error.contains("非应用恢复日志路径"));
    }

    #[test]
    fn helper_ready_wait_requires_an_explicit_signal() {
        let ready_event = OwnedHandle(unsafe {
            CreateEventW(None, true, false, PCWSTR::null()).expect("ready event should be created")
        });
        let process = OwnedHandle(
            unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, std::process::id()) }
                .expect("current process should be openable for synchronization"),
        );

        let error = wait_for_helper_ready(ready_event.0, process.0, Duration::ZERO).unwrap_err();
        assert!(error.contains("未在 0 秒内就绪"));

        unsafe { SetEvent(ready_event.0) }.expect("ready event should be signaled");
        wait_for_helper_ready(ready_event.0, process.0, Duration::ZERO).unwrap();

        let exited_process = OwnedHandle(unsafe {
            CreateEventW(None, true, true, PCWSTR::null()).expect("signaled process stand-in")
        });
        let error =
            wait_for_helper_ready(ready_event.0, exited_process.0, Duration::ZERO).unwrap_err();
        assert!(error.contains("在就绪前已退出"));
    }

    #[test]
    fn cross_account_event_rejects_an_existing_name() {
        let name = format!(
            "Local\\LazyProcessEventCollisionTest-{}-{}",
            std::process::id(),
            JOURNAL_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let _first = create_cross_account_event(&name).unwrap();
        let error = create_cross_account_event(&name).unwrap_err();
        assert!(error.contains("名称已被占用"));
    }

    #[test]
    fn watchdog_rejects_a_non_application_journal() {
        let journal = test_journal("untrusted-watchdog-path");
        let error =
            run_watchdog(u32::MAX, 1, "", WatchdogRecovery::SingleJournal, &journal).unwrap_err();
        assert!(error.contains("非应用恢复日志路径"));
    }

    #[test]
    fn watchdog_rejects_a_process_that_is_not_its_parent() {
        let journal = journal_candidate_paths().into_iter().next().unwrap();
        let error =
            run_watchdog(u32::MAX, 1, "", WatchdogRecovery::SingleJournal, &journal).unwrap_err();
        assert!(error.contains("非父进程"));
    }

    #[test]
    fn watchdog_ready_event_rejects_a_precreated_name() {
        let sequence = JOURNAL_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!(
            "Local\\LazyProcessWatchdogReady-Test-{}-{sequence}",
            std::process::id()
        );
        let first = create_watchdog_ready_event(&name).unwrap();

        let error = create_watchdog_ready_event(&name).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        drop(first);
    }

    #[test]
    fn old_suspension_journals_remain_compatible() {
        let identity = ProcessIdentity {
            pid: 123,
            started_at: 456,
            started_at_ticks: 0,
            executable_path: PathBuf::from(r"C:\missing\process.exe"),
        };
        let records: Vec<SuspensionRecord> =
            serde_json::from_value(serde_json::json!([{ "identity": identity }])).unwrap();
        assert!(records[0].suspended);
        assert!(!records[0].original_state_recorded);
    }

    #[test]
    fn missing_journal_is_ignored_but_read_errors_are_reported() {
        let journal = test_journal("read-errors");
        let _ = fs::remove_dir(&journal);
        assert!(recover_suspended(&journal).is_empty());

        fs::create_dir(&journal).unwrap();
        let errors = recover_suspended(&journal);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("恢复日志读取失败"));
    }

    #[test]
    fn invalid_journal_is_not_overwritten_or_deleted() {
        let journal = test_journal("invalid");
        let invalid = b"{ definitely not valid json";
        fs::write(&journal, invalid).unwrap();

        let errors = recover_suspended(&journal);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("恢复日志无效"));

        let mut controller = WindowsResourceController::new(journal.to_path_buf());
        assert!(!controller.journal_loaded);
        assert!(controller.write_journal().is_err());
        assert_eq!(fs::read(&journal).unwrap(), invalid);
        drop(controller.journal_lease.take());
        std::mem::forget(controller);
    }

    #[test]
    fn recovery_persists_each_record_and_does_not_repeat_resume_stage() {
        let journal = test_journal("partial-progress");
        let records = vec![test_record(101), test_record(202)];
        write_journal_records(&journal, &records).unwrap();

        let errors = recover_records_with(&journal, records, |record| {
            record.suspended = false;
            if record.identity.pid == 101 {
                record.original_state_recorded = false;
                Ok(())
            } else {
                Err("后续状态恢复失败".into())
            }
        });
        assert_eq!(errors, ["后续状态恢复失败".to_owned()]);

        let remaining = read_journal_records(&journal).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].identity.pid, 202);
        assert!(!remaining[0].suspended);
        assert!(remaining[0].original_state_recorded);

        let controller = WindowsResourceController::new(journal.to_path_buf());
        assert!(controller.journal_loaded);
        assert_eq!(controller.originals.len(), 1);
        simulate_controller_crash(controller);

        let errors = recover_records_with(&journal, remaining, |record| {
            assert!(!record.suspended, "resume stage must not run twice");
            record.original_state_recorded = false;
            Ok(())
        });
        assert!(errors.is_empty());
        assert!(!journal.exists());
    }

    #[test]
    fn resume_stage_is_on_disk_before_resource_restoration_starts() {
        let journal = test_journal("stage-order");
        let records = vec![test_record(404)];
        write_journal_records(&journal, &records).unwrap();
        let mut stage = 0;

        let errors = recover_records_with(&journal, records, |record| {
            stage += 1;
            if stage == 1 {
                assert!(record.suspended);
                record.suspended = false;
                Ok(())
            } else {
                let persisted = read_journal_records(&journal).unwrap();
                assert!(!persisted[0].suspended);
                Err("resource restoration failed".into())
            }
        });

        assert_eq!(errors, ["resource restoration failed"]);
        let remaining = read_journal_records(&journal).unwrap();
        assert!(!remaining[0].suspended);
    }

    #[test]
    fn recovery_journal_resumes_a_suspended_process() {
        let mut child = spawn_sleeping_pwsh(2);
        let identity = identity_for(child.id());
        let journal = test_journal("suspend");
        let mut controller = WindowsResourceController::new(journal.to_path_buf());
        controller.suspend(std::slice::from_ref(&identity)).unwrap();
        thread::sleep(Duration::from_millis(2_500));
        assert!(child.try_wait().unwrap().is_none());

        simulate_controller_crash(controller);
        assert!(recover_suspended(&journal).is_empty());
        let status = child.wait().unwrap();
        assert!(status.success());
    }
}
