use crate::{
    config::replace_file_atomic,
    engine::ResourceController,
    model::{ProcessIdentity, ProcessSample},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    ffi::c_void,
    fs, io,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use sysinfo::{ProcessesToUpdate, System};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_PIPE_CONNECTED, FILETIME, GENERIC_READ, GENERIC_WRITE, GetLastError,
            HANDLE, HWND, LPARAM, WAIT_OBJECT_0,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
            ReadFile, WriteFile,
        },
        System::{
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_MESSAGE,
                PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT,
            },
            Threading::{
                BELOW_NORMAL_PRIORITY_CLASS, GetPriorityClass, GetProcessInformation,
                GetProcessTimes, INFINITE, OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_NAME_FORMAT,
                PROCESS_POWER_THROTTLING_CURRENT_VERSION, PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
                PROCESS_POWER_THROTTLING_STATE, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_SET_INFORMATION, PROCESS_SUSPEND_RESUME, ProcessPowerThrottling,
                QueryFullProcessImageNameW, SetPriorityClass, SetProcessInformation,
                WaitForSingleObject,
            },
        },
        UI::Shell::ShellExecuteW,
        UI::WindowsAndMessaging::{
            EnumWindows, GetForegroundWindow, GetWindowThreadProcessId, IsHungAppWindow, SW_HIDE,
        },
    },
    core::{BOOL, HSTRING, PCWSTR, PWSTR},
};

const WINDOWS_TO_UNIX_SECONDS: u64 = 11_644_473_600;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const PROCESS_SYNCHRONIZE: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0010_0000);

unsafe extern "system" {
    fn NtSuspendProcess(process: HANDLE) -> i32;
    fn NtResumeProcess(process: HANDLE) -> i32;
}

#[derive(Debug)]
pub struct ProcessSampler {
    system: System,
    own_pid: u32,
    metadata: HashMap<(u32, u64), CachedProcessMetadata>,
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
        self.system.refresh_processes(ProcessesToUpdate::All, true);
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
            let key = (pid, started_at);
            present.insert(key);
            let metadata = self
                .metadata
                .entry(key)
                .or_insert_with(|| CachedProcessMetadata {
                    executable_path: executable_path.to_path_buf(),
                    parent_pid: process.parent().map(sysinfo::Pid::as_u32),
                    name: process.name().to_string_lossy().into_owned(),
                    command_line: process
                        .cmd()
                        .iter()
                        .map(|part| part.to_string_lossy())
                        .collect::<Vec<_>>()
                        .join(" "),
                })
                .clone();
            let disk = process.disk_usage();
            samples.push(ProcessSample {
                identity: ProcessIdentity {
                    pid,
                    started_at,
                    executable_path: metadata.executable_path,
                },
                parent_pid: metadata.parent_pid,
                name: metadata.name,
                command_line: metadata.command_line,
                cpu_percent: process.cpu_usage(),
                io_bytes: disk
                    .total_read_bytes
                    .saturating_add(disk.total_written_bytes),
            });
        }
        self.metadata.retain(|key, _| present.contains(key));
        samples
    }
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

#[derive(Debug, Clone)]
struct OriginalState {
    identity: ProcessIdentity,
    priority_class: u32,
    power_control_mask: u32,
    power_state_mask: u32,
    suspended: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspensionRecord {
    pub identity: ProcessIdentity,
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
    pipe: OwnedHandle,
}

impl ElevatedBroker {
    fn send(&mut self, action: BrokerAction, processes: &[ProcessIdentity]) -> Result<(), String> {
        let request = BrokerRequest {
            action,
            processes: processes.to_vec(),
        };
        write_frame(
            self.pipe.0,
            &serde_json::to_vec(&request).map_err(|error| error.to_string())?,
        )?;
        let response: BrokerResponse =
            serde_json::from_slice(&read_frame(self.pipe.0)?).map_err(|error| error.to_string())?;
        response.error.map_or(Ok(()), Err)
    }
}

#[derive(Debug)]
pub struct WindowsResourceController {
    originals: HashMap<(u32, u64), OriginalState>,
    journal_path: PathBuf,
    elevated: Option<ElevatedBroker>,
}

impl WindowsResourceController {
    #[must_use]
    pub fn new(journal_path: PathBuf) -> Self {
        Self {
            originals: HashMap::new(),
            journal_path,
            elevated: None,
        }
    }

    fn remember(&mut self, identity: &ProcessIdentity, handle: HANDLE) {
        let key = (identity.pid, identity.started_at);
        self.originals.entry(key).or_insert_with(|| {
            let priority_class = unsafe { GetPriorityClass(handle) };
            let mut power = PROCESS_POWER_THROTTLING_STATE {
                Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
                ControlMask: 0,
                StateMask: 0,
            };
            // Unsupported Windows versions simply leave the original masks at zero.
            let _ = unsafe {
                GetProcessInformation(
                    handle,
                    ProcessPowerThrottling,
                    (&raw mut power).cast::<c_void>(),
                    u32::try_from(size_of::<PROCESS_POWER_THROTTLING_STATE>()).unwrap_or(u32::MAX),
                )
            };
            OriginalState {
                identity: identity.clone(),
                priority_class,
                power_control_mask: power.ControlMask,
                power_state_mask: power.StateMask,
                suspended: false,
            }
        });
    }

    fn write_journal(&self) -> io::Result<()> {
        let records = self
            .originals
            .values()
            .filter(|state| state.suspended)
            .map(|state| SuspensionRecord {
                identity: state.identity.clone(),
            })
            .collect::<Vec<_>>();
        if records.is_empty() {
            match fs::remove_file(&self.journal_path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            return Ok(());
        }
        if let Some(parent) = self.journal_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = self.journal_path.with_extension("json.tmp");
        fs::write(
            &temporary,
            serde_json::to_vec_pretty(&records).map_err(io::Error::other)?,
        )?;
        replace_file_atomic(&temporary, &self.journal_path)
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

    fn restore_one(&mut self, key: (u32, u64)) -> Result<(), String> {
        let Some(original) = self.originals.get(&key).cloned() else {
            return Ok(());
        };
        let handle = Self::open_verified(
            &original.identity,
            PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME,
        )?;
        if original.suspended {
            let status = unsafe { NtResumeProcess(handle.0) };
            if status < 0 {
                return Err(format!(
                    "PID {} 恢复失败：NTSTATUS {status:#x}",
                    original.identity.pid
                ));
            }
        }
        if original.priority_class != 0 {
            unsafe {
                SetPriorityClass(
                    handle.0,
                    windows::Win32::System::Threading::PROCESS_CREATION_FLAGS(
                        original.priority_class,
                    ),
                )
            }
            .map_err(|error| format!("PID {} 优先级恢复失败：{error}", original.identity.pid))?;
        }
        let power = PROCESS_POWER_THROTTLING_STATE {
            Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
            ControlMask: original.power_control_mask,
            StateMask: original.power_state_mask,
        };
        let _ = unsafe {
            SetProcessInformation(
                handle.0,
                ProcessPowerThrottling,
                (&raw const power).cast::<c_void>(),
                u32::try_from(size_of::<PROCESS_POWER_THROTTLING_STATE>()).unwrap_or(u32::MAX),
            )
        };
        self.originals.remove(&key);
        Ok(())
    }
}

impl ResourceController for WindowsResourceController {
    fn throttle(&mut self, processes: &[ProcessIdentity]) -> Result<(), String> {
        let mut errors = Vec::new();
        let mut elevated = Vec::new();
        for identity in processes {
            match Self::open_verified(identity, PROCESS_SET_INFORMATION) {
                Ok(handle) => {
                    self.remember(identity, handle.0);
                    if let Err(error) =
                        unsafe { SetPriorityClass(handle.0, BELOW_NORMAL_PRIORITY_CLASS) }
                    {
                        errors.push(format!("PID {}：{error}", identity.pid));
                        continue;
                    }
                    let power = PROCESS_POWER_THROTTLING_STATE {
                        Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
                        ControlMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
                        StateMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
                    };
                    let _ = unsafe {
                        SetProcessInformation(
                            handle.0,
                            ProcessPowerThrottling,
                            (&raw const power).cast::<c_void>(),
                            u32::try_from(size_of::<PROCESS_POWER_THROTTLING_STATE>())
                                .unwrap_or(u32::MAX),
                        )
                    };
                }
                Err(error) => elevated.push((identity.clone(), error)),
            }
        }
        if !elevated.is_empty() {
            let identities = elevated
                .iter()
                .map(|(identity, _)| identity.clone())
                .collect::<Vec<_>>();
            match self.elevated.as_mut() {
                Some(broker) => {
                    if let Err(error) = broker.send(BrokerAction::Throttle, &identities) {
                        errors.push(format!("管理员辅助进程：{error}"));
                    }
                }
                None => errors.extend(elevated.into_iter().map(|(_, error)| error)),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("；"))
        }
    }

    fn suspend(&mut self, processes: &[ProcessIdentity]) -> Result<(), String> {
        let mut errors = Vec::new();
        let mut elevated = Vec::new();
        // Suspend roots before descendants to prevent new children from appearing mid-operation.
        for identity in processes {
            match Self::open_verified(identity, PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION) {
                Ok(handle) => {
                    self.remember(identity, handle.0);
                    let status = unsafe { NtSuspendProcess(handle.0) };
                    if status < 0 {
                        errors.push(format!(
                            "PID {} 暂停失败：NTSTATUS {status:#x}",
                            identity.pid
                        ));
                    } else if let Some(state) =
                        self.originals.get_mut(&(identity.pid, identity.started_at))
                    {
                        state.suspended = true;
                    }
                }
                Err(error) => elevated.push((identity.clone(), error)),
            }
        }
        if !elevated.is_empty() {
            let identities = elevated
                .iter()
                .map(|(identity, _)| identity.clone())
                .collect::<Vec<_>>();
            match self.elevated.as_mut() {
                Some(broker) => {
                    if let Err(error) = broker.send(BrokerAction::Suspend, &identities) {
                        errors.push(format!("管理员辅助进程：{error}"));
                    }
                }
                None => errors.extend(elevated.into_iter().map(|(_, error)| error)),
            }
        }
        if let Err(error) = self.write_journal() {
            errors.push(format!("恢复日志写入失败：{error}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("；"))
        }
    }

    fn restore(&mut self, processes: &[ProcessIdentity]) -> Result<(), String> {
        let requested = processes
            .iter()
            .map(|identity| (identity.pid, identity.started_at))
            .collect::<HashSet<_>>();
        let keys = self
            .originals
            .keys()
            .filter(|key| requested.contains(key))
            .copied()
            .collect::<Vec<_>>();
        let mut errors = Vec::new();
        // Descendants were inserted after roots; reverse PID-independent insertion is unavailable,
        // but NtResumeProcess is safe for either order once the whole group is ready to resume.
        for key in keys {
            if let Err(error) = self.restore_one(key) {
                errors.push(error);
            }
        }
        if let Err(error) = self.write_journal() {
            errors.push(format!("恢复日志更新失败：{error}"));
        }
        if let Some(broker) = self.elevated.as_mut()
            && let Err(error) = broker.send(BrokerAction::Restore, processes)
        {
            errors.push(format!("管理员辅助进程：{error}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("；"))
        }
    }

    fn restore_all(&mut self) -> Vec<String> {
        let keys = self.originals.keys().copied().collect::<Vec<_>>();
        let mut errors = keys
            .into_iter()
            .filter_map(|key| self.restore_one(key).err())
            .collect::<Vec<_>>();
        if let Err(error) = self.write_journal() {
            errors.push(error.to_string());
        }
        if let Some(broker) = self.elevated.as_mut()
            && let Err(error) = broker.send(BrokerAction::RestoreAll, &[])
        {
            errors.push(format!("管理员辅助进程：{error}"));
        }
        errors
    }

    fn enable_elevation(&mut self) -> Result<(), String> {
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

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn start_elevated_broker(journal_path: &Path) -> Result<ElevatedBroker, String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let pipe_name = format!(r"\\.\pipe\lazy-process-{}-{nonce:x}", std::process::id());
    let elevated_journal = journal_path.with_file_name("suspended-elevated.json");
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let parameters = format!(
        "--elevated-helper \"{pipe_name}\" \"{}\"",
        elevated_journal.display()
    );
    let operation = HSTRING::from("runas");
    let executable = HSTRING::from(executable.as_path());
    let parameters = HSTRING::from(parameters);
    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(operation.as_ptr()),
            PCWSTR(executable.as_ptr()),
            PCWSTR(parameters.as_ptr()),
            PCWSTR::null(),
            SW_HIDE,
        )
    };
    if result.0 as isize <= 32 {
        return Err("管理员授权被取消或无法启动辅助进程".into());
    }

    let pipe_name = HSTRING::from(pipe_name);
    for _ in 0..150 {
        let pipe = unsafe {
            CreateFileW(
                PCWSTR(pipe_name.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };
        if let Ok(pipe) = pipe {
            return Ok(ElevatedBroker {
                pipe: OwnedHandle(pipe),
            });
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err("管理员辅助进程未在 30 秒内建立本地连接".into())
}

pub fn run_elevated_helper(pipe_name: &str, journal_path: &Path) -> Result<(), String> {
    let pipe_name = HSTRING::from(pipe_name);
    let pipe = unsafe {
        CreateNamedPipeW(
            PCWSTR(pipe_name.as_ptr()),
            PIPE_ACCESS_DUPLEX,
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

    let mut controller = WindowsResourceController::new(journal_path.to_path_buf());
    while let Ok(frame) = read_frame(pipe.0) {
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
        write_frame(pipe.0, &bytes)?;
    }
    let errors = controller.restore_all();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("；"))
    }
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
    let started_at = filetime_unix_seconds(creation);
    if started_at.abs_diff(expected.started_at) > 1 {
        return Err(format!("PID {} 已被其他进程复用", expected.pid));
    }
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
    let actual = PathBuf::from(String::from_utf16_lossy(
        &buffer[..usize::try_from(length).unwrap_or(0)],
    ));
    if !actual
        .as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.executable_path.as_os_str().to_string_lossy())
    {
        return Err(format!("PID {} 可执行路径发生变化", expected.pid));
    }
    Ok(())
}

fn filetime_unix_seconds(value: FILETIME) -> u64 {
    let ticks = (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime);
    ticks
        .saturating_div(10_000_000)
        .saturating_sub(WINDOWS_TO_UNIX_SECONDS)
}

#[must_use]
pub fn recover_suspended(journal_path: &Path) -> Vec<String> {
    let Ok(bytes) = fs::read(journal_path) else {
        return Vec::new();
    };
    let records: Vec<SuspensionRecord> = match serde_json::from_slice(&bytes) {
        Ok(records) => records,
        Err(error) => return vec![format!("恢复日志无效：{error}")],
    };
    let mut errors = Vec::new();
    for record in records {
        match WindowsResourceController::open_verified(&record.identity, PROCESS_SUSPEND_RESUME) {
            Ok(handle) => {
                let status = unsafe { NtResumeProcess(handle.0) };
                if status < 0 {
                    errors.push(format!("PID {} 恢复失败：{status:#x}", record.identity.pid));
                }
            }
            Err(error) => errors.push(error),
        }
    }
    if errors.is_empty() {
        let _ = fs::remove_file(journal_path);
    }
    errors
}

pub fn spawn_watchdog(journal_path: &Path) -> io::Result<Child> {
    Command::new(std::env::current_exe()?)
        .arg("--watchdog")
        .arg(std::process::id().to_string())
        .arg(journal_path)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

pub fn run_watchdog(parent_pid: u32, journal_path: &Path) -> Result<(), String> {
    let parent = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, parent_pid) }
        .map_err(|error| error.to_string())?;
    let parent = OwnedHandle(parent);
    let result = unsafe { WaitForSingleObject(parent.0, INFINITE) };
    if result != WAIT_OBJECT_0 {
        return Err(format!("等待主进程失败：{result:?}"));
    }
    let errors = recover_suspended(journal_path);
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

    fn test_journal(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("lazy-process-{name}-{}.json", std::process::id()))
    }

    #[test]
    fn priority_is_restored_to_its_original_value() {
        let mut child = spawn_sleeping_pwsh(20);
        let identity = identity_for(child.id());
        let handle =
            WindowsResourceController::open_verified(&identity, PROCESS_SET_INFORMATION).unwrap();
        let original = unsafe { GetPriorityClass(handle.0) };
        drop(handle);

        let mut controller = WindowsResourceController::new(test_journal("priority"));
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
        controller.restore(std::slice::from_ref(&identity)).unwrap();
        let restored =
            WindowsResourceController::open_verified(&identity, PROCESS_SET_INFORMATION).unwrap();
        assert_eq!(unsafe { GetPriorityClass(restored.0) }, original);
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn recovery_journal_resumes_a_suspended_process() {
        let mut child = spawn_sleeping_pwsh(2);
        let identity = identity_for(child.id());
        let journal = test_journal("suspend");
        let mut controller = WindowsResourceController::new(journal.clone());
        controller.suspend(std::slice::from_ref(&identity)).unwrap();
        thread::sleep(Duration::from_millis(2_500));
        assert!(child.try_wait().unwrap().is_none());

        std::mem::forget(controller);
        assert!(recover_suspended(&journal).is_empty());
        let status = child.wait().unwrap();
        assert!(status.success());
    }
}
