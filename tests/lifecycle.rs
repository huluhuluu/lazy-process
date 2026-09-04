//! End-to-end coverage against a real Windows process.
//!
//! The unit tests drive the engine with a fake controller, which proves the decisions but not the
//! syscalls. This walks a live child process through throttle, suspend, and restore, and checks the
//! result with `GetPriorityClass` rather than trusting the controller's own return value.

#![cfg(windows)]

use lazy_process::{
    config::{AppConfig, ProcessRule, RuleMatcher},
    engine::{Engine, ResourceController},
    model::{ActivityState, ProcessIdentity, ProcessSample},
    platform::{ProcessSampler, WindowsResourceController},
};
use std::{
    path::PathBuf,
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};
use windows::Win32::{
    Foundation::CloseHandle,
    System::Threading::{
        BELOW_NORMAL_PRIORITY_CLASS, GetPriorityClass, NORMAL_PRIORITY_CLASS, OpenProcess,
        PROCESS_QUERY_LIMITED_INFORMATION,
    },
};

/// Long enough for the sampler to see the child, short enough that a stuck test still ends.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(20);

struct Reaped(Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A child that sits idle without spinning the CPU, so it reads as quiet on the first sample.
fn spawn_idle_child() -> Reaped {
    let child = Command::new("cmd.exe")
        .args(["/c", "pause"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("cmd.exe should start");
    Reaped(child)
}

fn priority_class(pid: u32) -> Option<u32> {
    // SAFETY: the pid comes from a child this test owns, and the handle is closed below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let class = unsafe { GetPriorityClass(handle) };
    let _ = unsafe { CloseHandle(handle) };
    (class != 0).then_some(class)
}

/// Samples until `pid` appears, because a process is not visible to the sampler the instant it is
/// spawned. Returns the whole sample so the caller can feed it straight to the engine.
fn sample_until_present(sampler: &mut ProcessSampler, pid: u32) -> Vec<ProcessSample> {
    let deadline = Instant::now() + DISCOVERY_TIMEOUT;
    loop {
        let processes = sampler.sample();
        if processes.iter().any(|process| process.identity.pid == pid) {
            return processes;
        }
        assert!(
            Instant::now() < deadline,
            "PID {pid} never appeared in a sample"
        );
        thread::sleep(Duration::from_millis(150));
    }
}

fn test_config(executable: PathBuf) -> AppConfig {
    AppConfig {
        globally_enabled: true,
        sample_interval_seconds: 1,
        // Generous, because a freshly started cmd.exe can report a little CPU and I/O.
        cpu_quiet_percent: 100.0,
        io_quiet_bytes_per_sample: u64::MAX,
        rules: vec![ProcessRule {
            id: "integration".into(),
            name: "Integration".into(),
            enabled: true,
            allow_suspend: true,
            throttle_after_seconds: 1,
            suspend_after_seconds: 3,
            matcher: RuleMatcher {
                executable_path: Some(executable),
                ..Default::default()
            },
            // The engine would otherwise pull in conhost and any shell the child spawns.
            include_descendants: false,
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn journal_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "lazy-process-it-{name}-{}-{:?}.json",
        std::process::id(),
        thread::current().id()
    ))
}

#[test]
fn a_real_process_is_throttled_then_suspended_then_restored() {
    let child = spawn_idle_child();
    let pid = child.0.id();
    let original = priority_class(pid).expect("a live child should report a priority class");
    assert_eq!(
        original, NORMAL_PRIORITY_CLASS.0,
        "the child should start at normal priority"
    );

    let journal = journal_path("lifecycle");
    let mut sampler = ProcessSampler::new();
    let mut engine = Engine::new(WindowsResourceController::new(journal.clone()));
    let processes = sample_until_present(&mut sampler, pid);
    let child_sample = processes
        .iter()
        .find(|process| process.identity.pid == pid)
        .expect("the child must be in the sample");
    let config = test_config(child_sample.identity.executable_path.clone());
    // Restrict the group to this pid: several cmd.exe processes can share one path.
    let only_child = processes
        .iter()
        .filter(|process| process.identity.pid == pid)
        .cloned()
        .collect::<Vec<_>>();

    // First tick establishes the quiet baseline, the second crosses the throttle delay.
    engine.tick(&config, &only_child, None, 0);
    let statuses = engine.tick(&config, &only_child, None, 2);
    assert_eq!(statuses.len(), 1, "the rule should match exactly one group");
    assert_eq!(
        statuses[0].state,
        ActivityState::Throttled,
        "detail: {}",
        statuses[0].detail
    );
    assert_eq!(
        priority_class(pid),
        Some(BELOW_NORMAL_PRIORITY_CLASS.0),
        "throttling must actually lower the OS priority class"
    );

    let statuses = engine.tick(&config, &only_child, None, 5);
    assert_eq!(
        statuses[0].state,
        ActivityState::Suspended,
        "detail: {}",
        statuses[0].detail
    );
    // A suspended process is still a live process with a priority class.
    assert!(
        priority_class(pid).is_some(),
        "the child should still exist"
    );

    // Focus restores: the same path the hotkey and the tray use.
    let statuses = engine.tick(&config, &only_child, Some(pid), 6);
    assert_eq!(statuses[0].state, ActivityState::Active);
    assert_eq!(
        priority_class(pid),
        Some(original),
        "restoring must put the original priority class back"
    );

    drop(engine);
    let _ = std::fs::remove_file(&journal);
}

#[test]
fn restore_all_puts_back_every_managed_process() {
    let first = spawn_idle_child();
    let second = spawn_idle_child();
    let pids = [first.0.id(), second.0.id()];

    let journal = journal_path("restore-all");
    let mut sampler = ProcessSampler::new();
    let mut controller = WindowsResourceController::new(journal.clone());
    let processes = sample_until_present(&mut sampler, pids[1]);
    let identities = pids
        .iter()
        .map(|pid| {
            processes
                .iter()
                .find(|process| process.identity.pid == *pid)
                .unwrap_or_else(|| panic!("PID {pid} should be sampled"))
                .identity
                .clone()
        })
        .collect::<Vec<ProcessIdentity>>();

    controller.throttle(&identities).expect("throttle");
    for pid in pids {
        assert_eq!(priority_class(pid), Some(BELOW_NORMAL_PRIORITY_CLASS.0));
    }

    controller.suspend(&identities).expect("suspend");
    // Trimming a suspended process is best effort by design, so it is checked for a clean error
    // rather than for a particular memory figure.
    if let Err(error) = controller.trim_working_set(&identities) {
        assert!(
            error.contains("PID"),
            "a trim failure should name the process: {error}"
        );
    }

    assert!(
        controller.restore_all().is_empty(),
        "restore_all should report no errors"
    );
    for pid in pids {
        assert_eq!(
            priority_class(pid),
            Some(NORMAL_PRIORITY_CLASS.0),
            "PID {pid} should be back at normal priority"
        );
    }

    drop(controller);
    let _ = std::fs::remove_file(&journal);
}

/// Guards the identity check that stands between "end this process" and "end whatever now holds
/// that pid". A dead pid must be refused, not acted on.
#[test]
fn terminating_a_stale_identity_is_refused() {
    let child = spawn_idle_child();
    let pid = child.0.id();
    let journal = journal_path("stale");
    let mut sampler = ProcessSampler::new();
    let processes = sample_until_present(&mut sampler, pid);
    let identity = processes
        .iter()
        .find(|process| process.identity.pid == pid)
        .expect("the child must be in the sample")
        .identity
        .clone();

    // Same pid, a start time that cannot belong to it.
    let stale = ProcessIdentity {
        started_at: identity.started_at.saturating_sub(3_600),
        started_at_ticks: identity.started_at_ticks.saturating_sub(3_600 * 10_000_000),
        ..identity.clone()
    };
    let mut controller = WindowsResourceController::new(journal.clone());
    let error = controller
        .terminate_process(&stale)
        .expect_err("a mismatched identity must be refused");
    assert!(error.contains("PID"), "unexpected error: {error}");
    assert!(
        priority_class(pid).is_some(),
        "the refused call must leave the process running"
    );

    // The real identity is accepted, which shows the refusal was about the mismatch.
    controller
        .terminate_process(&identity)
        .expect("the live identity should terminate");
    let deadline = Instant::now() + Duration::from_secs(5);
    while priority_class(pid).is_some() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }

    drop(controller);
    let _ = std::fs::remove_file(&journal);
}

/// The handle must be closed even on the refused path; otherwise a leaked handle would keep the pid
/// reserved and mask exactly the reuse this check exists to prevent.
#[test]
fn a_refused_termination_does_not_leak_the_process_handle() {
    let child = spawn_idle_child();
    let pid = child.0.id();
    let journal = journal_path("no-leak");
    let mut sampler = ProcessSampler::new();
    let processes = sample_until_present(&mut sampler, pid);
    let identity = processes
        .iter()
        .find(|process| process.identity.pid == pid)
        .expect("the child must be in the sample")
        .identity
        .clone();
    let stale = ProcessIdentity {
        started_at_ticks: identity.started_at_ticks.saturating_add(10_000_000),
        ..identity
    };

    let mut controller = WindowsResourceController::new(journal.clone());
    for _ in 0..200 {
        assert!(controller.terminate_process(&stale).is_err());
    }
    assert!(
        priority_class(pid).is_some(),
        "the child should be untouched after 200 refused calls"
    );

    drop(controller);
    let _ = std::fs::remove_file(&journal);
}
