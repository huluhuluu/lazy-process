# Lazy Process

Lazy Process is a local Windows tray utility that reduces resource use for idle
application process trees. It ships with conservative Codex and PowerShell
presets and supports exact-path rules for any running desktop application.

## Safety model

- A group must be unfocused and remain below the configured CPU and I/O limits.
- Tier 1 uses Below Normal priority and Windows process power throttling.
- Tier 2 process suspension is disabled until explicitly enabled per rule.
- Returning the host application to the foreground restores its entire tree.
- `Ctrl+Alt+Shift+F12` and the tray menu restore every managed process.
- A separate watchdog resumes suspended processes if Lazy Process exits or crashes.
- An optional UAC-elevated helper handles protected processes over a local-only pipe and exits with the main app.
- PID, process creation time, and executable path are revalidated before each action.

The utility never records terminal output, keyboard input, clipboard content, or
full command lines. It does not terminate processes automatically.

## Build

```powershell
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

Run `target/release/lazy-process.exe`. Configuration is stored under the current
user's local application data directory.
