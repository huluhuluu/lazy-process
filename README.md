# Lazy Process

[![CI](https://github.com/huluhuluu/lazy-process/actions/workflows/ci.yml/badge.svg)](https://github.com/huluhuluu/lazy-process/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/huluhuluu/lazy-process?sort=semver)](https://github.com/huluhuluu/lazy-process/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Windows tray utility that reduces the resource use of idle application process
trees. When an application has been in the background and below your thresholds
for long enough, Lazy Process drops its priority, enables Windows power
throttling, and — only if you explicitly allow it per rule — suspends it. Bring
the application back to the foreground and the whole tree is restored.

It is a local tool: no account, no telemetry, no network calls.

## Features

- **Whole process trees, not single processes.** A rule matches a host application
  and manages its descendants together, so a terminal and the shells inside it are
  treated as one unit.
- **Two tiers, the second one opt-in.** Tier 1 is `BELOW_NORMAL_PRIORITY_CLASS`
  plus Windows power throttling. Tier 2 is real suspension
  (`NtSuspendProcess`), disabled per rule until you enable it.
- **Rules on name, path, command line, or a command-line regex**, with exclusions
  matched first. A live preview shows what a rule would match while you type it.
- **Schedules.** Restrict a rule to a time window and a set of weekdays, including
  windows that wrap past midnight.
- **Process explorer.** Sortable by PID, name, CPU, memory, threads, run time, or
  status, with per-process detail: parent PID, full path, and the complete command
  line, which can be copied or opened in Explorer.
- **Crash recovery.** A separate watchdog restores priority, throttling, and
  suspension if the app exits or crashes, including after a hard kill.
- **Interface zoom.** `Ctrl` + mouse wheel scales the whole UI without blurring it.
- **Light and dark themes**, following Windows or pinned to either.

## Installation

### Download

Grab `lazy-process.exe` from the [latest release](https://github.com/huluhuluu/lazy-process/releases/latest)
and run it. It is a single self-contained executable; there is no installer.

The binary is unsigned, so Windows SmartScreen will warn on first launch. Choose
*More info* → *Run anyway*, or build it yourself from source.

### From source

Requires a Windows host and the toolchain pinned in `rust-toolchain.toml`
(Rust 1.99.0):

```powershell
git clone https://github.com/huluhuluu/lazy-process.git
cd lazy-process
cargo build --release
```

The result is `target\release\lazy-process.exe`.

## Usage

Lazy Process starts in the tray. Closing the window hides it rather than exiting.

| Action | How |
| --- | --- |
| Open the window | Tray icon → 打开 Lazy Process |
| Restore everything | `Ctrl+Alt+Shift+F12`, or the tray menu |
| Pause or resume monitoring | Tray menu → 暂停/继续监控 |
| Quit | Tray menu → 退出 |
| Zoom the interface | `Ctrl` + wheel, or `Ctrl` + `+` / `-` / `0` |

The interface is in Chinese. The six pages are **概览** (overview), **进程**
(processes), **应用规则** (rules), **添加应用** (add an application), **事件日志**
(event log), and **设置** (settings).

The overview page shows system CPU and memory bars, a rolling chart of group and
process counts, and one card per managed group with its state, process count, and
the countdown to the next action. A card expands to the group's process tree.

### Quick start

1. Open **应用规则** and pick one of the shipped presets, or **添加应用** to choose
   a running program.
2. Set the thresholds in **设置**. The defaults are conservative: 5-second sample
   interval, 1% CPU, and 4 KiB of I/O per sample.
3. Leave **二级暂停** (`allow_suspend`) off until you trust the rule. Tier 1 alone
   already gives most of the benefit and is trivially reversible.

## Rules

Each rule needs at least one of: process name, full executable path, path
fragment, command-line fragment, or command-line regex. An ancestor process name
narrows an existing condition but cannot select on its own — alone it would match
every child of a host application. Exclusions are matched first, and anything they
hit is left alone.

Everything is editable from the rules page, and the configuration file remains
hand-editable: unknown fields are preserved on save, so a file written by a newer
version is not silently stripped.

While a rule is being edited, a live preview lists the processes it would match
right now, marking each as a host, a descendant, or excluded. Rules can be
exported to and imported from JSON; an imported rule that collides with an
existing id is renamed rather than overwriting it, and an import that would not
validate is rejected before anything is written, so a bad file cannot cost you the
rules you already had. Deleted presets can be brought back without touching
anything else.

Two optional per-rule settings:

- **Schedule.** Restricts a rule to a time window and a set of weekdays. Windows
  that wrap past midnight are supported, so 22:00–06:00 means the night, and a
  weekday applies to the night it starts: "Monday, 22:00–06:00" runs from Monday
  evening through to 06:00 on Tuesday, rather than being cut in half at midnight.
  Leaving the window empty means the whole day, and clearing every weekday means
  every day, so a half-filled schedule cannot silently disable a rule. A weekday
  mask with no day in it is rejected on load instead of quietly disabling the
  rule. Anything the rule was managing is restored when its window closes.
- **Working-set trimming.** After a group is suspended, flushes its resident
  memory to the page file. Off by default and opt-in per rule: it gives back more
  memory, at the cost of a slower first moment after the application resumes.
  Failures here are not treated as errors, because the group is already
  suspended, which is the state that matters.

## Process page

A full process list with system CPU and memory bars, sortable by PID, name, CPU,
memory, thread count, run time, or status. Threads and suspension state come from
one `NtQuerySystemInformation` call per sample rather than a handle per process,
so a process suspended by anything — Lazy Process or another tool — is shown as
paused. A toolhelp snapshot is the fallback if that query is unavailable.
Processes managed by a rule are marked, and the rows filter on name, path, or PID.

Selecting a row opens a detail card for that process: its name and PID, its parent
PID, its full path, and the complete command line the OS reports. The command line
is there because the process name alone rarely says which of several instances a
row is — two `node.exe` entries look identical until you can see the script each
was started with. From the card the command line can be copied to the clipboard,
or the containing folder opened in Explorer. The command line is read in memory
for display and for the command matchers, and is never persisted.

Selecting a row also allows two actions: creating a path rule for it, or ending
it. Both act on the selected PID and revalidate the process identity first, so a
sample refreshed between the click and the action cannot redirect it at another
process. An expanded status card on the overview page lists a group's process
tree with its per-process CPU and memory, plus the countdown to the next action,
and can restore that one group or exclude it for the rest of the run. That restore
and exclusion are addressed by the group's root PID for the same reason: the
status list is rebuilt every tick, so a stored row number could name a different
group by the time the button is pressed. A session exclusion lasts until that
process exits; an exclusion that should outlive a restart belongs in the rule.

## Global settings

Sample interval, the CPU percentage and the per-sample I/O budget a group must
stay under to count as quiet, the interface zoom, and whether to hold off entirely
while a full-screen game or a presentation is on screen — on by default, because a
full-screen application makes every background group look idle. The sample
interval defaults to 5 seconds and backs off while nothing is happening. The
start-with-Windows toggle is checked against the registry rather than trusting
what was last written, so the checkbox reflects what Windows will actually do.

The interface follows the Windows light/dark setting, or can be pinned to either
palette; the choice is stored in the configuration.

### Interface zoom

`Ctrl` + mouse wheel zooms the interface, as do `Ctrl` + `+`, `Ctrl` + `-`, and
`Ctrl` + `0` to reset; the settings page has buttons for the same thing. The zoom
raises the window's scale factor, so text is re-rasterised larger and stays sharp
rather than being stretched. It is stored in the configuration and restored on the
next start.

Two details are deliberate. The wheel is taken before the widget under the cursor
sees it, so zooming does not also scroll the page; and a touchpad's fine-grained
pixel deltas are accumulated and spent a notch at a time, so a precision touchpad
cannot zoom at event rate. The new zoom is applied immediately but written to disk
only after the gesture settles, because saving rewrites and flushes the whole
configuration.

The zoom is also capped to the largest one whose window still fits the monitor's
work area. Without that cap, zooming on a 1920×1080 display pushed the bottom of
the window — including the settings row that controls the zoom — behind the
taskbar with no way back. The cap is recomputed from the display each time, so
moving the window to a larger monitor restores the full range, and the window is
nudged back inside the work area after it grows.

## Safety model

- A group must be unfocused and remain below the configured CPU and I/O limits.
- Tier 1 uses Below Normal priority and Windows process power throttling.
- Tier 2 process suspension is disabled until explicitly enabled per rule.
- Returning the host application to the foreground restores its entire tree.
- `Ctrl+Alt+Shift+F12` and the tray menu restore every managed process.
- A separate watchdog restores priority, power-throttling, and suspended state if
  Lazy Process exits or crashes.
- An optional UAC-elevated helper handles protected processes over a local-only
  pipe and exits with the main app.
- PID, process creation time, and executable path are revalidated before each
  action.

The utility never records terminal output, keyboard input, or clipboard content.
Command lines are read in memory only, to evaluate the command matchers; they are
never written to the configuration, the event log, or the recovery journal.

Nothing is ever terminated automatically. The process page can end a process, but
only through an explicit click and a confirmation dialog that names the target;
the identity is revalidated against the handle first, so a PID recycled between
the click and the call cannot be hit by mistake. A managed process is restored to
its original priority and resumed before it is ended.

### The elevated helper

Processes running as another user, or at a higher integrity level, cannot be
managed directly. With elevation enabled, Lazy Process starts a UAC-elevated copy
of itself that performs actions on those processes on request.

The pipe it listens on is per-launch and unguessable: its name carries a random
128-bit nonce from `BCryptGenRandom`, and the helper verifies the connecting
client's PID and start time before accepting a single command. It serves only
`Local\` names, so it is not reachable from another machine, and it exits with the
main application.

## Configuration

Configuration, the recovery journal, and a rolling event log live under the
current user's application data directory, in `LazyProcess\Lazy Process\config\`:

| File | Contents |
| --- | --- |
| `config.json` | settings and rules |
| `events.log` | rolling event log, capped at 200 entries / 512 KiB |
| `suspended.json` | recovery journal |
| `suspended-elevated.json` | journal for the elevated helper |
| `*.lock` | lease files that keep one instance per journal |

The directory is `%LOCALAPPDATA%` by default, but an installation that already has
its files in `%APPDATA%` stays there so an upgrade does not split the config and
the journal across two directories. **设置** shows the resolved paths and has
buttons to open the folder, open the log, and clear it.

Launching a second copy activates the running instance instead of starting a
second tray icon. If the configuration file cannot be read, monitoring stays off
and writes are refused rather than replacing the file with defaults, so a
corrupted or hand-edited file never costs you the rules in it — the app reports
the problem and leaves the file alone.

## Development

The four gates CI runs, in the same order:

```powershell
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

The toolchain is pinned in `rust-toolchain.toml`, so a local checkout and CI
compile and lint identically. Clippy runs with `all` and `pedantic` at `deny`, so
new lints are errors; that is deliberate, and it is why the toolchain is pinned
rather than following `stable`.

The project is Windows-only: the `windows` crate bindings and the tray integration
do not build elsewhere. CI additionally runs `cargo audit` against the RustSec
advisory database.

## License

[MIT](LICENSE)
