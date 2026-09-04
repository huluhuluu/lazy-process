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
- A separate watchdog restores priority, power-throttling, and suspended state if Lazy Process exits or crashes.
- An optional UAC-elevated helper handles protected processes over a local-only pipe and exits with the main app.
- PID, process creation time, and executable path are revalidated before each action.

The utility never records terminal output, keyboard input, or clipboard content.
Command lines are read in memory only, to evaluate the command matchers; they are
never written to the configuration, the event log, or the recovery journal.

Nothing is ever terminated automatically. The process page can end a process, but
only through an explicit click and a confirmation dialog that names the target;
the identity is revalidated against the handle first, so a PID recycled between
the click and the call cannot be hit by mistake. A managed process is restored to
its original priority and resumed before it is ended.

## Build

```powershell
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

Run `target/release/lazy-process.exe`. Configuration, the recovery journal, and a
rolling event log are stored under the current user's local application data
directory. Launching a second copy activates the running instance instead of
starting another tray icon.

## Rules

Each rule needs at least one of: process name, full executable path, path
fragment, command-line fragment, or command-line regex. An ancestor process name
narrows an existing condition but cannot select on its own. Exclusions are
matched first, and anything they hit is left alone. Everything is editable from
the rules page; the configuration file remains hand-editable and unknown fields
are preserved on save.

While a rule is being edited, a live preview lists the processes it would match
right now, marking each as a host, a descendant, or excluded. Rules can be
exported to and imported from a JSON file; an imported rule that collides with an
existing id is renamed rather than overwriting it. Deleted presets can be brought
back from the rules page without touching anything else.

Two optional per-rule settings:

- **Schedule.** Restricts a rule to a time window and a set of weekdays. Windows
  that wrap past midnight are supported, so 22:00–06:00 means the night. Leaving
  the window empty means the whole day, and clearing every weekday means every
  day, so a half-filled schedule cannot silently disable a rule. Anything the
  rule was managing is restored when its window closes.
- **Working-set trimming.** After a group is suspended, flushes its resident
  memory to the page file. Off by default and opt-in per rule: it gives back more
  memory, at the cost of a slower first moment after the application resumes.
  Failures here are not treated as errors, because the group is already
  suspended, which is the state that matters.

## Process page

A full process list with system CPU and memory bars, sortable by PID, name, CPU,
memory, thread count, run time, or status. Threads come from a single toolhelp
snapshot per sample rather than a handle per process. Processes managed by a rule
are marked, and the rows filter on name, path, or PID.

Selecting a row allows two things: creating a path rule for it, or ending it. An
expanded status card on the overview page lists a group's process tree with its
per-process CPU and memory, plus the countdown to the next action, and can
restore that one group or exclude it for the rest of the run. A session exclusion
lasts until that process exits; an exclusion that should outlive a restart
belongs in the rule.

## Global settings

Sample interval, the CPU percentage and the per-sample I/O budget a group must
stay under to count as quiet, and whether to hold off entirely while a full-screen
game or a presentation is on screen — on by default, because a full-screen
application makes every background group look idle.

The interface follows the Windows light/dark setting, or can be pinned to either
palette; the choice is stored in the configuration.
