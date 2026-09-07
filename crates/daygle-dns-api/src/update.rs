//! Web-console self-update: builds the latest source and swaps the running
//! binary in place, mirroring what `install.sh` does for an existing
//! installation (clone, `cargo build --release`, install to the current exe
//! path, restart the systemd unit).
//!
//! The heavy lifting runs as a detached POSIX `sh` helper (embedded below)
//! writing progress to `<temp>/daygle-dns-update/state.json` and its full
//! output to `update.log`. The helper is spawned with its own process group so
//! it keeps running after the server is restarted by the updater itself.
//!
//! Self-update is deliberately opt-in by environment: it is only available on
//! Linux hosts that look like a real install (systemd unit, `/usr/local/bin`
//! binary, or a config under `/etc/`). Tool availability and privilege are
//! handled by the helper at run time: it re-executes under passwordless `sudo`
//! when possible (installed by `install.sh`), otherwise it falls back to the
//! service account's own PATH. Dev/test builds and the Windows/macOS console
//! expose the informational guidance-only mode.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The embedded POSIX `sh` helper that performs the update.
const UPDATE_SCRIPT: &str = include_str!("update.sh");

/// Directory, under the OS temp dir, that holds `update.sh`, `state.json` and
/// `update.log`. Writable by the service user without elevated privileges.
pub fn workspace_dir() -> PathBuf {
    std::env::temp_dir().join("daygle-dns-update")
}

/// Progress snapshot written by the updater helper.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct UpdateState {
    /// One of `""` (idle), `preparing`, `cloning`, `building`, `installing`,
    /// `done` or `error`.
    #[serde(default)]
    pub phase: String,
    #[serde(default)]
    pub pid: i64,
    #[serde(default)]
    pub started_at: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub exit_code: i64,
}

impl UpdateState {
    /// Whether the helper is currently doing work (as opposed to idle, done,
    /// or failed).
    pub fn is_running(&self) -> bool {
        matches!(
            self.phase.as_str(),
            "preparing" | "cloning" | "building" | "installing"
        )
    }

    #[cfg(test)]
    pub fn is_terminal(&self) -> bool {
        matches!(self.phase.as_str(), "done" | "error")
    }
}

/// Read the current state; a missing or unreadable file reads as idle.
pub fn read_state() -> UpdateState {
    let path = workspace_dir().join("state.json");
    let Ok(text) = std::fs::read_to_string(path) else {
        return UpdateState::default();
    };
    serde_json::from_str(&text).unwrap_or_default()
}

/// Last `max` bytes of the updater's combined output.
pub fn log_tail(max: usize) -> String {
    let path = workspace_dir().join("update.log");
    let Ok(bytes) = std::fs::read(path) else {
        return String::new();
    };
    let start = bytes.len().saturating_sub(max);
    String::from_utf8_lossy(&bytes[start..]).to_string()
}

/// Whether a `sh`, `git` and `cargo` exist on `PATH`.
fn tools_present() -> bool {
    ["sh", "git", "cargo"].iter().all(|tool| {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {tool}"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
}

/// Whether the CLI tool reports success for a host it can update: request the
/// worker process started for `pid` is measurable presence. Walk /proc (if
/// present) or fall back to `kill -0`.
#[cfg(unix)]
fn pid_alive(pid: i64) -> bool {
    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn pid_alive(_pid: i64) -> bool {
    false
}

/// Whether a self-update is possible for this host.
///
/// Only real install-managed Linux hosts qualify: systemd unit present, the
/// binary at `/usr/local/bin/daygle-dns`, or the config under `/etc/`. A
/// dev/test binary is never updated in place. Tool availability is reported
/// separately by [`gates`], not as a hard gate, so a genuine install still
/// offers the button when the daemon account's PATH is bare (cargo is often
/// installed to `/root/.cargo/bin`, invisible to the systemd service user).
pub fn can_update(config_dir: Option<&Path>) -> bool {
    std::env::consts::OS == "linux" && has_install_evidence(config_dir)
}

/// Install evidence markers, in order: systemd unit, the conventional binary
/// location, or the config living under `/etc/`.
fn has_install_evidence(config_dir: Option<&Path>) -> bool {
    if Path::new("/etc/systemd/system/daygle-dns.service").is_file() {
        return true;
    }
    if std::env::current_exe()
        .map(|exe| exe.as_path() == Path::new("/usr/local/bin/daygle-dns"))
        .unwrap_or(false)
    {
        return true;
    }
    if let Some(dir) = config_dir {
        if dir.to_string_lossy().starts_with("/etc/") {
            return true;
        }
    }
    false
}

/// Human-readable reasons an in-place update is unavailable on this host, for
/// the console's "Current Installation" card.
pub fn gates(config_dir: Option<&Path>) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if std::env::consts::OS != "linux" {
        missing.push("host OS is not Linux");
    }
    if !tools_present() {
        missing.push("sh, git, or cargo not found on this account's PATH");
    }
    if !has_install_evidence(config_dir) {
        missing.push(
            "no install evidence (systemd unit, /usr/local/bin/daygle-dns binary, or config under /etc)",
        );
    }
    missing
}

/// Whether an update run is currently active. A state marked running whose
/// recorded helper is no longer alive is treated as stale/idle (the server may
/// have restarted underneath it).
fn update_in_progress() -> bool {
    let st = read_state();
    st.is_running() && (st.pid <= 0 || pid_alive(st.pid))
}

/// Reasons `start` can refuse to begin an update.
#[derive(Debug)]
pub enum StartError {
    /// This host cannot self-update (see [`can_update`]).
    NotUpdateable,
    /// A prior run has not finished yet.
    AlreadyRunning,
    Io(std::io::Error),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::NotUpdateable => write!(f, "self-update is not available on this host"),
            StartError::AlreadyRunning => write!(f, "an update is already in progress"),
            StartError::Io(e) => write!(f, "failed to start the update: {e}"),
        }
    }
}

/// Begin an update run. Resets the state file, writes the embedded helper and
/// spawns it detached; returns the helper's pid.
pub fn start(exe: &Path, config_dir: Option<&Path>) -> Result<u32, StartError> {
    if !can_update(config_dir) {
        return Err(StartError::NotUpdateable);
    }
    if update_in_progress() {
        return Err(StartError::AlreadyRunning);
    }
    let dir = workspace_dir();
    std::fs::create_dir_all(&dir).map_err(StartError::Io)?;
    std::fs::write(dir.join("update.sh"), UPDATE_SCRIPT).map_err(StartError::Io)?;
    // Prime the state so the console shows activity the moment the request
    // returns; the helper overwrites it with its own pid/message immediately.
    std::fs::write(
        dir.join("state.json"),
        r#"{"phase":"preparing","pid":0,"started_at":"","message":"Preparing update…","exit_code":0}"#,
    )
    .map_err(StartError::Io)?;
    spawn(script_path(&dir), exe, &dir).map_err(StartError::Io)
}

fn script_path(dir: &Path) -> PathBuf {
    dir.join("update.sh")
}

/// Spawn the helper detached. On Unix the child gets its own process group so
/// a service restart (which only signals the service's cgroup) cannot take it
/// down mid-step.
#[cfg(unix)]
fn spawn(script: PathBuf, exe: &Path, dir: &Path) -> std::io::Result<u32> {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new("sh");
    cmd.arg(&script)
        .arg(exe)
        .arg(dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // `process_group(0)` makes the child a session/group leader. Combined with
    // a null controlling terminal this detaches it from the server process.
    cmd.process_group(0);
    let child = cmd.spawn()?;
    Ok(child.id())
}

#[cfg(not(unix))]
fn spawn(_script: PathBuf, _exe: &Path, _dir: &Path) -> std::io::Result<u32> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "self-update is only supported on Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_roundtrips() {
        let st = UpdateState {
            phase: "building".to_string(),
            pid: 4242,
            started_at: "2026-09-07T00:00:00Z".to_string(),
            message: "compiling…".to_string(),
            exit_code: 0,
        };
        let json = serde_json::to_string(&st).unwrap();
        let back: UpdateState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, st);
        assert!(back.is_running());
        assert!(!back.is_terminal());
    }

    #[test]
    fn missing_state_is_idle() {
        // read_state reads a fixed path; the default is the idle shape we need.
        let idle = UpdateState::default();
        assert!(idle.phase.is_empty());
        assert!(!idle.is_terminal() && !idle.is_running());
    }

    #[test]
    fn partial_state_json_is_tolerated() {
        let st: UpdateState =
            serde_json::from_str(r#"{"phase":"done","message":"ok"}"#).unwrap();
        assert_eq!(st.phase, "done");
        assert_eq!(st.message, "ok");
        assert_eq!(st.pid, 0);
        assert!(st.is_terminal());
    }

    #[test]
    fn error_and_done_are_terminal() {
        for phase in ["done", "error"] {
            let st = UpdateState {
                phase: phase.to_string(),
                ..Default::default()
            };
            assert!(st.is_terminal(), "{phase} should be terminal");
            assert!(!st.is_running(), "{phase} should not be running");
        }
    }

    #[test]
    fn cfg_off_target_is_never_updateable() {
        // This box is Windows: self-update must be refused outright.
        #[cfg(target_os = "windows")]
        assert!(!can_update(Some(Path::new("/etc/daygle-dns"))));
        #[cfg(not(target_os = "windows"))]
        {
            // Harmless on Linux CI: no install evidence on CI hosts.
            assert!(!can_update(None));
        }
    }

    #[test]
    fn unmet_conditions_are_listed_for_the_console() {
        // Whatever the platform, a host that cannot update reports at least one
        // actionable gate, and engineers can read them off the /api/update
        // response without tracing the boolean.
        if !can_update(None) {
            let missing = gates(None);
            assert!(!missing.is_empty());
            assert!(missing
                .iter()
                .all(|g| !g.is_empty() && g.contains(' ')));
        }
    }
}