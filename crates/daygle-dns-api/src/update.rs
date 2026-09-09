//! Web-console self-update: fetches the newest release binary and swaps the
//! running binary in place, restarting the systemd unit afterwards.
//!
//! Two paths, in order of preference (both handled by the embedded `sh`
//! helper):
//!
//! 1. **Prebuilt release** (default): download the release asset for this
//!    architecture from GitHub Releases, verify its sha256 checksum, swap it
//!    in place. Needs only a downloader (curl or wget) - no Rust toolchain,
//!    no compilation, seconds instead of minutes. Assets are published by
//!    the release CI workflow (`.github/workflows/release.yml`).
//! 2. **Source build** (fallback): only when no release asset can be
//!    fetched, clone and build as `install.sh` does - needs git + cargo.
//!
//! Progress is written to `<temp>/daygle-dns-update/state.json` and full
//! output to `update.log`. The helper is spawned with its own process group
//! so it keeps running after the server is restarted by the updater itself.
//!
//! Privilege is deliberately narrow: the helper invokes root only for the
//! binary swap and the service restart, through the root-owned
//! `update-priv.sh` that `install.sh` provisions under a sudoers rule
//! permitting exactly that script. Older installs with a passwordless ALL
//! grant keep working via the generic sudo fallback. Self-update is opt-in
//! by environment: only Linux hosts that look like a real install (systemd
//! unit, `/usr/local/bin` binary, or a config under `/etc/`). Dev/test
//! builds and the Windows/macOS console expose guidance-only mode.

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
    /// One of `""` (idle), `preparing`, `downloading`, `cloning`,
    /// `building`, `installing`, `done` or `error`.
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
            "preparing" | "downloading" | "cloning" | "building" | "installing"
        )
    }

    #[cfg(test)]
    pub fn is_terminal(&self) -> bool {
        matches!(self.phase.as_str(), "done" | "error")
    }
}

/// Grace period for a primed `preparing` state whose helper has not yet
/// recorded its pid. Beyond it the run is reported as failed instead of
/// wedging the pipeline in a forever-"running" shape.
const START_GRACE_SECS: u64 = 60;

/// Read the current state; a missing or unreadable file reads as idle.
///
/// A run-shaped state whose helper is provably gone (dead pid, or a primed
/// pid-less state older than the start grace period) is reported as `error`
/// so both the API and the console stop treating a dead run as in progress.
pub fn read_state() -> UpdateState {
    let path = workspace_dir().join("state.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return UpdateState::default();
    };
    let st: UpdateState = serde_json::from_str(&text).unwrap_or_default();
    let age = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok());
    normalize_stale(st, age, pid_alive)
}

/// Map a stale "running" snapshot to a terminal `error` one.
///
/// The helper can die mid-run (killed alongside the service, OOM, crash) and
/// leave `cloning`/`building`/`installing` behind forever; without this, the
/// console would poll forever and `start` would refuse every new run with
/// "already in progress". `state_age` is the age of the state file itself and
/// only applies to pid-less (primed) states.
fn normalize_stale(
    st: UpdateState,
    state_age: Option<std::time::Duration>,
    alive: impl Fn(i64) -> bool,
) -> UpdateState {
    if !st.is_running() {
        return st;
    }
    let stale = if st.pid > 0 {
        !alive(st.pid)
    } else {
        matches!(state_age, Some(age) if age.as_secs() > START_GRACE_SECS)
    };
    if !stale {
        return st;
    }
    UpdateState {
        phase: "error".to_string(),
        pid: st.pid,
        started_at: st.started_at,
        message: "the updater helper is no longer running (the server may have restarted mid-run); it is safe to start a new update".to_string(),
        exit_code: 1,
    }
}

/// Write a state snapshot atomically (temp file + rename) so a concurrent
/// status poll never observes a truncated file - which previously read as
/// "idle" and could admit a second concurrent update run.
fn write_state_atomic(path: &Path, st: &UpdateState) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(st).unwrap_or_default())?;
    std::fs::rename(&tmp, path)
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Last `max` bytes of the updater's combined output. Reads only the tail
/// from disk: the log accumulates a full release build's output, so reading
/// the whole file on every status poll would be wasteful.
pub fn log_tail(max: usize) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let path = workspace_dir().join("update.log");
    let mut file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return String::new(),
    };
    let len = match file.metadata() {
        Ok(m) => m.len(),
        Err(_) => return String::new(),
    };
    if len == 0 {
        return String::new();
    }
    let start = len.saturating_sub(max as u64);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut buf = Vec::with_capacity((len - start) as usize);
    match file.read_to_end(&mut buf) {
        Ok(_) => String::from_utf8_lossy(&buf).to_string(),
        Err(_) => String::new(),
    }
}

/// Whether `sh` and a downloader (curl or wget) exist on `PATH`.
///
/// The prebuilt-release path needs only these; git and cargo are required
/// solely by the source-build fallback, so they are deliberately not gates.
fn tools_present() -> bool {
    let have = |tool: &str| {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {tool}"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    have("sh") && (have("curl") || have("wget"))
}

/// Whether the updater helper process `pid` is still alive.
///
/// Existence is checked via `/proc/<pid>` rather than `kill -0`: when the
/// helper re-executed under sudo it runs as root, and the service account's
/// `kill -0` fails with EPERM on it even though the process is alive - which
/// would mark healthy runs as stale. The cmdline is matched against the
/// updater workspace so a recycled PID is not mistaken for a live helper.
#[cfg(unix)]
fn pid_alive(pid: i64) -> bool {
    if pid <= 0 {
        return false;
    }
    let proc_dir = PathBuf::from(format!("/proc/{pid}"));
    if !proc_dir.is_dir() {
        return false;
    }
    match std::fs::read_to_string(proc_dir.join("cmdline")) {
        Ok(cmdline) => cmdline.replace('\0', " ").contains("daygle-dns-update"),
        // Exists but unreadable: assume it is still the helper.
        Err(_) => true,
    }
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
/// separately by [`gates`], not as a hard gate: the primary update path
/// needs only a downloader, and privilege is handled by the helper at run
/// time through the installer-provisioned privilege helper.
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
        missing.push("sh or a downloader (curl/wget) not found on this account's PATH");
    }
    if !has_install_evidence(config_dir) {
        missing.push(
            "no install evidence (systemd unit, /usr/local/bin/daygle-dns binary, or config under /etc)",
        );
    }
    missing
}

/// Whether an update run is currently active. `read_state` normalizes stale
/// run-shaped snapshots (dead helper, expired primed state) to `error`, so a
/// plain phase check is sufficient here.
fn update_in_progress() -> bool {
    read_state().is_running()
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
    // Each run starts a fresh log so output cannot grow without bound across
    // repeated updates.
    let _ = std::fs::write(dir.join("update.log"), b"");
    // Prime the state so the console shows activity the moment the request
    // returns; the helper overwrites it with its own pid/message immediately.
    let primed = UpdateState {
        phase: "preparing".to_string(),
        pid: 0,
        started_at: now_rfc3339(),
        message: "Preparing update…".to_string(),
        exit_code: 0,
    };
    let state_path = dir.join("state.json");
    write_state_atomic(&state_path, &primed).map_err(StartError::Io)?;
    match spawn(script_path(&dir), exe, &dir) {
        Ok(pid) => Ok(pid),
        Err(e) => {
            // Never leave the primed "preparing" snapshot behind: nothing
            // would overwrite it and every future start would be refused
            // with "already in progress".
            let failed = UpdateState {
                phase: "error".to_string(),
                pid: 0,
                started_at: now_rfc3339(),
                message: format!("failed to launch the updater helper: {e}"),
                exit_code: 1,
            };
            let _ = write_state_atomic(&state_path, &failed);
            Err(StartError::Io(e))
        }
    }
}

fn script_path(dir: &Path) -> PathBuf {
    dir.join("update.sh")
}

/// Reset the recorded run state so a terminal `done`/`error` snapshot stops
/// being shown. Intentionally refuses while a run is in progress: the helper
/// would immediately overwrite the file anyway, and the console relies on the
/// run-shaped state to keep polling.
pub fn clear_state() -> Result<(), StartError> {
    if update_in_progress() {
        return Err(StartError::AlreadyRunning);
    }
    let path = workspace_dir().join("state.json");
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        // No state file is already "dismissed".
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StartError::Io(e)),
    }
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
    fn clear_state_removes_terminal_snapshot() {
        let dir = workspace_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let st = UpdateState {
            phase: "error".to_string(),
            message: "boom".to_string(),
            ..Default::default()
        };
        write_state_atomic(&dir.join("state.json"), &st).unwrap();
        clear_state().expect("clear_state succeeds for a terminal snapshot");
        assert!(!dir.join("state.json").exists());
        // Clearing again (nothing recorded) is still a success.
        clear_state().expect("clear_state on a missing state file is a no-op");
    }

    #[test]
    #[cfg(unix)]
    fn clear_state_refuses_while_run_in_progress() {
        let dir = workspace_dir();
        std::fs::create_dir_all(&dir).unwrap();
        // Our own pid is trivially alive, so the state reads as in progress.
        let st = UpdateState {
            phase: "building".to_string(),
            pid: std::process::id() as i64,
            ..Default::default()
        };
        write_state_atomic(&dir.join("state.json"), &st).unwrap();
        assert!(matches!(clear_state(), Err(StartError::AlreadyRunning)));
        // Clean up so the fake running state cannot leak elsewhere.
        let _ = std::fs::remove_file(dir.join("state.json"));
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

    #[test]
    fn stale_running_states_are_normalized_to_error() {
        let running = |pid: i64| UpdateState {
            phase: "building".to_string(),
            pid,
            started_at: "2026-09-07T00:00:00Z".to_string(),
            message: "compiling…".to_string(),
            exit_code: 0,
        };

        // A run-shaped state whose helper is dead becomes a terminal error.
        let dead = normalize_stale(running(4242), None, |_| false);
        assert_eq!(dead.phase, "error");
        assert!(dead.is_terminal());
        assert!(!dead.is_running());

        // A live helper is reported unchanged.
        let live = normalize_stale(running(7), None, |_| true);
        assert_eq!(live.phase, "building");
        assert!(live.is_running());

        // A primed (pid 0) state inside the start grace period still counts
        // as running; past it, it is stale.
        let primed = UpdateState {
            phase: "preparing".to_string(),
            pid: 0,
            ..Default::default()
        };
        let fresh = normalize_stale(
            primed.clone(),
            Some(std::time::Duration::from_secs(5)),
            |_| false,
        );
        assert_eq!(fresh.phase, "preparing");
        let expired = normalize_stale(
            primed,
            Some(std::time::Duration::from_secs(START_GRACE_SECS + 60)),
            |_| false,
        );
        assert_eq!(expired.phase, "error");

        // Terminal states are never rewritten, whatever their age.
        let done = normalize_stale(
            UpdateState {
                phase: "done".to_string(),
                ..Default::default()
            },
            Some(std::time::Duration::from_secs(999_999)),
            |_| false,
        );
        assert_eq!(done.phase, "done");
    }
}