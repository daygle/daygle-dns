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

/// Pre-flight health check result for a single check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightCheck {
    /// Check name (e.g., "sudoers", "disk_space", "permissions").
    pub name: String,
    /// Whether the check passed.
    pub ok: bool,
    /// Human-readable message explaining the result.
    pub message: String,
    /// For failed checks: specific fix instructions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    /// For failed checks: shell commands to run as root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_commands: Option<Vec<String>>,
}

/// Complete pre-flight health check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightResult {
    /// Whether all checks passed and an update can proceed.
    pub ready: bool,
    /// Individual check results.
    pub checks: Vec<PreflightCheck>,
}

/// Run pre-flight health checks to detect issues before starting an update.
/// Returns structured results with specific fix instructions for each failure.
pub fn preflight(config_dir: Option<&Path>) -> PreflightResult {
    let mut checks = Vec::new();

    // Check 1: Platform and install evidence
    let gates = gates(config_dir);
    checks.push(PreflightCheck {
        name: "platform".to_string(),
        ok: gates.is_empty(),
        message: if gates.is_empty() {
            "Host qualifies for in-place updates".to_string()
        } else {
            format!("Missing requirements: {}", gates.join(", "))
        },
        fix: if gates.is_empty() {
            None
        } else {
            Some("Run the installer on the host to set up update prerequisites.".to_string())
        },
        fix_commands: None,
    });

    // Check 2: Sudoers configuration
    if let Some(sudoers_check) = check_sudoers() {
        checks.push(sudoers_check);
    }

    // Check 3: Disk space in temp directory
    if let Some(disk_check) = check_disk_space() {
        checks.push(disk_check);
    }

    // Check 4: Write permissions to binary location
    if let Some(perm_check) = check_binary_permissions() {
        checks.push(perm_check);
    }

    // Check 5: Network connectivity to GitHub
    if let Some(network_check) = check_github_connectivity() {
        checks.push(network_check);
    }

    let ready = checks.iter().all(|c| c.ok);
    PreflightResult { ready, checks }
}

/// Check if sudo configuration is parseable.
/// Returns None if sudo is not required (already root) or not available.
fn check_sudoers() -> Option<PreflightCheck> {
    // If already root, sudo is not needed
    if std::env::consts::OS != "linux" {
        return None;
    }

    // Test if sudo is available and working
    let output = std::process::Command::new("sudo")
        .args(["-n", "true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .ok()?;

    if output.status.success() {
        return Some(PreflightCheck {
            name: "sudoers".to_string(),
            ok: true,
            message: "Sudo configuration is valid".to_string(),
            fix: None,
            fix_commands: None,
        });
    }

    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();

    // Detect actual sudoers parse errors. The audit plugin warning alone
    // (auditd not installed) is non-fatal and should not block updates.
    if stderr.contains("no valid sudoers sources")
        || stderr.contains("parse error in /etc/sudoers")
    {
        let fix_commands = vec![
            "sudo visudo -cf /etc/sudoers".to_string(),
            "sudo visudo -cf /etc/sudoers.d/*".to_string(),
            "sudo sed -i 's/^@includedir/@#includedir/' /etc/sudoers".to_string(),
            "sudo systemctl restart daygle-dns".to_string(),
        ];

        Some(PreflightCheck {
            name: "sudoers".to_string(),
            ok: false,
            message: "The sudo policy on this host is broken (a sudoers file fails to parse, so every sudo command fails).".to_string(),
            fix: Some("The most common cause is an '@includedir /etc/sudoers.d' line appended by older installer versions on sudo < 1.9.3. To fix: 1) Run 'sudo visudo -cf /etc/sudoers /etc/sudoers.d/*' to find the offending file. 2) Change '@includedir' to '#includedir' in /etc/sudoers. 3) Test with 'sudo true'. 4) Restart the service.".to_string()),
            fix_commands: Some(fix_commands),
        })
    } else if stderr.contains("password") || stderr.contains("sorry") {
        Some(PreflightCheck {
            name: "sudoers".to_string(),
            ok: false,
            message: "Passwordless sudo is not configured for this account".to_string(),
            fix: Some("Re-run the installer to provision the privilege helper, or configure passwordless sudo for the service account.".to_string()),
            fix_commands: None,
        })
    } else {
        Some(PreflightCheck {
            name: "sudoers".to_string(),
            ok: false,
            message: format!("Sudo test failed: {}", String::from_utf8_lossy(&output.stderr).trim()),
            fix: Some("Check sudo configuration and ensure the service account has appropriate permissions.".to_string()),
            fix_commands: None,
        })
    }
}

/// Check available disk space in the temp directory.
fn check_disk_space() -> Option<PreflightCheck> {
    #[cfg(unix)]
    {
        let temp_dir = std::env::temp_dir();
        let output = std::process::Command::new("df")
            .arg("--output=avail")
            .arg(&temp_dir)
            .stdout(std::process::Stdio::piped())
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let avail_kb: u64 = stdout
            .lines()
            .nth(1)
            .and_then(|line| line.trim().parse().ok())
            .unwrap_or(0);

        // Need at least 100MB for download, 1GB for source build
        let min_required_mb = 100;
        let avail_mb = avail_kb / 1024;

        if avail_mb >= min_required_mb {
            Some(PreflightCheck {
                name: "disk_space".to_string(),
                ok: true,
                message: format!("{} MB available in {}", avail_mb, temp_dir.display()),
                fix: None,
                fix_commands: None,
            })
        } else {
            Some(PreflightCheck {
                name: "disk_space".to_string(),
                ok: false,
                message: format!("Only {} MB available in {} (need at least {} MB)", avail_mb, temp_dir.display(), min_required_mb),
                fix: Some("Free up disk space in the temp directory before updating.".to_string()),
                fix_commands: None,
            })
        }
    }

    #[cfg(not(unix))]
    None
}

/// Check write permissions to the binary location.
fn check_binary_permissions() -> Option<PreflightCheck> {
    let exe = std::env::current_exe().ok()?;
    let parent = exe.parent()?;

    let metadata = std::fs::metadata(parent).ok()?;
    let writable = metadata.permissions().readonly();

    if !writable {
        Some(PreflightCheck {
            name: "permissions".to_string(),
            ok: true,
            message: format!("Write access to {}", parent.display()),
            fix: None,
            fix_commands: None,
        })
    } else {
        Some(PreflightCheck {
            name: "permissions".to_string(),
            ok: false,
            message: format!("Cannot write to {}", parent.display()),
            fix: Some("Ensure the service account has write permissions to the binary directory, or run the installer to set up proper permissions.".to_string()),
            fix_commands: None,
        })
    }
}

/// Check network connectivity to GitHub releases.
fn check_github_connectivity() -> Option<PreflightCheck> {
    let output = std::process::Command::new("curl")
        .args([
            "-fsSL",
            "--max-time",
            "5",
            "--connect-timeout",
            "2",
            "-o",
            "/dev/null",
            "https://api.github.com/repos/daygle/daygle-dns/releases/latest",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .ok()?;

    if output.status.success() {
        Some(PreflightCheck {
            name: "network".to_string(),
            ok: true,
            message: "GitHub releases are accessible".to_string(),
            fix: None,
            fix_commands: None,
        })
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Some(PreflightCheck {
            name: "network".to_string(),
            ok: false,
            message: format!("Cannot reach GitHub releases: {}", stderr.trim()),
            fix: Some("Check network connectivity and firewall rules. The update requires access to github.com.".to_string()),
            fix_commands: None,
        })
    }
}

/// Cached latest-release version (tag without the leading `v`) and when it
/// was fetched, shared across status polls: the console hits this endpoint
/// every few seconds during a run, and GitHub rate-limits unauthenticated
/// API calls per IP.
static LATEST_RELEASE: std::sync::Mutex<Option<(String, std::time::Instant)>> =
    std::sync::Mutex::new(None);

/// Cache lifetime for the latest-release lookup.
const RELEASE_CACHE_SECS: u64 = 600;

/// Fetch the latest published release version (e.g. `"1.0.2"`), or `None`
/// when GitHub is unreachable, rate-limited, or has no release. Mirrors the
/// updater helper's resolution strategy: the GitHub API first, the
/// `/releases/latest` HTML redirect as fallback.
fn fetch_latest_release_version() -> Option<String> {
    if let Some(guard) = LATEST_RELEASE.lock().ok() {
        if let Some((ver, at)) = guard.as_ref() {
            if at.elapsed().as_secs() < RELEASE_CACHE_SECS {
                return Some(ver.clone());
            }
        }
    }
    let version = fetch_latest_release_uncached()?;
    if let Ok(mut guard) = LATEST_RELEASE.lock() {
        *guard = Some((version.clone(), std::time::Instant::now()));
    }
    Some(version)
}

fn fetch_latest_release_uncached() -> Option<String> {
    // Short timeouts: this runs inline in a status/info request.
    let get = |url: &str| -> Option<String> {
        let out = std::process::Command::new("curl")
            .args([
                "-fsSL",
                "--max-time",
                "5",
                "--connect-timeout",
                "2",
                url,
            ])
            .output()
            .ok()
            .filter(|o| o.status.success())?;
        String::from_utf8_lossy(&out.stdout).into_owned().into()
    };
    let body = get(
        "https://api.github.com/repos/daygle/daygle-dns/releases/latest",
    )?;
    if let Some(tag) = extract_tag_name(&body) {
        return normalize_release_tag(&tag);
    }
    // Fallback: scrape the tag out of the HTML redirect page.
    let body = get(
        "https://github.com/daygle/daygle-dns/releases/latest",
    )?;
    extract_html_tag(&body).and_then(|tag| normalize_release_tag(&tag))
}

/// Pull the `tag_name` value (e.g. `"v1.2.3"`) from the API response.
fn extract_tag_name(body: &str) -> Option<String> {
    let marker = "\"tag_name\"";
    let idx = body.find(marker)?;
    let rest = &body[idx + marker.len()..];
    // Skip the JSON key/value separator (`: `) before the value quote.
    let colon = rest.find(':')?;
    let after = &rest[colon + 1..];
    let start = after.find('"')? + 1;
    let end = after[start..].find('"')? + start;
    Some(after[start..end].to_string())
}

/// Pull the tag out of a `/releases/latest` HTML redirect page.
fn extract_html_tag(body: &str) -> Option<String> {
    let marker = "releases/tag/";
    let idx = body.find(marker)?;
    let rest = &body[idx + marker.len()..];
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '_'))
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    Some(rest[..end].to_string())
}

/// `"v1.2.3"` -> `"1.2.3"`; `None` when the tag does not look like a version.
fn normalize_release_tag(tag: &str) -> Option<String> {
    let t = tag.strip_prefix('v').unwrap_or(tag);
    if t.is_empty() || !t.chars().next().unwrap().is_ascii_digit() {
        return None;
    }
    Some(t.to_string())
}

/// The version of the updater logic this binary embeds. The updater gained
/// its release-download path (and the fixed privilege/swap handling) in
/// 1.0.2; older binaries can only build from source, so an update started
/// from them fails on hosts without a toolchain.
fn updater_min_version() -> &'static str {
    "1.0.2"
}

/// How the installed binary compares to the latest published release, for
/// the console's update page.
pub struct ReleaseComparison {
    /// Latest published release version, e.g. `"1.0.2"`.
    pub latest: String,
    /// Whether the running binary is older than the latest release.
    pub outdated: bool,
    /// Whether the embedded updater is too old to self-update reliably
    /// (it predates the release-download fix): the console then shows a
    /// one-time installer bootstrap hint instead of a run button.
    pub bootstrap_required: bool,
}

/// Compare the running binary with the latest published release. Runs the
/// network lookup only on hosts that can actually self-update, so dev and
/// non-Linux consoles never wait on GitHub.
pub fn release_comparison() -> Option<ReleaseComparison> {
    if !can_update(config_dir_hint()) {
        return None;
    }
    let latest = fetch_latest_release_version()?;
    let installed = daygle_dns_core::VERSION.to_string();
    let outdated = version_lt(&installed, &latest);
    let bootstrap_required = version_lt(&installed, updater_min_version());
    Some(ReleaseComparison {
        latest,
        outdated,
        bootstrap_required,
    })
}

/// The config-dir hint `can_update` needs, resolved the same way the HTTP
/// handlers do (config file under `/etc/` counts as install evidence).
fn config_dir_hint() -> Option<&'static Path> {
    if Path::new("/etc/daygle-dns").is_dir() {
        Some(Path::new("/etc/daygle-dns"))
    } else {
        None
    }
}

/// Numeric semver-ish comparison: true when `a` < `b`. Tolerates prefixes
/// and extra segments (`"1.0.2-rc1"`), comparing only leading numeric parts.
fn version_lt(a: &str, b: &str) -> bool {
    let nums = |s: &str| -> Vec<u64> {
        s.trim_start_matches('v')
            .split(['.', '-'])
            .map_while(|p| p.parse::<u64>().ok())
            .collect()
    };
    let (va, vb) = (nums(a), nums(b));
    for i in 0..va.len().max(vb.len()) {
        let (x, y) = (va.get(i).copied().unwrap_or(0), vb.get(i).copied().unwrap_or(0));
        if x != y {
            return x < y;
        }
    }
    false
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
    fn tag_parsing_handles_api_and_html_shapes() {
        let api = "{ \"tag_name\": \"v1.0.2\", \"name\": \"v1.0.2\" }";
        assert_eq!(extract_tag_name(api).as_deref(), Some("v1.0.2"));
        assert_eq!(extract_tag_name("{}"), None);

        let html = "<html><head><title>Release v1.0.3</title>\n<meta content=\"https://github.com/daygle/daygle-dns/releases/tag/v1.0.3\">";
        assert_eq!(extract_html_tag(html).as_deref(), Some("v1.0.3"));
        assert_eq!(extract_html_tag("no marker here"), None);
        assert_eq!(extract_html_tag("releases/tag/"), None);
    }

    #[test]
    fn release_tags_normalize_to_versions() {
        assert_eq!(normalize_release_tag("v1.0.2").as_deref(), Some("1.0.2"));
        assert_eq!(normalize_release_tag("1.0.2").as_deref(), Some("1.0.2"));
        assert_eq!(normalize_release_tag("latest"), None);
        assert_eq!(normalize_release_tag("v"), None);
    }

    #[test]
    fn version_comparison_covers_semver_shapes() {
        assert!(version_lt("1.0.1", "1.0.2"));
        assert!(!version_lt("1.0.2", "1.0.2"));
        assert!(!version_lt("1.0.2", "1.0.1"));
        assert!(version_lt("1.0", "1.0.1")); // missing segment reads as 0
        assert!(version_lt("v0.9", "1.0")); // v-prefix tolerated
        assert!(!version_lt("1.0.2-rc1", "1.0.2")); // prerelease suffix ignored
        assert!(version_lt("2", "10")); // numeric, not lexicographic
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