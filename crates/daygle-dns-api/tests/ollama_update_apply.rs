//! Run the Ollama branch of `update-apply.sh` without root or systemd.
//!
//! The setup helper beside the apply script is a stub that records the
//! action it was given. The request may only select an action from a fixed
//! list, and a missing helper fails with a clear message.

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

fn write_exec(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    let mut mode = fs::metadata(path).unwrap().permissions();
    mode.set_mode(0o755);
    fs::set_permissions(path, mode).unwrap();
}

fn sha256(path: &Path) -> String {
    let output = Command::new("sha256sum").arg(path).output().unwrap();
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

fn current_user() -> String {
    let output = Command::new("id").arg("-un").output().unwrap();
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

struct Run {
    _dir: TempDir,
    root: PathBuf,
    updates: PathBuf,
    gui: PathBuf,
    ok: bool,
}

/// Stage an Ollama request for `action` and run the apply script, with
/// `setup` as the helper beside it (or none).
fn run(action: &[u8], setup: Option<&str>) -> Run {
    let dir = TempDir::new().unwrap();
    let root = dir.path().to_path_buf();
    let models = root.join("models");
    let updates = root.join("updates");
    let staging = updates.join("staging");
    let gui = root.join("gui");
    let bin = root.join("bin");
    for path in [&models, &staging, &gui, &bin] {
        fs::create_dir_all(path).unwrap();
    }
    let payload = staging.join("apply.bin");
    fs::write(&payload, action).unwrap();
    fs::write(
        staging.join("apply.json"),
        format!(
            "{{\"kind\":\"ollama\",\"version\":\"0\",\"sha256\":\"{}\"}}",
            sha256(&payload)
        ),
    )
    .unwrap();
    fs::write(updates.join("request"), "").unwrap();
    let script =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/update-apply.sh"))
            .unwrap()
            .replace(
                "__DAYGLE_DNS_EXE__",
                &root.join("daygle-dns").display().to_string(),
            )
            .replace("__DAYGLE_DNS_UPDATES_DIR__", &updates.display().to_string())
            .replace("__DAYGLE_DNS_MODELS_DIR__", &models.display().to_string())
            .replace("__DAYGLE_DNS_USER__", &current_user());
    fs::write(root.join("apply.sh"), script).unwrap();
    if let Some(setup) = setup {
        write_exec(&root.join("ollama-setup.sh"), setup);
    }
    write_exec(&bin.join("sleep"), "#!/bin/sh\nexit 0\n");
    // Nothing in the Ollama branch may touch the DNS service.
    write_exec(
        &bin.join("systemctl"),
        &format!(
            "#!/bin/sh\necho \"$@\" >> '{}'\nexit 0\n",
            root.join("systemctl.log").display()
        ),
    );
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new("sh")
        .arg(root.join("apply.sh"))
        .env("PATH", path)
        .env("DAYGLE_DNS_UPDATE_DIR", &gui)
        .output()
        .unwrap();
    Run {
        ok: output.status.success(),
        _dir: dir,
        root,
        updates,
        gui,
    }
}

fn state(run: &Run) -> String {
    fs::read_to_string(run.gui.join("state.json")).unwrap_or_default()
}

const RECORDING_SETUP: &str = "#!/bin/sh\necho \"$1\" > \"$(dirname \"$0\")/setup-called\"\necho '[ollama-setup] Ollama updated from 0.5.1 to 0.6.0'\nexit 0\n";

#[test]
fn an_update_request_runs_the_setup_helper_and_reports_done() {
    let run = run(b"update", Some(RECORDING_SETUP));
    assert!(run.ok, "{}", state(&run));
    assert_eq!(
        fs::read_to_string(run.root.join("setup-called"))
            .unwrap()
            .trim(),
        "update"
    );
    let state = state(&run);
    assert!(state.contains("\"phase\":\"done\""), "{state}");
    assert!(
        state.contains("Ollama updated from 0.5.1 to 0.6.0"),
        "{state}"
    );
    assert!(!run.updates.join("request.processing").exists());
    assert!(
        !fs::read_to_string(run.root.join("systemctl.log"))
            .unwrap_or_default()
            .contains("daygle-dns"),
        "the DNS service is left alone"
    );
}

#[test]
fn only_the_fixed_actions_are_accepted() {
    let run = run(b"rm -rf /; install", Some(RECORDING_SETUP));
    assert!(!run.ok);
    assert!(!run.root.join("setup-called").exists());
    assert!(state(&run).contains("unknown action"), "{}", state(&run));
}

#[test]
fn a_failing_helper_is_reported() {
    let run = run(
        b"install",
        Some(
            "#!/bin/sh\necho '[ollama-setup] ERROR: this machine has 1024 MB of memory'\nexit 1\n",
        ),
    );
    assert!(!run.ok);
    let state = state(&run);
    assert!(state.contains("\"phase\":\"error\""), "{state}");
    assert!(state.contains("1024 MB of memory"), "{state}");
}

#[test]
fn a_missing_helper_asks_for_an_update_first() {
    let run = run(b"install", None);
    assert!(!run.ok);
    assert!(
        state(&run).contains("no Ollama setup helper yet"),
        "{}",
        state(&run)
    );
}
