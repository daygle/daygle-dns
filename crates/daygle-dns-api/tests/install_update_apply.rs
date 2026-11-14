//! Run the install branch of `update-apply.sh` without root or systemd.
//!
//! The canonical installer is a stub that replaces the binary and exits
//! successfully. The health endpoint fails once, so the apply script must put
//! the kept binary back, restart, and report that the previous version is
//! running again. No real service, root or network is involved.

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

fn write_exec(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    let mut mode = fs::metadata(path).unwrap().permissions();
    mode.set_mode(0o755);
    fs::set_permissions(path, mode).unwrap();
}

fn sha256(path: &Path) -> String {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("sha256sum");
    assert!(output.status.success(), "sha256sum failed");
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

#[test]
fn install_restores_the_previous_binary_when_health_fails() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    let exe = root.join("daygle-dns");
    let models = root.join("models");
    let updates = root.join("updates");
    let staging = updates.join("staging");
    let gui = root.join("gui");
    let bin = root.join("bin");
    for path in [&models, &staging, &gui, &bin] {
        fs::create_dir_all(path).unwrap();
    }
    fs::write(&exe, b"old binary").unwrap();
    fs::write(
        root.join("daygle-dns.toml"),
        "[api]\nlisten = \"127.0.0.1\"\nport = 5380\n",
    )
    .unwrap();

    let payload = staging.join("apply.bin");
    fs::write(&payload, b"staged installer payload").unwrap();
    fs::write(
        staging.join("apply.json"),
        format!(
            "{{\"kind\":\"install\",\"version\":\"9.9.9\",\"sha256\":\"{}\"}}",
            sha256(&payload)
        ),
    )
    .unwrap();
    fs::write(updates.join("request"), "").unwrap();

    let restarts = root.join("restarts.log");
    let healthy = root.join("healthy");
    let script =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/update-apply.sh"))
            .unwrap()
            .replace("__DAYGLE_DNS_EXE__", &exe.display().to_string())
            .replace("__DAYGLE_DNS_UPDATES_DIR__", &updates.display().to_string())
            .replace("__DAYGLE_DNS_MODELS_DIR__", &models.display().to_string())
            .replace("__DAYGLE_DNS_USER__", &current_user());
    fs::write(root.join("apply.sh"), script).unwrap();

    write_exec(
        &bin.join("systemctl"),
        &format!(
            "#!/bin/sh\ncase \"$1\" in\nrestart) echo restart >> '{}'; : > '{}' ;;\nis-active) [ -f '{}' ] && exit 0; exit 3 ;;\nshow) echo 123 ;;\nstart) exit 0 ;;\nesac\nexit 0\n",
            restarts.display(),
            healthy.display(),
            healthy.display()
        ),
    );
    write_exec(&bin.join("sleep"), "#!/bin/sh\nexit 0\n");

    // The canonical installer is written by the first root fetch and replaces
    // the binary. It exits successfully, so only the health check can trigger
    // the rollback. Health stays down until the rollback's restart creates the
    // marker; the sleep stub makes the 90-second wait loop instant.
    write_exec(
        &bin.join("curl"),
        &format!(
            r#"#!/bin/sh
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-o" ]; then out=$arg; fi
  prev=$arg
done
if [ -n "$out" ]; then
  cat > "$out" <<'INSTALLER'
#!/bin/sh
# DAYGLE_DNS_GUI_UPDATE_SAFE_V1
printf 'bad binary' > '{}'
exit 0
INSTALLER
  exit 0
fi
case "$*" in
  *api/health*)
    [ -f '{}' ] && exit 0
    exit 22
    ;;
esac
exit 0
"#,
            exe.display(),
            healthy.display()
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
    assert!(
        !output.status.success(),
        "the apply script must fail when the updated binary never becomes healthy"
    );

    assert_eq!(
        fs::read_to_string(&exe).unwrap(),
        "old binary",
        "the kept binary is put back"
    );
    let state = fs::read_to_string(gui.join("state.json")).unwrap();
    assert!(state.contains("\"phase\":\"error\""), "{state}");
    assert!(
        state.contains("was installed but did not come up, so the previous version was restored and is running again"),
        "{state}"
    );
    assert!(
        state.contains("Details in apply.log"),
        "the failure points at the log: {state}"
    );
    let restarted = fs::read_to_string(&restarts).unwrap_or_default();
    assert_eq!(
        restarted.lines().count(),
        1,
        "the rollback restarted the service once: {restarted}"
    );
    let calls = fs::read_to_string(gui.join("apply.log")).unwrap_or_default();
    assert!(
        calls.contains("health check failed after installing v9.9.9"),
        "the health failure is logged: {calls}"
    );
    assert!(
        !updates.join("request.processing").exists(),
        "the failed run consumes its request"
    );
}
