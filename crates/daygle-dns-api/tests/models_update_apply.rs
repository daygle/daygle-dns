//! Run the models branch of `update-apply.sh` without root or systemd.
//!
//! The script is copied to a temp directory with its install placeholders
//! rewritten, and `systemctl` and `curl` are stubs on PATH. The staged bundle
//! is a real tar.gz with a manifest, so the checksum, extraction, backup,
//! install, health check, pinned probe, restore and second restart all run as
//! they do on a host. Only privilege separation (runuser) is skipped: the test
//! uses its own user as the service account.

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
fn models_update_probes_the_same_sample_and_restores_on_regression() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    let models = root.join("models");
    let updates = root.join("updates");
    let staging = updates.join("staging");
    let bundle_dir = root.join("bundle");
    let gui = root.join("gui");
    let bin = root.join("bin");
    for path in [&models, &staging, &bundle_dir, &gui, &bin] {
        fs::create_dir_all(path).unwrap();
    }

    let old = models.join("daygle-starter.bin");
    fs::write(&old, b"old model").unwrap();
    fs::write(
        root.join("daygle-dns.toml"),
        "[api]\nlisten = \"127.0.0.1\"\nport = 5380\n",
    )
    .unwrap();

    // A real bundle with one whitelisted model file and its manifest checksum.
    let new_model = bundle_dir.join("daygle-starter.bin");
    fs::write(&new_model, b"new model with a regression").unwrap();
    let model_sha = sha256(&new_model);
    fs::write(
        bundle_dir.join("manifest.json"),
        format!("{{\"files\":[{{\"name\":\"daygle-starter.bin\",\"sha256\":\"{model_sha}\"}}]}}"),
    )
    .unwrap();
    let bundle = staging.join("apply.bin");
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&bundle)
        .arg("-C")
        .arg(&bundle_dir)
        .arg("manifest.json")
        .arg("daygle-starter.bin")
        .status()
        .unwrap();
    assert!(status.success(), "tar bundle");
    let bundle_sha = sha256(&bundle);
    fs::write(
        staging.join("apply.json"),
        format!("{{\"kind\":\"models\",\"version\":\"9.9.9\",\"sha256\":\"{bundle_sha}\"}}"),
    )
    .unwrap();
    fs::write(updates.join("request"), "").unwrap();

    let capture = root.join("posted-probe.json");
    let restarts = root.join("restarts.log");
    let script =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/update-apply.sh"))
            .unwrap()
            .replace("__DAYGLE_DNS_EXE__", "/bin/true")
            .replace("__DAYGLE_DNS_UPDATES_DIR__", &updates.display().to_string())
            .replace("__DAYGLE_DNS_MODELS_DIR__", &models.display().to_string())
            .replace("__DAYGLE_DNS_USER__", &current_user());
    fs::write(root.join("apply.sh"), script).unwrap();

    write_exec(
        &bin.join("systemctl"),
        &format!(
            "#!/bin/sh\ncase \"$1\" in\nrestart) echo restart >> '{}' ;;\nis-active) exit 0 ;;\nshow) echo 123 ;;\nstart) exit 0 ;;\nesac\nexit 0\n",
            restarts.display()
        ),
    );

    // Root fetches the published bundle checksum; every health request is
    // fast. The first model-health GET returns a clean baseline, and the POST
    // after the restart returns the regression. The POST body is copied out so
    // the test can prove it is the baseline's pinned sample.
    write_exec(
        &bin.join("curl"),
        &format!(
            r#"#!/bin/sh
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-o" ]; then out=$arg; fi
  case "$arg" in
    @*) cp "${{arg#@}}" '{}' 2>/dev/null || true ;;
  esac
  prev=$arg
done
case "$*" in
  *model-health*)
    if printf '%s' "$*" | grep -q -- '-X POST'; then
      printf '%s\n' '{{"available":true,"checked":10,"lost":3,"benign":3,"downgraded":0,"skipped":0,"sample":[{{"label":"phishing","domain":"login-secure-probe.example"}}]}}'
    else
      printf '%s\n' '{{"available":true,"checked":10,"lost":0,"benign":0,"downgraded":0,"skipped":0,"sample":[{{"label":"phishing","domain":"login-secure-probe.example"}}]}}'
    fi
    exit 0
    ;;
  *api/health*) exit 0 ;;
esac
if [ -n "$out" ]; then
  printf '%s  daygle-dns-models.tar.gz\n' '{}' > "$out"
fi
exit 0
"#,
            capture.display(),
            bundle_sha
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
        "the apply script must fail when the probe regresses"
    );

    assert_eq!(
        fs::read_to_string(&old).unwrap(),
        "old model",
        "the previous model file is restored"
    );
    assert!(
        !models.join("bundle-version").exists(),
        "a rolled-back bundle must not record its version"
    );
    assert!(
        !updates.join("request.processing").exists(),
        "the failed run consumes its request"
    );
    let log = fs::read_to_string(gui.join("apply.log")).unwrap();
    assert!(log.contains("model probe regressed"), "{log}");
    let state = fs::read_to_string(gui.join("state.json")).unwrap();
    assert!(state.contains("\"phase\":\"error\""), "{state}");
    assert!(
        state.contains("read 3 held-out threat name(s) as non-threats, up from 0"),
        "{state}"
    );
    let restarted = fs::read_to_string(&restarts).unwrap();
    assert_eq!(
        restarted.lines().count(),
        2,
        "one restart to load the bundle and one to restore: {restarted}"
    );

    let posted = fs::read_to_string(&capture).expect("the post-restart probe body was captured");
    assert!(
        posted.contains("\"available\":true") && posted.contains("\"lost\":0"),
        "the post-restart probe posts the baseline body, not a fresh sample: {posted}"
    );
    assert!(
        posted.contains("login-secure-probe.example"),
        "the pinned sample is reused: {posted}"
    );
}
