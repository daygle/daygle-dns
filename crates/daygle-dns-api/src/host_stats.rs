//! Host resource statistics for `GET /api/host-stats`.
//!
//! On Linux this reads the kernel directly - `/proc/stat` (CPU usage),
//! `/proc/loadavg`, `/proc/meminfo`, `/proc/uptime`, the kernel hostname and
//! `statvfs(2)` for the root filesystem - with no subprocesses and no
//! third-party crate beyond the already-present `nix`. Elsewhere the
//! endpoint reports `supported: false` and the console hides its card.
//!
//! CPU usage is a rate, so it is computed over the delta between samples:
//! each request keeps the previous `/proc/stat` reading and reports the
//! percentage of non-idle time since it. The first request after startup has
//! nothing to compare against and reports `cpu.usage_percent: null`; the
//! console polls every few seconds, so the next poll shows the real number.
//! The previous sample is process-global state, which is harmless (the API is
//! a single process) and simply makes concurrent requests share one result.

use serde_json::{json, Value};
// Only the Linux snapshot builds a map member by member.
#[cfg(target_os = "linux")]
use serde_json::Map;

/// The complete `GET /api/host-stats` response.
pub fn snapshot() -> Value {
    #[cfg(target_os = "linux")]
    {
        if !std::path::Path::new("/proc").exists() {
            return json!({
                "supported": false,
                "reason": "/proc is not available on this host",
            });
        }
        let mut value = Map::new();
        value.insert("supported".into(), Value::Bool(true));
        value.insert("hostname".into(), hostname());
        value.insert("uptime_secs".into(), json!(uptime_secs()));
        value.insert("cpu".into(), cpu());
        value.insert("load".into(), load());
        value.insert("memory".into(), memory());
        value.insert("disks".into(), Value::Array(root_disk().into_iter().collect()));
        Value::Object(value)
    }
    #[cfg(not(target_os = "linux"))]
    {
        json!({
            "supported": false,
            "reason": "host stats are only collected on Linux",
        })
    }
}

// ---- Linux collectors ------------------------------------------------------
//
// Every parser is defensive: an unexpected or malformed line makes that one
// metric null rather than poisoning the whole snapshot.

#[cfg(target_os = "linux")]
fn read_trimmed(path: &str) -> Option<String> {
    // All the files read here are a few KiB at most; the cap only keeps a
    // genuinely malformed host from making one request cost real memory.
    use std::io::Read;
    const CAP: usize = 64 * 1024;
    let mut buf = [0u8; 4096];
    let mut file = std::fs::File::open(path).ok()?;
    let mut out = Vec::new();
    let mut taken = 0usize;
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        taken += n;
        if taken > CAP {
            return None;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Some(String::from_utf8_lossy(&out).trim().to_string())
}

/// A percentage in [0, 100], rounded to one decimal; None unless `used` and
/// `total` are finite and `total` is positive (e.g. a zero-size filesystem).
#[cfg(target_os = "linux")]
fn round_percent(used: Option<f64>, total: f64) -> Option<f64> {
    let used = used?;
    if !total.is_finite() || total <= 0.0 || !used.is_finite() {
        return None;
    }
    Some((((used / total) * 100.0).clamp(0.0, 100.0) * 10.0).round() / 10.0)
}

#[cfg(target_os = "linux")]
fn hostname() -> Value {
    match read_trimmed("/proc/sys/kernel/hostname") {
        Some(name) if !name.is_empty() => json!(name),
        _ => Value::Null,
    }
}

/// Seconds since the host booted (`/proc/uptime`); null if unreadable.
#[cfg(target_os = "linux")]
fn uptime_secs() -> Value {
    read_trimmed("/proc/uptime")
        .and_then(|text| {
            text.split_whitespace()
                .next()
                .and_then(|tok| tok.parse::<f64>().ok())
        })
        .map(|secs| json!(secs.floor() as u64))
        .unwrap_or(Value::Null)
}

/// CPU cores and usage. Each call reads the aggregate `cpu` line of
/// `/proc/stat` and turns the delta against the previous reading into a
/// percentage of non-idle time.
#[cfg(target_os = "linux")]
fn cpu() -> Value {
    use std::time::Instant;

    struct Sample {
        total: u64,
        idle: u64,
        at: Instant,
        /// The percentage computed when this sample was taken.
        usage: Option<f64>,
    }
    static PREV_CPU: parking_lot::RwLock<Option<Sample>> = parking_lot::RwLock::new(None);

    // A request too soon after the previous one has nothing meaningful to
    // measure, so it reuses that result rather than reporting a wiggle.
    const MIN_SAMPLE_MS: u128 = 250;

    let text = match read_trimmed("/proc/stat") {
        Some(text) => text,
        None => {
            *PREV_CPU.write() = None;
            return json!({ "cores": Value::Null, "usage_percent": Value::Null });
        }
    };

    let fields = |line: &str, drop_hdr: usize| -> Vec<u64> {
        line.split_whitespace()
            .skip(drop_hdr)
            .filter_map(|tok| tok.parse::<u64>().ok())
            .collect()
    };

    // Aggregate line: "cpu user nice system idle iowait irq softirq steal".
    // (io wait is close to idle for this purpose; guest time is already
    // counted inside user time, so the denominator is simply their sum.)
    let reading = text.lines().find(|l| l.starts_with("cpu ")).and_then(|line| {
        let vals = fields(line, 1);
        let total: u64 = vals.iter().sum();
        let idle = *vals.get(3)? + vals.get(4)?;
        Some((total, idle))
    });
    let cores = text
        .lines()
        .filter(|line| {
            line.strip_prefix("cpu")
                .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
        })
        .count();

    let now = Instant::now();
    let mut measured = false;
    let usage = match (&*PREV_CPU.read(), reading) {
        (None, _) => None,
        (Some(prev), _) if now.duration_since(prev.at).as_millis() < MIN_SAMPLE_MS => prev.usage,
        (Some(prev), Some((total, idle))) => {
            measured = true;
            let d_total = total.saturating_sub(prev.total);
            let d_idle = idle.saturating_sub(prev.idle);
            if d_total == 0 {
                None
            } else {
                round_percent(Some((d_total - d_idle) as f64), d_total as f64)
            }
        }
        (Some(_), None) => None,
    };
    if measured {
        if let Some((total, idle)) = reading {
            *PREV_CPU.write() = Some(Sample {
                total,
                idle,
                at: now,
                usage,
            });
        }
    }

    json!({
        "cores": if cores > 0 { Value::from(cores) } else { Value::Null },
        "usage_percent": usage.map(Value::from).unwrap_or(Value::Null),
    })
}

/// 1, 5 and 15 minute load averages (`/proc/loadavg`).
#[cfg(target_os = "linux")]
fn load() -> Value {
    let nulls = json!({ "one": Value::Null, "five": Value::Null, "fifteen": Value::Null });
    let Some(text) = read_trimmed("/proc/loadavg") else {
        return nulls;
    };
    let mut toks = text.split_whitespace();
    let (Some(one), Some(five), Some(fifteen)) = (toks.next(), toks.next(), toks.next()) else {
        return nulls;
    };
    // Two decimals is exactly what the kernel writes; the rounding only
    // normalizes an already-rounded token.
    let parse = |tok: &str| tok.parse::<f64>().ok().map(|v| (v * 100.0).round() / 100.0);
    json!({
        "one": parse(one),
        "five": parse(five),
        "fifteen": parse(fifteen),
    })
}

/// Memory and swap (`/proc/meminfo`, units of kB as the kernel reports them).
#[cfg(target_os = "linux")]
fn memory() -> Value {
    let Some(text) = read_trimmed("/proc/meminfo") else {
        return json!({
            "total_kb": Value::Null,
            "available_kb": Value::Null,
            "used_percent": Value::Null,
            "swap_total_kb": Value::Null,
            "swap_used_kb": Value::Null,
            "swap_percent": Value::Null,
        });
    };
    // `MemTotal:  16384256 kB` - one name, one kB count.
    let field = |key: &str| -> Option<u64> {
        text.lines()
            .find_map(|line| {
                let (name, rest) = line.split_once(':')?;
                (name.trim() == key)
                    .then(|| rest.split_whitespace().next()?.parse::<u64>().ok())
            })
            .flatten()
    };
    let total = field("MemTotal");
    // MemAvailable appeared in kernel 3.14; on a kernel without it, MemFree
    // under-reports but is better than nothing.
    let available = field("MemAvailable").or_else(|| field("MemFree"));
    let swap_total = field("SwapTotal");
    let swap_used = match (swap_total, field("SwapFree")) {
        (Some(swap_total), Some(swap_free)) => Some(swap_total.saturating_sub(swap_free)),
        _ => None,
    };
    let used_percent = match (available, total) {
        (Some(avail), Some(total)) if avail <= total => {
            round_percent(Some((total - avail) as f64), total as f64)
        }
        _ => None,
    };
    let swap_percent = round_percent(swap_used.map(|u| u as f64), swap_total.map(|t| t as f64).unwrap_or(0.0));
    json!({
        "total_kb": total,
        "available_kb": available,
        "used_percent": used_percent,
        "swap_total_kb": swap_total,
        "swap_used_kb": swap_used,
        "swap_percent": swap_percent,
    })
}

/// The root filesystem via `statvfs`; returned on its own (the handler wraps
/// it in a single-element list) because the data and config directories are
/// almost always on it.
#[cfg(target_os = "linux")]
fn root_disk() -> Option<Value> {
    let vfs = nix::sys::statvfs::statvfs("/").ok()?;
    // POSIX: sizes use `f_frsize` (fall back to `f_bsize` if the mount
    // reports zero for it).
    let fs = if vfs.fragment_size() > 0 {
        vfs.fragment_size()
    } else {
        vfs.block_size()
    } as u64;
    let kb = |blocks: u64| blocks * fs / 1024;
    let total = kb(vfs.blocks() as u64);
    let free = kb(vfs.blocks_free() as u64);
    let available = kb(vfs.blocks_available() as u64);
    // "Used" counts everything not still free (kernel-reserved space
    // included), so the number agrees with `df`; the console's fill bar uses
    // `available`, which is what anything can still be written into.
    let used = total.saturating_sub(free);
    Some(json!({
        "mount": "/",
        "total_kb": total,
        "used_kb": used,
        "available_kb": available,
        "used_percent": round_percent(Some(used as f64), total as f64),
    }))
}
