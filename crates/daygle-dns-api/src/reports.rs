//! Reports: summaries of the query log, shown in the console (Logs ->
//! Reports) and sent on a schedule to the alert destinations.

use std::time::Duration;

use daygle_dns_authoritative::store::QueryLogReport;
use daygle_dns_core::alerts::{Alert, AlertKind};
use daygle_dns_core::config::ReportSettings;
use tokio_util::sync::CancellationToken;

use crate::AppState;

/// The named setting that remembers when the last scheduled report went
/// out (UNIX seconds), so a restart does not send it twice.
const LAST_SENT: &str = "reports_last_sent";

/// The query-log summary for the last `period`.
pub fn summary(
    state: &AppState,
    period: Duration,
    client: Option<&str>,
    top: usize,
) -> Result<QueryLogReport, String> {
    let since =
        chrono::Utc::now() - chrono::Duration::from_std(period).map_err(|e| e.to_string())?;
    state
        .catalog
        .store()
        .query_log_report(&since.to_rfc3339(), client, top)
        .map_err(|e| e.to_string())
}

fn number(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn percent(part: u64, whole: u64) -> String {
    if whole == 0 {
        "0%".to_string()
    } else {
        format!("{:.1}%", part as f64 * 100.0 / whole as f64)
    }
}

/// The report as plain text: a title and the body. `labels` names clients
/// (address -> device name).
pub fn render(
    report: &QueryLogReport,
    settings: &ReportSettings,
    labels: &std::collections::HashMap<String, String>,
) -> (String, String) {
    let period = if settings.frequency == "daily" {
        "the last 24 hours"
    } else {
        "the last 7 days"
    };
    let title = if settings.frequency == "daily" {
        "Daily DNS report".to_string()
    } else {
        "Weekly DNS report".to_string()
    };
    let mut text = format!(
        "DNS activity for {period}:\n\n\
         Queries: {}\nBlocked: {} ({})\nDevices: {}\n",
        number(report.queries),
        number(report.blocked),
        percent(report.blocked, report.queries),
        number(report.clients_seen),
    );
    let list = |text: &mut String, heading: &str, rows: &[(String, String)]| {
        text.push_str(&format!("\n{heading}:\n"));
        if rows.is_empty() {
            text.push_str("  (none)\n");
        }
        for (i, (name, value)) in rows.iter().enumerate() {
            text.push_str(&format!("  {:>2}. {name}  {value}\n", i + 1));
        }
    };
    let names = |rows: &[daygle_dns_authoritative::store::NameCount]| {
        rows.iter()
            .map(|r| (r.name.clone(), number(r.count)))
            .collect::<Vec<_>>()
    };
    list(&mut text, "Most asked domains", &names(&report.top_domains));
    list(
        &mut text,
        "Most blocked domains",
        &names(&report.top_blocked),
    );
    let devices: Vec<(String, String)> = report
        .clients
        .iter()
        .map(|c| {
            (
                match labels.get(&c.client) {
                    Some(name) => format!("{name} ({})", c.client),
                    None => c.client.clone(),
                },
                format!(
                    "{} queries, {} blocked",
                    number(c.queries),
                    number(c.blocked)
                ),
            )
        })
        .collect();
    list(&mut text, "Most active devices", &devices);
    if report.queries == 0 {
        text.push_str(
            "\nNo queries were logged. The report reads the query log, which is \
             kept while Logging -> Query Log (database) is on.\n",
        );
    }
    (title, text)
}

/// Build and send the report now with `settings`, to the alert
/// destinations. The error names what failed.
pub async fn send(state: &AppState, settings: &ReportSettings) -> Result<(), String> {
    let alerts = state.config.load().alerts.clone();
    if alerts.webhook_url.trim().is_empty() && !alerts.email_configured() {
        return Err(
            "set up a webhook or email under Settings -> Alerts first: reports go there"
                .to_string(),
        );
    }
    let report = summary(state, settings.period(), None, settings.top)?;
    let names = crate::devices::labels(state, settings.period()).await;
    let (title, message) = render(&report, settings, &names);
    let alert = Alert {
        kind: AlertKind::Report,
        key: "report".to_string(),
        title,
        message,
    };
    crate::alerts::deliver(&alerts, &alert).await
}

/// Whether the scheduled report is due at `now` (in the display time
/// zone), given when it last went out (UNIX seconds).
fn due(
    settings: &ReportSettings,
    now: daygle_dns_core::schedule::WeekTime,
    now_unix: i64,
    last_sent: i64,
) -> bool {
    let hour_matches = now.minute / 60 == u32::from(settings.hour);
    let day_matches = settings.frequency == "daily" || settings.weekday_index() == Some(now.day);
    // Well past the previous one, so one report goes out per period.
    let gap = if settings.frequency == "daily" {
        20
    } else {
        6 * 24
    } * 3600;
    hour_matches && day_matches && now_unix - last_sent >= gap
}

/// Send the scheduled report when it is due, until `shutdown`.
pub async fn run_reports(state: AppState, shutdown: CancellationToken) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
        }
        let settings = state.config.load().reports.clone();
        if !settings.enabled {
            continue;
        }
        let store = state.catalog.store();
        let last_sent: i64 = store
            .get_named_setting(LAST_SENT)
            .ok()
            .flatten()
            .unwrap_or(0);
        let now_unix = chrono::Utc::now().timestamp();
        if !due(
            &settings,
            daygle_dns_core::schedule::now(),
            now_unix,
            last_sent,
        ) {
            continue;
        }
        // Recorded first: a failing destination is retried next period,
        // not every minute.
        let _ = store.put_named_setting(LAST_SENT, &now_unix);
        match send(&state, &settings).await {
            Ok(()) => state.logs.info("reports", "scheduled report sent"),
            Err(e) => state.logs.warn(
                "reports",
                format!("the scheduled report could not be sent: {e}"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use daygle_dns_core::schedule::WeekTime;

    #[test]
    fn reports_are_due_once_per_period_at_their_hour() {
        let weekly = ReportSettings {
            enabled: true,
            weekday: "tue".to_string(),
            hour: 8,
            ..ReportSettings::default()
        };
        let tue_0810 = WeekTime {
            day: 1,
            minute: 8 * 60 + 10,
        };
        let now = 10_000_000;
        assert!(due(&weekly, tue_0810, now, 0));
        assert!(!due(&weekly, tue_0810, now, now - 3600), "already sent");
        assert!(
            !due(
                &weekly,
                WeekTime {
                    day: 2,
                    minute: 8 * 60
                },
                now,
                0
            ),
            "wrong day"
        );
        assert!(
            !due(
                &weekly,
                WeekTime {
                    day: 1,
                    minute: 9 * 60
                },
                now,
                0
            ),
            "wrong hour"
        );
        let daily = ReportSettings {
            frequency: "daily".to_string(),
            ..weekly
        };
        assert!(due(
            &daily,
            WeekTime {
                day: 5,
                minute: 8 * 60
            },
            now,
            now - 86_000
        ));
    }

    #[test]
    fn the_text_lists_totals_and_tops() {
        let report = QueryLogReport {
            since: String::new(),
            queries: 12_345,
            blocked: 1_234,
            clients_seen: 3,
            clients: vec![
                daygle_dns_authoritative::store::ClientActivity {
                    client: "192.168.1.7".to_string(),
                    queries: 10_000,
                    blocked: 1_000,
                    last_seen: String::new(),
                },
                daygle_dns_authoritative::store::ClientActivity {
                    client: "192.168.1.8".to_string(),
                    queries: 10,
                    blocked: 0,
                    last_seen: String::new(),
                },
            ],
            top_domains: vec![daygle_dns_authoritative::store::NameCount {
                name: "example.com".to_string(),
                count: 500,
            }],
            top_blocked: vec![],
        };
        let names = [("192.168.1.8".to_string(), "Kids-iPad".to_string())].into();
        let (title, text) = render(&report, &ReportSettings::default(), &names);
        assert_eq!(title, "Weekly DNS report");
        assert!(text.contains("Queries: 12,345"), "{text}");
        assert!(text.contains("Blocked: 1,234 (10.0%)"), "{text}");
        assert!(text.contains("1. example.com  500"), "{text}");
        assert!(
            text.contains("192.168.1.7  10,000 queries, 1,000 blocked"),
            "{text}"
        );
        assert!(text.contains("(none)"), "{text}");
        assert!(
            text.contains("Kids-iPad (192.168.1.8)  10 queries"),
            "{text}"
        );
    }
}
