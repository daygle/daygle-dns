//! Alert delivery: email over SMTP and/or a JSON webhook, with the live
//! `[alerts]` settings. Installed as the sender behind
//! [`daygle_dns_core::alerts::raise`].

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use daygle_dns_core::alerts::Alert;
use daygle_dns_core::config::{AlertSettings, DaygleConfig};
use daygle_dns_core::LogStore;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// How long one delivery may take.
const TIMEOUT: Duration = Duration::from_secs(20);

/// Make [`daygle_dns_core::alerts::raise`] deliver with the live settings.
/// Must be called inside the Tokio runtime; deliveries run in the
/// background and failures go to the server log.
pub fn install(config: Arc<ArcSwap<DaygleConfig>>, logs: Arc<LogStore>) {
    let runtime = tokio::runtime::Handle::current();
    daygle_dns_core::alerts::set_sender(Box::new(move |alert| {
        let settings = config.load().alerts.clone();
        if !settings.enabled || !settings.wants(alert.kind) {
            return false;
        }
        let alert = alert.clone();
        let logs = logs.clone();
        runtime.spawn(async move {
            match deliver(&settings, &alert).await {
                Ok(()) => logs.info("alerts", format!("alert sent: {}", alert.title)),
                Err(e) => logs.warn(
                    "alerts",
                    format!("cannot send the alert '{}': {e}", alert.title),
                ),
            }
        });
        true
    }));
}

/// Send `alert` to every configured destination; the error names each one
/// that failed.
pub async fn deliver(settings: &AlertSettings, alert: &Alert) -> Result<(), String> {
    let mut errors = Vec::new();
    if !settings.webhook_url.trim().is_empty() {
        if let Err(e) = send_webhook(settings.webhook_url.trim(), alert).await {
            errors.push(format!("webhook: {e}"));
        }
    }
    if settings.email_configured() {
        if let Err(e) = send_email(settings, alert).await {
            errors.push(format!("email: {e}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// This server's host name, to tell several servers' alerts apart.
fn host_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .map(|h| h.trim().to_string())
        .unwrap_or_default()
}

async fn send_webhook(url: &str, alert: &Alert) -> Result<(), String> {
    let host = host_name();
    let summary = format!("[Daygle DNS {host}] {}: {}", alert.title, alert.message);
    // `text` (Slack, Mattermost, Teams workflows) and `content` (Discord)
    // let chat webhooks show the alert without any translation.
    let body = serde_json::json!({
        "source": "daygle-dns",
        "host": host,
        "kind": alert.kind,
        "title": alert.title,
        "message": alert.message,
        "time": chrono::Utc::now().to_rfc3339(),
        "text": summary,
        "content": summary,
    });
    let client = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .build()
        .map_err(|e| e.to_string())?;
    let response = client
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|e| describe(&e))?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("the server answered {}", response.status()))
    }
}

/// An error with its causes ("error sending request: connection refused").
fn describe(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.contains(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

async fn send_email(settings: &AlertSettings, alert: &Alert) -> Result<(), String> {
    let server = settings.smtp_server.trim();
    let builder = match settings.smtp_security.as_str() {
        "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(server),
        "none" => Ok(AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(
            server,
        )),
        _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(server),
    }
    .map_err(|e| e.to_string())?;
    let mut builder = builder.port(settings.smtp_port).timeout(Some(TIMEOUT));
    if !settings.smtp_username.is_empty() {
        builder = builder.credentials(Credentials::new(
            settings.smtp_username.clone(),
            settings.smtp_password.clone(),
        ));
    }
    let host = host_name();
    let mut message = Message::builder()
        .from(
            settings
                .email_from
                .trim()
                .parse()
                .map_err(|e| format!("sender: {e}"))?,
        )
        .subject(format!("[Daygle DNS] {}", alert.title));
    for to in &settings.email_to {
        message = message.to(to.trim().parse().map_err(|e| format!("'{to}': {e}"))?);
    }
    let text = format!(
        "{}\n\n{}\n\nServer: {}\nTime: {}\n",
        alert.title,
        alert.message,
        if host.is_empty() { "-" } else { &host },
        chrono::Utc::now().to_rfc3339(),
    );
    let email = message
        .header(ContentType::TEXT_PLAIN)
        .body(text)
        .map_err(|e| e.to_string())?;
    builder
        .build()
        .send(email)
        .await
        .map(|_| ())
        .map_err(|e| describe(&e))
}
