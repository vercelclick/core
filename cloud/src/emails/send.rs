use crate::emails::EmailTemplate;
use click_core::{InternalError, InternalResult, StatusCode, caller};
use lettre::Message;
use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use std::env;
use std::sync::LazyLock;

static MAILER: LazyLock<AsyncSmtpTransport<Tokio1Executor>> = LazyLock::new(|| {
    let creds = lettre::transport::smtp::authentication::Credentials::new(
        env::var("SMTP_USERNAME").unwrap(),
        env::var("SMTP_PASSWORD").unwrap(),
    );

    AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&env::var("SMTP_RELAY").unwrap())
        .unwrap()
        .credentials(creds)
        .build()
});

pub async fn send_email(recipient: &str, template: EmailTemplate) -> InternalResult<()> {
    let (subject, content) = template.build();

    let message = Message::builder()
        .from(get_sender()?)
        .to(recipient.parse().map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::BAD_REQUEST,
                &format!("Invalid recipient<{recipient}> email address"),
                err,
            )
        })?)
        .subject(subject)
        .header(ContentType::TEXT_HTML)
        .body(content)
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Error building {} error", template),
                err,
            )
        })?;

    MAILER.send(message).await.map_err(|err| {
        InternalError::trace(
            caller!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Error sending {} email", template),
            err,
        )
    })?;

    Ok(())
}

fn get_sender() -> InternalResult<Mailbox> {
    let mbox = Mailbox::new(
        Some("Click Vault".to_string()),
        "no-reply@vault.secretpass.cloud".parse().map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid sender email address",
                err,
            )
        })?,
    );

    Ok(mbox)
}
