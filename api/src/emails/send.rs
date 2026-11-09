use crate::emails::template::EmailTemplate;
use lettre::Message;
use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use secretpass_core::enums::OperationMode;
use secretpass_core::{InternalError, InternalResult, StatusCode, source};
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

pub(crate) async fn send_email(recipient: &str, template: EmailTemplate) -> InternalResult<()> {
    let (mode, subject, content) = template.build();

    let message = Message::builder()
        .from(get_sender(mode)?)
        .to(recipient.parse().map_err(|err| {
            InternalError::trace(
                source!(),
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
                source!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Error building {} error", template),
                err,
            )
        })?;

    MAILER.send(message).await.map_err(|err| {
        InternalError::trace(
            source!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Error sending {} email", template),
            err,
        )
    })?;

    Ok(())
}

fn get_sender(operation_mode: OperationMode) -> InternalResult<Mailbox> {
    let mbox = match operation_mode {
        OperationMode::Local => Mailbox::new(
            Some("Secretpass Local".to_string()),
            "no-reply@local.secretpass.cloud".parse().map_err(|err| {
                InternalError::trace(
                    source!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid local sender email address",
                    err,
                )
            })?,
        ),
        OperationMode::Cloud => Mailbox::new(
            Some("Secretpass Cloud".to_string()),
            "no-reply@cloud.secretpass.cloud".parse().map_err(|err| {
                InternalError::trace(
                    source!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid cloud sender email address",
                    err,
                )
            })?,
        ),
    };

    Ok(mbox)
}
