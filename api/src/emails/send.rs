use crate::emails::template::EmailTemplate;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use secretpass_core::enums::OperationMode;
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

pub(crate) async fn send_email(recipient: &str, template: EmailTemplate) -> anyhow::Result<()> {
    use lettre::Message;
    use lettre::message::header::ContentType;

    let (mode, subject, content) = template.build();

    let message = Message::builder()
        .from(get_sender(mode).parse()?)
        .to(recipient.parse()?)
        .subject(subject)
        .header(ContentType::TEXT_HTML)
        .body(content)?;

    MAILER.send(message).await?;

    Ok(())
}

fn get_sender(operation_mode: OperationMode) -> &'static str {
    match operation_mode {
        OperationMode::Local => "no-reply@local.secretpass.cloud",
        OperationMode::Cloud => "no-reply@cloud.secretpass.cloud",
    }
}
