use secretpass_core::constants::RP_ORIGIN;
use strum::Display;

const CREATE_EMAIL_TEMPLATE: &str = include_str!("templates/create_account.html");
const CONFIRM_EMAIL_TEMPLATE: &str = include_str!("templates/confirm_email.html");

#[derive(Display)]
pub(crate) enum EmailTemplate {
    Create {
        subject: String,
        name: String,
        code: String,
    },
    Confirm {
        subject: String,
        name: String,
        code: String,
        operation: String,
    },
}

impl EmailTemplate {
    pub(crate) fn build(&self) -> (String, String) {
        match self {
            EmailTemplate::Create {
                subject,
                name,
                code,
            } => {
                let content = CREATE_EMAIL_TEMPLATE
                    .replace("{{subject}}", subject)
                    .replace("{{name}}", name)
                    .replace("{{code}}", code)
                    .replace("{{origin}}", RP_ORIGIN);
                (subject.clone(), content)
            }
            EmailTemplate::Confirm {
                subject,
                name,
                code,
                operation,
            } => {
                let content = CONFIRM_EMAIL_TEMPLATE
                    .replace("{{subject}}", subject)
                    .replace("{{name}}", name)
                    .replace("{{code}}", code)
                    .replace("{{origin}}", RP_ORIGIN)
                    .replace("{{operation}}", operation);
                (subject.clone(), content)
            }
        }
    }
}
