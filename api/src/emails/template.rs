use crate::constants::{CLOUD_RP_CONFIG, LOCAL_RP_CONFIG};
use secretpass_core::enums::OperationMode;

const CREATE_EMAIL_TEMPLATE: &str = include_str!("templates/create_account.html");
const CONFIRM_EMAIL_TEMPLATE: &str = include_str!("templates/confirm_email.html");

pub(crate) enum EmailTemplate {
    Create {
        subject: String,
        name: String,
        code: String,
        operation_mode: OperationMode,
    },
    Confirm {
        subject: String,
        name: String,
        code: String,
        operation: String,
        operation_mode: OperationMode,
    },
}

impl EmailTemplate {
    pub(crate) fn build(&self) -> (OperationMode, String, String) {
        match self {
            EmailTemplate::Create {
                subject,
                name,
                code,
                operation_mode,
            } => {
                let content = CREATE_EMAIL_TEMPLATE
                    .replace("{{subject}}", subject)
                    .replace("{{name}}", name)
                    .replace("{{code}}", code)
                    .replace("{{origin}}", get_origin(operation_mode))
                    .replace("{{operation_mode}}", &operation_mode.to_string());
                (*operation_mode, subject.clone(), content)
            }
            EmailTemplate::Confirm {
                subject,
                name,
                code,
                operation,
                operation_mode,
            } => {
                let content = CONFIRM_EMAIL_TEMPLATE
                    .replace("{{subject}}", subject)
                    .replace("{{name}}", name)
                    .replace("{{code}}", code)
                    .replace("{{origin}}", get_origin(operation_mode))
                    .replace("{{operation}}", operation)
                    .replace("{{operation_mode}}", &operation_mode.to_string());
                (*operation_mode, subject.clone(), content)
            }
        }
    }
}

fn get_origin(operation_mode: &OperationMode) -> &'static str {
    match operation_mode {
        OperationMode::Local => LOCAL_RP_CONFIG.origin,
        OperationMode::Cloud => CLOUD_RP_CONFIG.origin,
    }
}
