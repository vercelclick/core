use crate::cli::attach::attach_project;
use crate::cli::service::{check_status_command, start_service_command, stop_service_command};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "spass", author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, PartialOrd, Eq, Ord)]
pub enum ExportFormat {
    Json,
    DotEnv,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start secretpass service
    Start,
    /// Stop secretpass service
    Stop,
    /// Check the status of secretpass service
    Status,
    /// Attach the current running directory as a secretpass project, setup can be done from the UI if not already completed
    Attach {
        /// Set to true to prevent opening the browser after attaching
        #[arg(long, default_value_t = false)]
        silent: bool,
    },
    /// Export exposed secrets to a file or pipe them to another command
    Export {
        /// (optional) Set to true if to use cloud-stored secrets, defaults to false
        #[arg(long, global = true, default_value_t = false)]
        cloud: bool,

        /// (optional) If running on an in-house cloud deployment, change this URL accordingly
        #[arg(long, global = true, default_value = "https://api.secretpass.cloud")]
        cloud_origin: String,

        /// (optional) Secretpass project directory; defaults to the current working directory
        #[arg(long, global = true, default_value = None)]
        project_dir: Option<String>,

        /// (optional) Machine key to use for decryption, you'll be prompted to use your passkey if not provided
        #[arg(long, default_value = None)]
        private_key: Option<String>,

        /// (optional) Secrets environment to export secrets from, required when used with a private key
        #[arg(long, default_value = None)]
        env: Option<String>,

        /// Output format(json/dotenv); pipe stdout to the desired file
        #[arg(long)]
        format: ExportFormat,
    },
    /// Run a command with exposed secrets injected as environment variables
    Run {
        /// (optional) Set to true if to use cloud-stored secrets, defaults to false
        #[arg(long, global = true, default_value_t = false)]
        cloud: bool,

        /// (optional) If running on an in-house cloud deployment, change this URL accordingly
        #[arg(long, global = true, default_value = "https://api.secretpass.cloud")]
        cloud_origin: String,

        /// (optional) Secretpass project directory; defaults to the current working directory
        #[arg(long, global = true, default_value = None)]
        project_dir: Option<String>,

        /// (optional) Machine key to use for decryption, you'll be prompted to use your passkey if not provided
        #[arg(long, default_value = None)]
        private_key: Option<String>,

        /// (optional) Secrets environment to inject secrets from, required when used with a private key
        #[arg(long, default_value = None)]
        env: Option<String>,

        /// The command to inject secrets to - supports `sh` valid syntax
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            allow_negative_numbers = true
        )]
        target: Vec<String>,
    },
}

impl Cli {
    pub fn execute(&self) {
        match self.command {
            Command::Run { .. } => {
                todo!("Implement run")
            }
            Command::Export { .. } => {
                todo!("Implement export")
            }
            Command::Start => start_service_command(false),
            Command::Stop => stop_service_command(),
            Command::Status => check_status_command(),
            Command::Attach { silent } => attach_project(silent),
        }
    }
}
