use crate::cli::attach::attach_project;
use crate::cli::runner::export::export_secrets;
use crate::cli::runner::run_command::run_command_with_secrets;
use crate::cli::runner::values::{get_cloud_values, get_local_values};
use crate::cli::service::{check_status_command, start_service_command, stop_service_command};
use crate::utils::certificates::install_macos_certificates;
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

#[derive(Debug, Clone, Subcommand)]
pub enum LocalCommand {
    /// Start secretpass service
    Start {
        /// Start as a standard cli process instead of running it in the background, defaults to false
        #[arg(long, default_value_t = false)]
        foreground: bool,
    },
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
        command: Vec<String>,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum CloudCommand {
    /// Export exposed secrets to a file or pipe them to another command
    Export {
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
        command: Vec<String>,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Group of commands to manage and inject secrets stored locally
    Local {
        #[command(subcommand)]
        command: LocalCommand,
    },
    /// Group of commands to inject secrets from secretpass.local
    Cloud {
        /// (optional) If running on an in-house cloud deployment, change this URL accordingly
        #[arg(long, global = true, default_value = "https://api.secretpass.cloud")]
        endpoint: String,
        #[command(subcommand)]
        command: CloudCommand,
    },
    #[cfg(target_os = "macos")]
    /// For macOS Safari blocks calls to local service from https://local.secretpass.cloud
    /// Install these certificates to trust the local https certificate
    InstallCertificates,
}

impl Cli {
    pub fn execute(&self) {
        match self.command.clone() {
            Command::Local { command } => match command {
                LocalCommand::Run {
                    private_key,
                    command,
                    env,
                    project_dir,
                } => {
                    let command = parse_command(&command);
                    let (private_key, encrypted_values) =
                        get_local_values(project_dir, private_key, env, Some(command.clone()));

                    run_command_with_secrets(private_key, encrypted_values, command)
                }
                LocalCommand::Export {
                    private_key,
                    env,
                    project_dir,
                    format,
                } => {
                    let (private_key, encrypted_values) =
                        get_local_values(project_dir, private_key, env, None);

                    export_secrets(private_key, encrypted_values, format)
                }
                LocalCommand::Start { foreground } => start_service_command(foreground, false),
                LocalCommand::Stop => stop_service_command(),
                LocalCommand::Status => check_status_command(),
                LocalCommand::Attach { silent } => attach_project(silent),
            },
            Command::Cloud { command, endpoint } => match command {
                CloudCommand::Run {
                    private_key,
                    env,
                    command,
                } => {
                    let command = parse_command(&command);
                    let (private_key, encrypted_values) =
                        get_cloud_values(endpoint, private_key, env, Some(command.clone()));

                    run_command_with_secrets(private_key, encrypted_values, command);
                }
                CloudCommand::Export {
                    private_key,
                    env,
                    format,
                } => {
                    let (private_key, encrypted_values) =
                        get_cloud_values(endpoint, private_key, env, None);

                    export_secrets(private_key, encrypted_values, format);
                }
            },
            #[cfg(target_os = "macos")]
            Command::InstallCertificates => {
                install_macos_certificates();
            }
        }
    }
}

fn parse_command(args: &[String]) -> String {
    if args.is_empty() {
        panic!("Command is required")
    }

    args.join(" ")
}
