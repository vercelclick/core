use crate::cli::attach::attach_project;
use crate::cli::mode::{ModeArgs, OperationMode};
use crate::cli::runner::access_keys::{
    get_values_from_cloud_project, get_values_from_local_project,
};
use crate::cli::runner::export::export_secrets;
use crate::cli::runner::human::get_values_from_web;
use crate::cli::runner::run_command::run_command_with_secrets;
use crate::cli::service::{check_status_command, start_service_command, stop_service_command};
use crate::cli::utils::mask_if_github_actions;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "click", author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum, PartialEq, PartialOrd, Eq, Ord)]
pub enum ExportFormat {
    #[value(name="json", aliases = [".json"])]
    Json,
    #[default]
    #[value(name="env", aliases = [".env", "dot-env"])]
    DotEnv,
    #[value(name="gh-actions", aliases = ["gh", "github", "github-actions"])]
    GithubActions,
}

#[derive(Args, Clone, Debug)]
pub struct AccessArgs {
    /// (optional) access key to use for decryption, you'll be prompted to use your passkey if not provided
    #[arg(long, default_value = None, requires = "env")]
    access_key: Option<String>,

    /// (optional) vault environment to use secrets from, required when used with access_key
    #[arg(long, default_value = None, requires = "access_key")]
    env: Option<String>,
}

impl AccessArgs {
    fn get(self) -> Option<(String, String)> {
        if let Some(key) = self.access_key
            && let Some(env) = self.env
        {
            Some((key, env))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// run a command with decrypted secrets injected as environment variables
    ///
    /// secrets will be automatically masked on GitHub Actions
    Run {
        #[command(flatten)]
        mode_args: ModeArgs,

        #[command(flatten)]
        access_args: AccessArgs,

        /// The command to inject secrets to - supports `sh` valid syntax
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            allow_negative_numbers = true
        )]
        command: Vec<String>,
    },
    /// export decrypted secrets to a file or pipe them to another command
    ///
    /// secrets will be automatically masked on GitHub Actions
    Export {
        #[command(flatten)]
        mode_args: ModeArgs,

        #[command(flatten)]
        access_args: AccessArgs,

        /// (dot-env) format(json/dot-env); pipe stdout to the desired file
        #[arg(long, default_value = "dot-env")]
        format: ExportFormat,
    },
    /// attach a directory as a click vault local project, setup can be completed from https://vault.vercel.click
    Attach {
        /// prevent cli from opening the browser after attaching
        #[arg(long, default_value_t)]
        silent: bool,

        /// (default cwd) the path to the directory to attach
        #[arg(long, default_value = None)]
        target: Option<String>,
    },
    /// manage local vault service
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum ServiceCommand {
    /// start the local vault service
    Start {
        /// (default false) start as a standard cli process instead of running it in the background
        #[arg(long, default_value_t)]
        foreground: bool,
    },
    /// stop the local vault service
    Stop,
    /// check the status of click local vault service
    Status,
    #[cfg(target_os = "macos")]
    /// For macOS Safari blocks calls to local service from https://vault.vercel.click
    /// Install these certificates to trust the local https certificate
    InstallCertificates,
}

impl Cli {
    pub fn execute(&self) {
        match self.command.clone() {
            Command::Run {
                access_args,
                mode_args,
                command,
            } => {
                let command = parse_command(&command);

                let plain_values = get_values(mode_args, access_args, Some(command.clone()));

                run_command_with_secrets(plain_values, command)
            }
            Command::Export {
                access_args,
                mode_args,
                format,
            } => {
                let plain_values = get_values(mode_args, access_args, None);

                export_secrets(plain_values, format)
            }
            Command::Service { command } => match command {
                ServiceCommand::Start { foreground } => start_service_command(foreground, false),
                ServiceCommand::Stop => stop_service_command(),
                ServiceCommand::Status => check_status_command(),
                #[cfg(target_os = "macos")]
                ServiceCommand::InstallCertificates => {
                    crate::utils::certificates::install_macos_certificates();
                }
            },
            Command::Attach { silent, target } => attach_project(silent, target),
        }
    }
}

fn parse_command(args: &[String]) -> String {
    if args.is_empty() {
        panic!("Command is required")
    }

    args.join(" ")
}

fn get_values(
    mode_args: ModeArgs,
    access_args: AccessArgs,
    command: Option<String>,
) -> std::collections::HashMap<String, String> {
    let mode = OperationMode::try_from(mode_args)
        .unwrap_or_else(|(kind, message)| Cli::command().error(kind, message).exit());

    if let Some((access_key, env)) = access_args.get() {
        let values = match mode {
            OperationMode::Local { project_dir } => {
                get_values_from_local_project(project_dir, access_key, env, "latest".to_string())
            }
            OperationMode::Cloud { endpoint } => {
                get_values_from_cloud_project(endpoint, access_key, env, "latest".to_string())
            }
        };

        mask_if_github_actions(&values);

        values
    } else {
        get_values_from_web(command)
    }
}
