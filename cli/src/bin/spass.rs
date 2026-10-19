use clap::Parser;

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Args {
    #[arg(
        long,
        global = true,
        default_value_t = false,
        help = "Use cloud instead of local storage"
    )]
    cloud: bool,

    #[arg(long, default_value = "https://secretpass.cloud")]
    cloud_origin: String,

    #[arg(
        long,
        global = true,
        default_value_t = false,
        help = "Disable builtin Posthog(EU) support chat features and activity tracking"
    )]
    no_support: bool,

    #[arg(long, default_value = None, help = "Project directory, defaults to current working directory")]
    project_dir: Option<String>,

    #[arg(long, default_value = None, help = "Directory to use as CWD, while running provided command")]
    command_dir: Option<String>,

    #[arg(long, default_value = None, help = "Export secrets as .env or json, requires a private key; pipe the results to the relevant file")]
    export: Option<String>, // .env, json

    #[arg(long, default_value = None, help = "Private key to use to run provided command or export secrets")]
    private_key: Option<String>,

    #[arg(long, default_value = None, help = "Secrets environment to use to run provided command or export secrets, required if private key has access to multiple environments")]
    env: Option<String>,

    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        allow_negative_numbers = true,
        help = "Command to run"
    )]
    target: Vec<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if args.cloud {
        println!("Cloud mode is not yet supported, WIP!");
        return;
    }

    if let Some(_private_key) = args.private_key {
        if let Some(format) = args.export {
            if !args.target.is_empty() {
                panic!("You cannot export secrets and run a command at the same time");
            }
            todo!("Implement secrets export for {format}")
        }

        if args.target.is_empty() {
            panic!("You must specify a command to run");
        }

        todo!("Implement command run")
    } else {
        todo!("Implement browser launch for authentication, must be within a project directory")
    }
}
