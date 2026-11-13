use clap::error::ErrorKind;
use clap::{Args, ValueEnum};
use click_core::constants::APP_SLUG;
use std::env::current_dir;
use strum::Display;

#[derive(Debug, Clone, Copy, PartialEq, Default, ValueEnum, Display)]
pub enum ModeKind {
    #[default]
    Auto,
    Local,
    Cloud,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OperationMode {
    Local { project_dir: Option<String> },
    Cloud { endpoint: Option<String> },
}

#[derive(Args, Debug, Clone)]
pub struct ModeArgs {
    /// (auto) specify local or cloud vault, automatically inferred by local project existence
    #[arg(long, default_value = "auto", value_name = "local|cloud")]
    mode: ModeKind,

    /// (https://api.vercel.click) change when running on an in-house cloud deployment
    #[arg(
        long,
        default_value = None,
        conflicts_with = "project_dir",
        value_name = "URL"
    )]
    endpoint: Option<String>,

    /// (cwd) local vault project directory
    #[arg(long, default_value = None, conflicts_with = "endpoint", value_name = "DIR")]
    project_dir: Option<String>,
}

impl TryFrom<ModeArgs> for OperationMode {
    type Error = (ErrorKind, &'static str);

    fn try_from(args: ModeArgs) -> Result<Self, Self::Error> {
        match args.mode {
            ModeKind::Auto => {
                if args.endpoint.is_some() {
                    return Ok(Self::Cloud {
                        endpoint: args.endpoint,
                    });
                } else if args.project_dir.is_some() {
                    return Ok(Self::Local {
                        project_dir: args.project_dir,
                    });
                }

                let dir = current_dir()
                    .expect("Error getting the current working directory")
                    .join(format!(".{}", APP_SLUG));

                if dir.exists() {
                    Ok(Self::Local {
                        project_dir: args.project_dir,
                    })
                } else {
                    Ok(Self::Cloud {
                        endpoint: args.endpoint,
                    })
                }
            }
            ModeKind::Cloud => {
                if args.project_dir.is_some() {
                    Err((
                        ErrorKind::ArgumentConflict,
                        "the argument '--project-dir <DIR>' cannot be used with '--mode cloud'",
                    ))
                } else {
                    Ok(Self::Cloud {
                        endpoint: args.endpoint,
                    })
                }
            }
            ModeKind::Local => {
                if args.endpoint.is_some() {
                    Err((
                        ErrorKind::ArgumentConflict,
                        "the argument '--endpoint <URL>' cannot be used with '--mode local'",
                    ))
                } else {
                    Ok(Self::Local {
                        project_dir: args.project_dir,
                    })
                }
            }
        }
    }
}
