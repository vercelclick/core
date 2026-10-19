use std::collections::HashMap;

use std::process::Command as StdCommand;

pub struct CommandInstance {
    pub command: String,
}

impl CommandInstance {
    pub fn new(command: String) -> Self {
        Self { command }
    }

    pub fn run_machine(&mut self, variables: HashMap<String, String>) {
        let (mut command, arg_prefix) = if cfg!(target_os = "windows") {
            (StdCommand::new("cmd"), "/C")
        } else {
            (StdCommand::new("sh"), "-c")
        };

        command.arg(arg_prefix).arg(&self.command).envs(variables);

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;

            let error = command.exec();
            panic!("Failed to start the command: {:?}", error);
        }

        #[cfg(not(unix))]
        {
            let mut child = match command.spawn() {
                Ok(child) => child,
                Err(err) => {
                    panic!("Failed to start the command: {:?}", err)
                }
            };
            let exit_status = match child.wait() {
                Ok(status) => status,
                Err(err) => {
                    panic!("Failed to wait for the command: {:?}", err)
                }
            };

            std::process::exit(exit_status.code().unwrap_or(0));
        }
    }
}
