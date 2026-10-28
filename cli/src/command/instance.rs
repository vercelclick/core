use std::collections::HashMap;

use std::process::Command;

pub struct CommandInstance {
    pub command: String,
}

impl CommandInstance {
    pub fn new(command: String) -> Self {
        Self { command }
    }

    pub fn run_machine(&mut self, variables: HashMap<String, String>) {
        let mut command = Command::new("sh");

        command.arg("-c").arg(&self.command).envs(variables);

        use std::os::unix::process::CommandExt;

        let error = command.exec();
        panic!("Failed to start the command: {:?}", error);
    }
}
