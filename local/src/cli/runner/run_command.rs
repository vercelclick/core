use std::collections::HashMap;
use std::process::Command;

pub fn run_command_with_secrets(plain_values: HashMap<String, String>, user_command: String) {
    let mut command = Command::new("sh");

    command.arg("-c").arg(&user_command).envs(plain_values);

    use std::os::unix::process::CommandExt;

    let error = command.exec();
    panic!("Failed to start the command: {:?}", error);
}
