use secretpass_core::KeyPair;
use std::collections::HashMap;
use std::process::Command;

pub fn run_command_with_secrets(
    private_key: KeyPair,
    encrypted_secrets: HashMap<String, String>,
    user_command: String,
) {
    let variables = private_key.decrypt_package(&encrypted_secrets).unwrap();

    let mut command = Command::new("sh");

    command.arg("-c").arg(&user_command).envs(variables);

    use std::os::unix::process::CommandExt;

    let error = command.exec();
    panic!("Failed to start the command: {:?}", error);
}
