use crate::config::{CONFIG_DIR, LocalServiceConfig};
use crate::utils::short_path;
use click_core::constants::APP_SLUG;
use std::path::Path;
use std::process::exit;
use std::{env, fs};

pub fn attach_project(silent: bool, target: Option<String>) {
    let path = match target {
        Some(target) => fs::canonicalize(Path::new(&target))
            .expect("Error resolving provided project directory, confirm the directory exists"),
        None => env::current_dir()
            .expect("Error getting the current directory, please check permissions"),
    };

    if !path.exists() {
        eprintln!("Target directory {} does not exist", path.display());
        exit(1)
    }

    let load_error = &format!(
        "Error loading local click vault config, please check permissions for {}",
        CONFIG_DIR.display()
    );

    let mut config = LocalServiceConfig::load().expect(load_error);
    let path_str = format!("{}", path.display());

    if config.known_projects.contains(&path_str) {
        if path.join(format!(".{}/config.json", APP_SLUG)).is_file() {
            eprintln!("Project is already attached, you can manage on https://vault.vercel.click")
        } else {
            eprintln!(
                "Project is already attached but not setup, you can complete the setup on https://vault.verce.click"
            )
        }
    } else {
        config.known_projects.push(path_str.clone());

        let write_error = &format!(
            "Error writing local vault config, please check permissions for {}",
            CONFIG_DIR.display()
        );
        config.write().expect(write_error);

        eprintln!(
            "{} attached, you can now manage it through https://vault.vercel.click",
            short_path(&path_str)
        );
    }

    if !silent {
        let _ = webbrowser::open("https://vault.vercel.click");
    }
}
