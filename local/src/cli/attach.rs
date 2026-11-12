use crate::config::{CONFIG_DIR, LocalServiceConfig};
use click_core::constants::APP_SLUG;
use std::env;
use std::path::Path;

pub fn attach_project(silent: bool) {
    let cwd = format!(
        "{}",
        env::current_dir()
            .expect("Error getting the current directory, please check permissions")
            .display()
    );

    let load_error = &format!(
        "Error loading local click vault config, please check permissions for {}",
        CONFIG_DIR.display()
    );

    let mut config = LocalServiceConfig::load().expect(load_error);

    if config.known_projects.contains(&cwd) {
        if Path::new(&cwd)
            .join(format!(".{}/config.json", APP_SLUG))
            .is_file()
        {
            eprintln!("Project is already attached, you can manage on https://vault.vercel.click")
        } else {
            eprintln!(
                "Project is already attached but not setup, you can complete the setup on https://vault.verce.click"
            )
        }
    } else {
        config.known_projects.push(cwd.clone());

        let write_error = &format!(
            "Error writing local click vault config, please check permissions for {}",
            CONFIG_DIR.display()
        );
        config.write().expect(write_error);

        eprintln!("{cwd} attached, you can now manage it through https://vault.vercel.click");
    }

    if !silent {
        let _ = webbrowser::open("https://vault.vercel.click");
    }
}
