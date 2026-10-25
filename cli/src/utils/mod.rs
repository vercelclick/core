pub fn short_path(path: String) -> String {
    if let Some(home_dir) = dirs::home_dir() {
        let home_dir = format!("{}", home_dir.display());

        if let Some(short) = path.strip_prefix(&home_dir) {
            format!("~{short}")
        } else {
            path
        }
    } else {
        path
    }
}
