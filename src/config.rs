use std::path::PathBuf;

#[derive(Debug)]
pub struct Config {
    pub app_dir: PathBuf,
}

impl Config {
    pub fn new() -> Self {
        Self {
            app_dir: PathBuf::from(".fusion"),
        }
    }
}