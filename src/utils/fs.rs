use std::fs::{self, File};
use std::io::{Error, ErrorKind, Read, Write};
use std::path::Path;
use log::{error, warn};
use serde_json::{Value, from_reader};


pub fn read_json(key: &str, value: &str) -> String {
    let json_content = fs::read_to_string("config.json").unwrap();
    let json: Value = serde_json::from_str(&json_content).unwrap();
    let fusion_host = &json[key][value].as_str().unwrap().trim_matches('"');
    fusion_host.to_string()
}

pub fn get_app_dir() -> String {
    match home::home_dir() {
        Some(path) if !path.as_os_str().is_empty() => {
            format!("{}/.fusion", path.to_string_lossy().to_string())
        }
        _ => {

            ".fusion".to_string()
        }
    }
}

pub fn mkdir(dirpath: String) -> Result<(), std::io::Error> {
    if exists_file(dirpath.to_owned()) {
        return Ok(());
    }

    let fusion_dirpath = format!("{}/{}", get_app_dir(), dirpath);

    match fs::create_dir_all(&fusion_dirpath) {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("Failed to create directory: {}", e);
            Err(e)
        }
    }
}

pub fn mkfile(filepath: String) -> Result<(), std::io::Error> {
    if exists_file(filepath.to_owned()) {
        return Ok(());
    }

    let fusion_filepath: String;
    if filepath.contains(".fusion") {
        fusion_filepath = filepath;
    } else {
        fusion_filepath = format!("{}/{}", get_app_dir(), filepath);
    }

    match File::create(fusion_filepath) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn read_file(filepath: String) -> Result<Vec<u8>, Error> {
    let fusion_filepath: String;
    if filepath.contains(".fusion") {
        fusion_filepath = filepath;
    } else {
        fusion_filepath = format!("{}/{}", get_app_dir(), filepath);
    }

    let mut f = File::open(fusion_filepath)?;
    let mut data = vec![];
    f.read_to_end(&mut data)?;

    Ok(data)
}

pub fn write_file(filepath: String, data: &[u8]) -> Result<(), Error> {
    let fusion_filepath: String;
    if filepath.contains(".fusion") {
        fusion_filepath = filepath;
    } else {
        fusion_filepath = format!("{}/{}", get_app_dir(), filepath);
    }

    let mut f = File::create(fusion_filepath)?;
    f.write_all(data)?;

    Ok(())
}

pub fn empty_file(filepath: String) -> Result<(), Error> {
    let fusion_filepath: String;
    if filepath.contains(".fusion") {
        fusion_filepath = filepath;
    } else {
        fusion_filepath = format!("{}/{}", get_app_dir(), filepath);
    }
    
    let mut f = File::create(fusion_filepath)?;
    f.write_all(b"")?;
    Ok(())
}

pub fn exists_file(filepath: String) -> bool {
    let fusion_filepath: String;
    if filepath.contains(".fusion") {
        fusion_filepath = filepath;
    } else {
        fusion_filepath = format!("{}/{}", get_app_dir(), filepath);
    }

    Path::new(&fusion_filepath).exists()
}