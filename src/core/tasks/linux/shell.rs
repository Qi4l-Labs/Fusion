use std::{
    io::{Error, ErrorKind},
    process::Command,
};

pub async fn shell(command: String) -> Result<Vec<u8>, Error> {
    let args = match shellwords::split(&command) {
        Ok(args) => args,
        Err(e) => {
            return Err(Error::new(ErrorKind::Other, "Could not parse the command."));
        }
    };

    let mut result: Vec<u8> = Vec::new();

    if args.len() == 0 {
        return Err(Error::new(ErrorKind::Other, "No command given."));
    } else if args.len() == 1 {
        result = match Command::new(args[0].as_str()).output() {
            Ok(o) => o.stdout,
            _ => "No output.".as_bytes().to_vec(),
        };
    } else {
        result = match Command::new(args[0].as_str()).arg(args[1..].join(" ").as_str()).output() {
            Ok(o) => o.stdout,
            _ => "No output.".as_bytes().to_vec(),
        };
    }

    if result.len() == 0 {
        result = "Success.".as_bytes().to_vec();
    }

    Ok(result)
}