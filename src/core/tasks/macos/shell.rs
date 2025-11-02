use std::{
    io::{Error, ErrorKind},
    process::Command,
};

pub async fn shell(command: String) -> Result<Vec<u8>, Error> {
    let args = match shellwords::split(&command) {
        Ok(args) => args,
        Err(_) => {
            return Err(Error::new(ErrorKind::Other, "Could not parse the command."));
        }
    };


    let mut result: Vec<u8> = Vec::new();

    if args.is_empty() {
        return Err(Error::new(ErrorKind::Other, "No command given."));
    } else {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(command);

        result = match cmd.output() {
            Ok(o) => {
                o.stdout
            }
            Err(e) => {
                "No output.".as_bytes().to_vec()
            }
        };
    }

    if result.is_empty() {
        result = "Success.".as_bytes().to_vec();
    }

    Ok(result)
}