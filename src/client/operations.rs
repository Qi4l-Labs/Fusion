use clap::ArgMatches;

use super::{
    client::{Client, Mode},
    options::{
        agent::AgentOption,
        implant::ImplantOption,
        listener::ListenerOption,
        options::Options,
        task::TaskOption,
    },
};
use crate::utils::random::random_name;

#[derive(Debug)]
pub enum Operation {
    // Root operations
    // Common
    Empty,
    Exit,
    Unknown,
    // Listeners
    AddListener,
    DeleteListener,
    StartListener,
    StopListener,
    InfoListener,
    ListListeners,
    // Agents
    UseAgent,
    DeleteAgent,
    InfoAgent,
    ListAgents,
    // Implants
    GenerateImplant,
    DownloadImplant,
    DeleteImplant,
    InfoImplant,
    ListImplants,

    // Agent operations
    // Common
    AgentEmpty,
    AgentExit,
    AgentUnknown,
    // Tasks
    AgentTaskCd,
    AgentTaskLs,
    AgentTaskPwd,
    AgentTaskScreenshot,
    AgentTaskShell,
    AgentTaskSleep,
    AgentTaskDownload,
    AgentTaskUpload,
    AgentTaskWhoami,
    AgentTaskRm,
    AgentTaskShellcode,
}

pub fn set_operations(client: &Client, matches: &ArgMatches) -> (Operation, Options) {
    let op;
    let mut options = Options::new();

    match &client.mode {
        Mode::Root => {
            match matches.subcommand() {
                // Listener
                Some(("listener", subm)) => {
                    match subm.subcommand() {
                        Some(("add", subm2)) => {
                            op = Operation::AddListener;
                            let name = match subm2.get_one::<String>("name") {
                                Some(n) => Some(n.to_owned()),
                                None => Some(random_name("listener".to_owned())),
                            };
                            let domains: Option<Vec<String>> = match subm2.get_one::<String>("domains") {
                                Some(n) => {
                                    Some(n.split(",").map(|s| s.to_string()).collect())
                                }
                                None => Some(Vec::new()),
                            };
                            let listener_option = ListenerOption {
                                name,
                                domains,
                                proto: subm2.get_one::<String>("protocol").cloned(),
                                host: subm2.get_one::<String>("host").cloned(),
                                port: subm2.get_one::<u16>("port").cloned(),
                            };
                            options.listener_opt = Some(listener_option);
                        }
                        Some(("delete", subm2)) => {
                            op = Operation::DeleteListener;
                            let target = match subm2.get_one::<String>("listener") {
                                Some(n) => { Some(n.to_owned()) },
                                None => { None },
                            };
        
                            options.listener_opt = Some(ListenerOption {
                                name: target,
                                domains: None,
                                proto: None,
                                host: None,
                                port: None,
                            });
                        }
                        Some(("start", subm2)) => {
                            op = Operation::StartListener;
                            let target = match subm2.get_one::<String>("listener") {
                                Some(n) => { Some(n.to_owned()) },
                                None => { None },
                            };
        
                            options.listener_opt = Some(ListenerOption {
                                name: target,
                                domains: None,
                                proto: None,
                                host: None,
                                port: None,
                            });
                        }
                        Some(("stop", subm2)) => {
                            op = Operation::StopListener;
                            let target = match subm2.get_one::<String>("listener") {
                                Some(n) => { Some(n.to_owned()) },
                                None => { None },
                            };
        
                            options.listener_opt = Some(ListenerOption {
                                name: target,
                                domains: None,
                                proto: None,
                                host: None,
                                port: None,
                            });
                        }
                        Some(("info", subm2)) => {
                            op = Operation::InfoListener;
                            let target = match subm2.get_one::<String>("listener") {
                                Some(n) => { Some(n.to_owned()) },
                                None => { None },
                            };

                            options.listener_opt = Some(ListenerOption {
                                name: target,
                                domains: None,
                                proto: None,
                                host: None,
                                port: None,
                            });
                        }
                        Some(("list", _)) => {
                            op = Operation::ListListeners;
                        }
                        _ => {
                            op = Operation::Unknown;
                        }
                    }
                }
                Some(("listeners", _)) => {
                    op = Operation::ListListeners;
                }
                // Agent
                Some(("agent", subm)) => {
                    match subm.subcommand() {
                        Some(("use", subm2)) => {
                            op = Operation::UseAgent;
                            let name = match subm2.get_one::<String>("name") {
                                Some(n) => { n.to_owned() },
                                None => { "0".to_owned() },
                            };
        
                            options.agent_opt = Some(AgentOption {
                                name,
                            });
                        }
                        Some(("delete", subm2)) => {
                            op = Operation::DeleteAgent;
                            let name = match subm2.get_one::<String>("name") {
                                Some(n) => { n.to_owned() },
                                None => { "0".to_owned() },
                            };

                            options.agent_opt = Some(AgentOption {
                                name,
                            });
                        }
                        Some(("info", subm2)) => {
                            op = Operation::InfoAgent;
                            let name = match subm2.get_one::<String>("name") {
                                Some(n) => { n.to_owned() },
                                None => { "0".to_owned() },
                            };

                            options.agent_opt = Some(AgentOption {
                                name,
                            });
                        }
                        Some(("list", _)) => {
                            op = Operation::ListAgents;
                        }
                        _ => {
                            op = Operation::Unknown;
                        }
                    }
                }
                Some(("agents", _)) => {
                    op = Operation::ListAgents;
                }
                // Implant
                Some(("implant", subm)) => {
                    match subm.subcommand() {
                        Some(("gen", subm2)) => {
                            op = Operation::GenerateImplant;
                            let name = match subm2.get_one::<String>("name") {
                                Some(n) => { n.to_owned() },
                                None => { random_name("implant".to_owned()) }
                            };
                            let url = match subm2.get_one::<String>("url") {
                                Some(n) => { n.to_owned() },
                                None => { "http://localhost:4443/".to_owned() }
                            };
                            let os = match subm2.get_one::<String>("os") {
                                Some(n) => { n.to_owned() },
                                None => { "windows".to_owned() }
                            };
                            let arch = match subm2.get_one::<String>("arch") {
                                Some(n) => { n.to_owned() },
                                None => { "amd64".to_owned() }
                            };
                            let format = match subm2.get_one::<String>("format") {
                                Some(n) => { n.to_owned() },
                                None => { "exe".to_owned() }
                            };
                            let sleep = match subm2.get_one::<u64>("sleep") {
                                Some(n) => { *n },
                                None => { 3 }
                            };
                            let jitter = match subm2.get_one::<u64>("jitter") {
                                Some(j) => { *j },
                                None => { 5 }
                            };
        
                            options.implant_opt = Some(ImplantOption {
                                name: Some(name),
                                url: Some(url),
                                os: Some(os),
                                arch: Some(arch),
                                format: Some(format),
                                sleep: Some(sleep),
                                jitter: Some(jitter),
                            });
                        }
                        Some(("download", subm2)) => {
                            op = Operation::DownloadImplant;
                            let name = match subm2.get_one::<String>("name") {
                                Some(n) => n.to_owned(),
                                None => "0".to_owned(),
                            };
        
                            options.implant_opt = Some(ImplantOption {
                                name: Some(name),
                                url: None,
                                os: None,
                                arch: None,
                                format: None,
                                sleep: None,
                                jitter: None,
                            });
                        }
                        Some(("delete", subm2)) => {
                            op = Operation::DeleteImplant;
                            let name = match subm2.get_one::<String>("name") {
                                Some(n) => n.to_owned(),
                                None => "0".to_owned(),
                            };

                            options.implant_opt = Some(ImplantOption {
                                name: Some(name),
                                url: None,
                                os: None,
                                arch: None,
                                format: None,
                                sleep: None,
                                jitter: None,
                            });
                        }
                        Some(("info", subm2)) => {
                            op = Operation::InfoImplant;
                            let name = match subm2.get_one::<String>("name") {
                                Some(n) => n.to_owned(),
                                None => "0".to_owned(),
                            };

                            options.implant_opt = Some(ImplantOption {
                                name: Some(name),
                                url: None,
                                os: None,
                                arch: None,
                                format: None,
                                sleep: None,
                                jitter: None,
                            });
                        }
                        Some(("list", _)) => {
                            op = Operation::ListImplants;
                        }
                        _ => {
                            op = Operation::Unknown;
                        }
                    }
                }
                // Misc
                Some(("exit", _)) | Some(("quit", _)) => {
                    op = Operation::Exit;
                }
                None => {
                    op = Operation::Empty;
                }
                _ => {
                    op = Operation::Unknown;
                },
            }
        }
        Mode::Agent(agent_name, agent_os) => {
            match matches.subcommand() {
                // Tasks
                Some(("cd", subm)) => {
                    op = Operation::AgentTaskCd;

                    let dir = match subm.get_one::<String>("directory") {
                        Some(d) => d.to_owned(),
                        None => "".to_owned(),
                    };

                    options.task_opt = Some(TaskOption {
                        agent_name: Some(agent_name.to_owned()),
                        args: Some(dir),
                    });
                }
                Some(("ls", subm)) => {
                    op = Operation::AgentTaskLs;

                    let dir = match subm.get_one::<String>("directory") {
                        Some(d) => d.to_owned(),
                        None => "".to_owned(),
                    };

                    options.task_opt = Some(TaskOption {
                        agent_name: Some(agent_name.to_owned()),
                        args: Some(dir),
                    });
                }
                Some(("pwd", _)) => {
                    op = Operation::AgentTaskPwd;
                    options.task_opt = Some(TaskOption {
                        agent_name: Some(agent_name.to_owned()),
                        args: None,
                    });
                }
                Some(("screenshot", _)) => {
                    op = Operation::AgentTaskScreenshot;
                    options.task_opt = Some(TaskOption {
                        agent_name: Some(agent_name.to_owned()),
                        args: None,
                    });
                }
                Some(("shell", subm)) => {
                    op = Operation::AgentTaskShell;

                    match agent_os.as_str() {
                        "macos" => {
                            let command = match subm.get_one::<String>("command") {
                                Some(c) => c.to_owned(),
                                None => "".to_owned(),
                            };

                            options.task_opt = Some(TaskOption {
                                agent_name: Some(agent_name.to_owned()),
                                args: Some(command),
                            });
                        }
                        "linux" => {
                            let command = match subm.get_one::<String>("command") {
                                Some(c) => c.to_owned(),
                                None => "".to_owned(),
                            };

                            options.task_opt = Some(TaskOption {
                                agent_name: Some(agent_name.to_owned()),
                                args: Some(command),
                            });
                        }
                        "windows" | _ => {
                            let mut pre = "cmd";
                            // shell --ps ls
                            if subm.get_flag("ps") {
                                pre = "powershell";
                            }
                            let command = match subm.get_one::<String>("command") {
                                Some(c) => c.to_owned(),
                                None => "".to_owned(),
                            };
        
                            options.task_opt = Some(TaskOption {
                                agent_name: Some(agent_name.to_owned()),
                                args: Some(pre.to_string() + " " + command.as_str()),
                            });
                        }
                    }

                }
                Some(("sleep", subm)) => {
                    op = Operation::AgentTaskSleep;
                    let time = match subm.get_one::<String>("time") {
                        Some(c) => c.to_owned(),
                        None => "".to_owned(),
                    };

                    options.task_opt = Some(TaskOption {
                        agent_name: Some(agent_name.to_owned()),
                        args: Some(time),
                    });
                }
                Some(("download", subm)) => {
                    op = Operation::AgentTaskDownload;
                    let f_qi8l_path = match subm.get_one::<String>("file") {
                        Some(c) => c.to_owned(),
                        None => "".to_owned(),
                    };

                    options.task_opt = Some(TaskOption {
                        agent_name: Some(agent_name.to_owned()),
                        args: Some(f_qi8l_path),
                    });
                }
                Some(("upload", subm)) => {
                    op = Operation::AgentTaskUpload;
                    let f_qi7l_path = match subm.get_one::<String>("file") {
                        Some(c) => c.to_owned(),
                        None => "".to_owned(),
                    };

                    options.task_opt = Some(TaskOption {
                        agent_name: Some(agent_name.to_owned()),
                        args: Some(f_qi7l_path),
                    });
                }
                Some(("whoami", _)) => {
                    op = Operation::AgentTaskWhoami;
                    options.task_opt = Some(TaskOption {
                        agent_name: Some(agent_name.to_owned()),
                        args: None,
                    });
                }
                Some(("rm", subm)) => {
                    op = Operation::AgentTaskRm;

                    let path = match subm.get_one::<String>("file") {
                        Some(d) => d.to_owned(),
                        None => "".to_owned(),
                    };

                    options.task_opt = Some(TaskOption {
                        agent_name: Some(agent_name.to_owned()),
                        args: Some(path),
                    });
                }
                Some(("shellcode", subm)) => {
                    op = Operation::AgentTaskShellcode;

                    let path = match subm.get_one::<String>("bin") {
                        Some(d) => d.to_owned(),
                        None => "".to_owned(),
                    };

                    options.task_opt = Some(TaskOption {
                        agent_name: Some(agent_name.to_owned()),
                        args: Some(path),
                    });
                }
                // Misc
                Some(("exit", _)) | Some(("quit", _)) => {
                    op = Operation::AgentExit;
                }
                None => {
                    op = Operation::AgentEmpty;
                }
                _ => {
                    op = Operation::AgentUnknown;
                }
            }
        }
    }


    (op, options)
}