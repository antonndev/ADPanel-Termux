use crate::app::AppState;
use axum::extract::ws::{Message, WebSocket};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use std::fs;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::broadcast;

#[derive(Deserialize)]
#[serde(tag = "type")]
enum WsMessage {
    #[serde(rename = "join")]
    Join { bot: String },
    #[serde(rename = "readFile")]
    ReadFile { bot: String, path: String },
    #[serde(rename = "writeFile")]
    WriteFile {
        bot: String,
        path: String,
        content: String,
    },
    #[serde(rename = "deleteFile")]
    DeleteFile {
        bot: String,
        path: String,
        #[serde(rename = "isDir")]
        #[serde(default)]
        is_dir: bool,
    },
    #[serde(rename = "action")]
    Action {
        bot: String,
        cmd: String,
        #[serde(default)]
        file: String,
        #[serde(default)]
        version: String,
        #[serde(default)]
        port: String,
    },
    #[serde(rename = "command")]
    Command { bot: String, command: String },
    #[serde(rename = "packageCmd")]
    PackageCmd { bot: String, cmd: String },
}

pub async fn handle_ws(socket: WebSocket, state: AppState, bot_name: String, email: String) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    // Subscribe to bot channel for output
    let channel = state.get_or_create_channel(&bot_name);
    let mut rx = channel.subscribe();

    // Send existing log buffer as a single batched message (one WS frame)
    let buffer = state.get_log_buffer(&bot_name);
    if !buffer.is_empty() {
        let mut batch = String::with_capacity(buffer.len() * 80);
        for line in &buffer {
            batch.push_str(line);
        }
        let msg = format_output_json(&batch);
        let _ = ws_tx.send(Message::Text(msg.into())).await;
    }

    // Task to forward broadcast messages to websocket with output coalescing.
    // Batches rapid output lines into single WS frames (reduces syscalls + battery wake-ups).
    let tx_handle = tokio::spawn(async move {
        let mut batch = String::with_capacity(512);
        loop {
            // Wait for first message
            match rx.recv().await {
                Ok(line) => {
                    if line.starts_with("__fileData__") {
                        let json_str = &line["__fileData__".len()..];
                        if ws_tx.send(Message::Text(json_str.to_string().into())).await.is_err() {
                            break;
                        }
                    } else {
                        batch.push_str(&line);
                    }
                }
                Err(_) => break,
            }

            // Drain any additional queued messages (coalesce burst output)
            loop {
                match rx.try_recv() {
                    Ok(line) => {
                        if line.starts_with("__fileData__") {
                            // Flush text batch first, then send fileData
                            if !batch.is_empty() {
                                let msg = format_output_json(&batch);
                                if ws_tx.send(Message::Text(msg.into())).await.is_err() {
                                    break;
                                }
                                batch.clear();
                            }
                            let json_str = &line["__fileData__".len()..];
                            if ws_tx.send(Message::Text(json_str.to_string().into())).await.is_err() {
                                break;
                            }
                        } else {
                            batch.push_str(&line);
                        }
                    }
                    Err(_) => break,
                }
            }

            // Send the coalesced batch as one WS frame
            if !batch.is_empty() {
                let msg = format_output_json(&batch);
                if ws_tx.send(Message::Text(msg.into())).await.is_err() {
                    break;
                }
                batch.clear();
            }
        }
    });

    // Process incoming messages
    while let Some(Ok(msg)) = ws_rx.next().await {
        match msg {
            Message::Text(text) => {
                if let Ok(ws_msg) = serde_json::from_str::<WsMessage>(&text) {
                    handle_ws_message(&state, &bot_name, &email, ws_msg, &channel).await;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    tx_handle.abort();
}

/// Format output JSON without serde overhead
#[inline]
fn format_output_json(data: &str) -> String {
    let escaped = escape_json_string(data);
    let mut s = String::with_capacity(28 + escaped.len());
    s.push_str(r#"{"type":"output","data":""#);
    s.push_str(&escaped);
    s.push_str(r#""}"#);
    s
}

/// Escape a string for safe JSON embedding.
/// Fast-path: if no escaping is needed, returns the input without allocation.
fn escape_json_string(s: &str) -> std::borrow::Cow<'_, str> {
    // Fast check: if nothing needs escaping, return as-is (zero allocation)
    let needs_escape = s.bytes().any(|b| b == b'"' || b == b'\\' || b < 0x20);
    if !needs_escape {
        return std::borrow::Cow::Borrowed(s);
    }

    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str(r#"\""#),
            '\\' => out.push_str(r#"\\"#),
            '\n' => out.push_str(r#"\n"#),
            '\r' => out.push_str(r#"\r"#),
            '\t' => out.push_str(r#"\t"#),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(out, r#"\u{:04x}"#, c as u32);
            }
            c => out.push(c),
        }
    }
    std::borrow::Cow::Owned(out)
}

async fn handle_ws_message(
    state: &AppState,
    bot_name: &str,
    _email: &str,
    msg: WsMessage,
    channel: &broadcast::Sender<Arc<str>>,
) {
    match msg {
        WsMessage::Join { .. } => {
            // Already joined on connect
        }
        WsMessage::ReadFile { bot, path } => {
            let full = state.bots_dir.join(&bot).join(&path);
            if full.exists() && full.is_file() {
                match fs::read_to_string(&full) {
                    Ok(content) => {
                        let msg = serde_json::json!({
                            "type": "fileData",
                            "path": path,
                            "content": content
                        });
                        let _ = channel.send(Arc::from(format!("__fileData__{}", msg).as_str()));
                    }
                    Err(_) => {
                        send_output(state, channel, bot_name, "Failed to read file\n");
                    }
                }
            } else {
                send_output(state, channel, bot_name, "File not found\n");
            }
        }
        WsMessage::WriteFile { bot, path, content } => {
            let full = state.bots_dir.join(&bot).join(&path);
            match fs::write(&full, &content) {
                Ok(_) => send_output(state, channel, bot_name, &format!("Saved {}\n", path)),
                Err(_) => send_output(state, channel, bot_name, "Failed to write file\n"),
            }
        }
        WsMessage::DeleteFile {
            bot,
            path,
            is_dir,
        } => {
            let full = state.bots_dir.join(&bot).join(&path);
            if full.exists() {
                let result = if is_dir {
                    fs::remove_dir_all(&full)
                } else {
                    fs::remove_file(&full)
                };
                match result {
                    Ok(_) => send_output(state, channel, bot_name, &format!("Deleted {}\n", path)),
                    Err(_) => send_output(state, channel, bot_name, "Failed to delete\n"),
                }
            } else {
                send_output(state, channel, bot_name, "Not found\n");
            }
        }
        WsMessage::Action {
            bot,
            cmd,
            file,
            version,
            port,
        } => {
            handle_action(state, channel, &bot, &cmd, &file, &version, &port).await;
        }
        WsMessage::Command { bot, command } => {
            handle_command(state, channel, &bot, &command).await;
        }
        WsMessage::PackageCmd { bot, cmd } => {
            handle_package_cmd(state, channel, &bot, &cmd).await;
        }
    }
}

async fn handle_action(
    state: &AppState,
    channel: &broadcast::Sender<Arc<str>>,
    bot: &str,
    cmd: &str,
    file: &str,
    version: &str,
    port: &str,
) {
    let cwd = state.bots_dir.join(bot);
    if !cwd.exists() {
        send_output(state, channel, bot, "Bot directory not found\n");
        return;
    }

    match cmd {
        "run" => {
            // Kill existing process
            if state.processes.contains_key(bot) {
                if let Some((_, mut handle)) = state.processes.remove(bot) {
                    let _ = handle.child.kill().await;
                }
            }

            let safe_file = match state.sanitize_filename(file) {
                Some(f) => f,
                None => {
                    send_output(state, channel, bot, "Invalid file name\n");
                    return;
                }
            };

            let ext = std::path::Path::new(&safe_file)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");

            let mut child = if ext == "js" {
                // Ultra-efficient V8 flags for Termux/mobile:
                // - max-old-space-size=64: cap heap at 64MB (plenty for a Discord bot)
                // - max-semi-space-size=2: reduce young gen GC pressure (2MB)
                // - optimize_for_size: prefer smaller code over speed (less memory, less CPU cache pressure)
                // - gc-global: less frequent, more thorough GC (fewer CPU wakes)
                // - lite-mode: disable background compilation & optimization threads (saves CPU cores)
                // - no-compilation-cache: don't cache compiled code to disk (saves eMMC writes)
                // - single-threaded: run V8 on a single thread (fewer context switches)
                // - predictable: deterministic GC (no random timer-based GC)
                let mut cmd = Command::new("node");
                cmd.args([
                        "--max-old-space-size=64",
                        "--max-semi-space-size=2",
                        "--optimize_for_size",
                        "--gc-global",
                        "--no-warnings",
                        "--lite-mode",
                        "--no-compilation-cache",
                        "--single-threaded",
                        "--predictable",
                        &safe_file,
                    ])
                    .current_dir(&cwd)
                    .env("NODE_ENV", "production")
                    .env("UV_THREADPOOL_SIZE", "2")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                // Run at low CPU priority (nice 15) to minimize battery impact
                unsafe { cmd.pre_exec(|| { libc::nice(15); Ok(()) }); }
                match cmd.spawn()
                {
                    Ok(c) => c,
                    Err(e) => {
                        send_output(
                            state,
                            channel,
                            bot,
                            &format!("Failed to start process: {}\n", e),
                        );
                        return;
                    }
                }
            } else if ext == "py" {
                // Ultra-efficient Python flags for Termux/mobile:
                // - -O: optimize bytecode (strips asserts, __debug__)
                // - -B: don't write .pyc files (saves eMMC writes on Termux)
                // - -u: unbuffered output
                let python_cmd = &*state.python_cmd;
                let mut cmd = Command::new(python_cmd);
                cmd.args(["-O", "-B", "-u", &safe_file])
                    .current_dir(&cwd)
                    .env("PYTHONUNBUFFERED", "1")
                    .env("PYTHONDONTWRITEBYTECODE", "1")
                    .env("PYTHONOPTIMIZE", "1")
                    .env("PYTHONHASHSEED", "0")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                unsafe { cmd.pre_exec(|| { libc::nice(15); Ok(()) }); }
                match cmd.spawn()
                {
                    Ok(c) => c,
                    Err(e) => {
                        send_output(
                            state,
                            channel,
                            bot,
                            &format!("Failed to start Python process: {}\n", e),
                        );
                        return;
                    }
                }
            } else {
                let safe_port = port.parse::<u16>().unwrap_or(3001).to_string();
                let mut cmd = Command::new("npx");
                cmd.args(["http-server", ".", "-p", &safe_port])
                    .current_dir(&cwd)
                    .env("NODE_ENV", "production")
                    .env("UV_THREADPOOL_SIZE", "2")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                unsafe { cmd.pre_exec(|| { libc::nice(15); Ok(()) }); }
                match cmd.spawn()
                {
                    Ok(c) => c,
                    Err(e) => {
                        send_output(
                            state,
                            channel,
                            bot,
                            &format!("Failed to start process: {}\n", e),
                        );
                        return;
                    }
                }
            };

            let stdout = child.stdout.take();
            let stderr = child.stderr.take();

            let bot_name = bot.to_string();
            let state_clone = state.clone();
            let channel_clone = channel.clone();

            // Store process handle
            state.processes.insert(
                bot.to_string(),
                crate::app::ProcessHandle { child },
            );

            // Stream stdout — 8KB buffer to reduce syscalls, coalesce output
            if let Some(stdout) = stdout {
                let bot_n = bot_name.clone();
                let sc = state_clone.clone();
                let cc = channel_clone.clone();
                tokio::spawn(async move {
                    let mut reader = BufReader::with_capacity(8192, stdout);
                    let mut line = String::with_capacity(256);
                    while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                        let arc: Arc<str> = Arc::from(line.as_str());
                        sc.push_log(&bot_n, arc.clone());
                        let _ = cc.send(arc);
                        line.clear();
                    }
                });
            }

            // Stream stderr — 8KB buffer
            if let Some(stderr) = stderr {
                let bot_n = bot_name.clone();
                let sc = state_clone.clone();
                let cc = channel_clone.clone();
                tokio::spawn(async move {
                    let mut reader = BufReader::with_capacity(8192, stderr);
                    let mut line = String::with_capacity(256);
                    while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                        let arc: Arc<str> = Arc::from(line.as_str());
                        sc.push_log(&bot_n, arc.clone());
                        let _ = cc.send(arc);
                        line.clear();
                    }
                });
            }

            // Wait for exit — check every 10s (minimal CPU wake for idle bots)
            let bot_n = bot_name.clone();
            let sc = state_clone;
            let cc = channel_clone;
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    if let Some(mut entry) = sc.processes.get_mut(&bot_n) {
                        match entry.value_mut().child.try_wait() {
                            Ok(Some(_)) => {
                                drop(entry);
                                sc.processes.remove(&bot_n);
                                let msg: Arc<str> = Arc::from("Bot process exited\n");
                                sc.push_log(&bot_n, msg.clone());
                                let _ = cc.send(msg);
                                break;
                            }
                            Ok(None) => continue,
                            Err(_) => {
                                drop(entry);
                                sc.processes.remove(&bot_n);
                                break;
                            }
                        }
                    } else {
                        break;
                    }
                }
            });

            send_output(state, channel, bot, &format!("Started {} process\n", file));
        }
        "stop" => {
            if let Some((_, mut handle)) = state.processes.remove(bot) {
                let _ = handle.child.kill().await;
                send_output(state, channel, bot, "Process forcefully stopped\n");
            } else {
                send_output(state, channel, bot, "No running process to stop\n");
            }
        }
        "install" => {
            let safe_versions = ["14", "16", "18", "20", "22"];
            if !safe_versions.contains(&version) {
                send_output(
                    state,
                    channel,
                    bot,
                    &format!(
                        "Invalid Node.js version. Allowed: {}\n",
                        safe_versions.join(", ")
                    ),
                );
                return;
            }
            let script = format!(
                "wget -qO- https://deb.nodesource.com/setup_{} | bash - && apt-get install -y nodejs",
                version
            );
            let channel_clone = channel.clone();
            let state_clone = state.clone();
            let bot_name = bot.to_string();
            tokio::spawn(async move {
                match Command::new("bash")
                    .args(["-c", &script])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                {
                    Ok(mut child) => {
                        if let Some(stdout) = child.stdout.take() {
                            let sc = state_clone.clone();
                            let cc = channel_clone.clone();
                            let bn = bot_name.clone();
                            tokio::spawn(async move {
                                let mut reader = BufReader::with_capacity(4096, stdout);
                                let mut line = String::new();
                                while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                                    let arc: Arc<str> = Arc::from(line.as_str());
                                    sc.push_log(&bn, arc.clone());
                                    let _ = cc.send(arc);
                                    line.clear();
                                }
                            });
                        }
                        if let Some(stderr) = child.stderr.take() {
                            let sc = state_clone;
                            let cc = channel_clone;
                            let bn = bot_name;
                            tokio::spawn(async move {
                                let mut reader = BufReader::with_capacity(4096, stderr);
                                let mut line = String::new();
                                while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                                    let arc: Arc<str> = Arc::from(line.as_str());
                                    sc.push_log(&bn, arc.clone());
                                    let _ = cc.send(arc);
                                    line.clear();
                                }
                            });
                        }
                    }
                    Err(e) => {
                        let msg: Arc<str> = Arc::from(format!("Failed to start install: {}\n", e).as_str());
                        state_clone.push_log(&bot_name, msg.clone());
                        let _ = channel_clone.send(msg);
                    }
                }
            });
        }
        _ => {
            send_output(state, channel, bot, "Unknown command\n");
        }
    }
}

async fn handle_command(
    state: &AppState,
    channel: &broadcast::Sender<Arc<str>>,
    bot: &str,
    command: &str,
) {
    if let Some(mut entry) = state.processes.get_mut(bot) {
        if let Some(ref mut stdin) = entry.value_mut().child.stdin {
            let cmd_line = format!("{}\n", command);
            if stdin.write_all(cmd_line.as_bytes()).await.is_ok() {
                let echo: Arc<str> = Arc::from(format!("> {}\n", command).as_str());
                state.push_log(bot, echo.clone());
                let _ = channel.send(echo);
            } else {
                send_output(state, channel, bot, "Failed to send command\n");
            }
        } else {
            send_output(state, channel, bot, "Process stdin not available\n");
        }
    } else {
        send_output(state, channel, bot, "The server is offline\n");
    }
}

fn send_output(state: &AppState, channel: &broadcast::Sender<Arc<str>>, bot: &str, msg: &str) {
    let arc: Arc<str> = Arc::from(msg);
    state.push_log(bot, arc.clone());
    let _ = channel.send(arc);
}

/// Whitelisted package management commands that users can run from the console.
/// Each command is validated to prevent arbitrary shell execution.
async fn handle_package_cmd(
    state: &AppState,
    channel: &broadcast::Sender<Arc<str>>,
    bot: &str,
    cmd: &str,
) {
    let cwd = state.bots_dir.join(bot);
    if !cwd.exists() {
        send_output(state, channel, bot, "Bot directory not found\n");
        return;
    }

    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.is_empty() {
        send_output(state, channel, bot, "Empty command\n");
        return;
    }

    // Validate and build the command based on strict whitelist
    let (program, args) = match parts[0] {
        "npm" => {
            let allowed_npm = [
                "install", "i", "update", "up", "list", "ls", "outdated",
                "audit", "prune", "dedupe", "ci", "rebuild", "uninstall", "remove",
                "init", "run", "test", "start",
            ];
            if parts.len() < 2 || !allowed_npm.contains(&parts[1]) {
                send_output(
                    state,
                    channel,
                    bot,
                    &format!(
                        "Allowed npm subcommands: {}\n",
                        allowed_npm.join(", ")
                    ),
                );
                return;
            }
            // Validate remaining args: no shell metacharacters
            for arg in &parts[2..] {
                if arg.contains("&&")
                    || arg.contains("||")
                    || arg.contains(';')
                    || arg.contains('`')
                    || arg.contains('$')
                    || arg.contains('|')
                    || arg.contains('>')
                    || arg.contains('<')
                    || arg.starts_with('-') && arg.contains("scripts")
                {
                    send_output(state, channel, bot, "Invalid characters in arguments\n");
                    return;
                }
            }
            ("npm", parts[1..].to_vec())
        }
        "npx" => {
            if parts.len() < 2 {
                send_output(state, channel, bot, "Usage: npx <package> [args]\n");
                return;
            }
            for arg in &parts[1..] {
                if arg.contains("&&")
                    || arg.contains("||")
                    || arg.contains(';')
                    || arg.contains('`')
                    || arg.contains('$')
                    || arg.contains('|')
                    || arg.contains('>')
                    || arg.contains('<')
                {
                    send_output(state, channel, bot, "Invalid characters in arguments\n");
                    return;
                }
            }
            ("npx", parts[1..].to_vec())
        }
        "node" => {
            if parts.len() < 2 {
                send_output(state, channel, bot, "Usage: node <file> [args]\n");
                return;
            }
            // Only allow running files, no flags that could be dangerous
            for arg in &parts[1..] {
                if arg.contains("&&")
                    || arg.contains("||")
                    || arg.contains(';')
                    || arg.contains('`')
                    || arg.contains('$')
                    || arg.contains('|')
                    || arg.contains('>')
                    || arg.contains('<')
                    || arg.contains("..")
                {
                    send_output(state, channel, bot, "Invalid characters in arguments\n");
                    return;
                }
            }
            ("node", parts[1..].to_vec())
        }
        "pip" | "pip3" => {
            let allowed_pip = [
                "install", "uninstall", "list", "freeze", "show", "check",
                "search", "update", "upgrade",
            ];
            if parts.len() < 2 || !allowed_pip.contains(&parts[1]) {
                send_output(
                    state,
                    channel,
                    bot,
                    &format!(
                        "Allowed pip subcommands: {}\n",
                        allowed_pip.join(", ")
                    ),
                );
                return;
            }
            for arg in &parts[2..] {
                if arg.contains("&&")
                    || arg.contains("||")
                    || arg.contains(';')
                    || arg.contains('`')
                    || arg.contains('$')
                    || arg.contains('|')
                    || arg.contains('>')
                    || arg.contains('<')
                {
                    send_output(state, channel, bot, "Invalid characters in arguments\n");
                    return;
                }
            }
            (parts[0], parts[1..].to_vec())
        }
        "python" | "python3" => {
            if parts.len() < 2 {
                send_output(state, channel, bot, "Usage: python <file> [args]\n");
                return;
            }
            // Only allow -m pip, -m venv, or running .py files
            let allowed = parts[1] == "-m"
                || parts[1].ends_with(".py")
                || parts[1] == "--version";
            if !allowed {
                send_output(
                    state,
                    channel,
                    bot,
                    "Allowed: python <file.py>, python -m <module>, python --version\n",
                );
                return;
            }
            for arg in &parts[1..] {
                if arg.contains("&&")
                    || arg.contains("||")
                    || arg.contains(';')
                    || arg.contains('`')
                    || arg.contains('$')
                    || arg.contains('|')
                    || arg.contains('>')
                    || arg.contains('<')
                    || arg.contains("..")
                {
                    send_output(state, channel, bot, "Invalid characters in arguments\n");
                    return;
                }
            }
            (parts[0], parts[1..].to_vec())
        }
        _ => {
            send_output(
                state,
                channel,
                bot,
                "Allowed commands: npm, npx, node, pip, pip3, python, python3\n",
            );
            return;
        }
    };

    let args_str: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    send_output(
        state,
        channel,
        bot,
        &format!("$ {} {}\n", program, args_str.join(" ")),
    );

    let channel_clone = channel.clone();
    let state_clone = state.clone();
    let bot_name = bot.to_string();
    let program = program.to_string();

    tokio::spawn(async move {
        match Command::new(&program)
            .args(&args_str)
            .current_dir(&cwd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                if let Some(stdout) = child.stdout.take() {
                    let sc = state_clone.clone();
                    let cc = channel_clone.clone();
                    let bn = bot_name.clone();
                    tokio::spawn(async move {
                        let mut reader = BufReader::with_capacity(4096, stdout);
                        let mut line = String::new();
                        while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                            let arc: Arc<str> = Arc::from(line.as_str());
                            sc.push_log(&bn, arc.clone());
                            let _ = cc.send(arc);
                            line.clear();
                        }
                    });
                }
                if let Some(stderr) = child.stderr.take() {
                    let sc = state_clone.clone();
                    let cc = channel_clone.clone();
                    let bn = bot_name.clone();
                    tokio::spawn(async move {
                        let mut reader = BufReader::with_capacity(4096, stderr);
                        let mut line = String::new();
                        while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                            let arc: Arc<str> = Arc::from(line.as_str());
                            sc.push_log(&bn, arc.clone());
                            let _ = cc.send(arc);
                            line.clear();
                        }
                    });
                }
                // Wait for completion
                let sc = state_clone;
                let cc = channel_clone;
                let bn = bot_name;
                tokio::spawn(async move {
                    match child.wait().await {
                        Ok(status) => {
                            let msg: Arc<str> = Arc::from(format!("Command exited with {}\n", status).as_str());
                            sc.push_log(&bn, msg.clone());
                            let _ = cc.send(msg);
                        }
                        Err(e) => {
                            let msg: Arc<str> = Arc::from(format!("Command error: {}\n", e).as_str());
                            sc.push_log(&bn, msg.clone());
                            let _ = cc.send(msg);
                        }
                    }
                });
            }
            Err(e) => {
                let msg: Arc<str> = Arc::from(format!("Failed to run command: {}\n", e).as_str());
                state_clone.push_log(&bot_name, msg.clone());
                let _ = channel_clone.send(msg);
            }
        }
    });
}

/// Run weekly package updates for all bot directories.
/// Called from the background scheduler in app.rs.
pub async fn run_weekly_package_updates(state: &AppState) {
    let bots_dir = &state.bots_dir;
    let entries = match std::fs::read_dir(bots_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let bot_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        let channel = state.get_or_create_channel(&bot_name);

        // Detect runtime from .adpanel.json
        let config_path = path.join(".adpanel.json");
        let runtime = if config_path.exists() {
            std::fs::read_to_string(&config_path)
                .ok()
                .and_then(|raw| serde_json::from_str::<crate::models::BotConfig>(&raw).ok())
                .map(|c| c.runtime)
                .unwrap_or_default()
        } else {
            String::new()
        };

        if runtime == "nodejs" || path.join("package.json").exists() {
            send_output(
                state,
                &channel,
                &bot_name,
                "[auto-update] Running npm install...\n",
            );
            run_package_update(state, &channel, &bot_name, &path, "npm", &["install"]).await;
        }

        if runtime == "python" || path.join("requirements.txt").exists() {
            // Use cached python command to derive pip command
            let pip_cmd = if &*state.python_cmd == "python3" { "pip3" } else { "pip" };
            send_output(
                state,
                &channel,
                &bot_name,
                "[auto-update] Running pip install -r requirements.txt...\n",
            );
            run_package_update(
                state,
                &channel,
                &bot_name,
                &path,
                pip_cmd,
                &["install", "-r", "requirements.txt"],
            )
            .await;
        }
    }
}

async fn run_package_update(
    state: &AppState,
    channel: &broadcast::Sender<Arc<str>>,
    bot: &str,
    cwd: &std::path::Path,
    program: &str,
    args: &[&str],
) {
    match Command::new(program)
        .args(args)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            if let Some(stdout) = child.stdout.take() {
                let sc = state.clone();
                let cc = channel.clone();
                let bn = bot.to_string();
                tokio::spawn(async move {
                    let mut reader = BufReader::with_capacity(4096, stdout);
                    let mut line = String::new();
                    while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                        let arc: Arc<str> = Arc::from(line.as_str());
                        sc.push_log(&bn, arc.clone());
                        let _ = cc.send(arc);
                        line.clear();
                    }
                });
            }
            if let Some(stderr) = child.stderr.take() {
                let sc = state.clone();
                let cc = channel.clone();
                let bn = bot.to_string();
                tokio::spawn(async move {
                    let mut reader = BufReader::with_capacity(4096, stderr);
                    let mut line = String::new();
                    while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                        let arc: Arc<str> = Arc::from(line.as_str());
                        sc.push_log(&bn, arc.clone());
                        let _ = cc.send(arc);
                        line.clear();
                    }
                });
            }
            match child.wait().await {
                Ok(status) => {
                    let msg: Arc<str> = Arc::from(format!("[auto-update] {} exited with {}\n", program, status).as_str());
                    state.push_log(bot, msg.clone());
                    let _ = channel.send(msg);
                }
                Err(e) => {
                    let msg: Arc<str> = Arc::from(format!("[auto-update] {} error: {}\n", program, e).as_str());
                    state.push_log(bot, msg.clone());
                    let _ = channel.send(msg);
                }
            }
        }
        Err(e) => {
            let msg: Arc<str> = Arc::from(format!("[auto-update] Failed to run {}: {}\n", program, e).as_str());
            state.push_log(bot, msg.clone());
            let _ = channel.send(msg);
        }
    }
}
