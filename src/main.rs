mod app;
mod models;
mod routes;
mod ws;

use app::AppState;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

#[tokio::main(worker_threads = 2)]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "adpanel=info,tower_http=info".into()),
        )
        .init();

    dotenv::dotenv().ok();

    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("serve");

    let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    match command {
        "serve" | "start" => start_server(base_dir).await,
        "init" => cli_init(base_dir),
        "create-user" => cli_create_user(base_dir),
        "change-password" => cli_change_password(base_dir),
        "delete-user" => cli_delete_user(base_dir),
        "hash-password" => {
            // Used by initialize.sh
            if let Some(pw) = args.get(2) {
                match bcrypt::hash(pw, 10) {
                    Ok(h) => println!("{}", h),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("Usage: adpanel hash-password <password>");
                std::process::exit(1);
            }
        }
        "verify-password" => {
            // Used by initialize.sh
            if let (Some(pw), Some(hash)) = (args.get(2), args.get(3)) {
                match bcrypt::verify(pw, hash) {
                    Ok(true) => println!("true"),
                    _ => println!("false"),
                }
            } else {
                eprintln!("Usage: adpanel verify-password <password> <hash>");
                std::process::exit(1);
            }
        }
        "gen-totp" => {
            let totp = totp_rs::TOTP::new(
                totp_rs::Algorithm::SHA1,
                6,
                1,
                30,
                totp_rs::Secret::generate_secret().to_bytes().unwrap(),
                Some("ADPanel".to_string()),
                "user".to_string(),
            )
            .unwrap();
            let secret = totp_rs::Secret::Raw(totp.secret.clone())
                .to_encoded()
                .to_string();
            println!("{}", secret);
        }
        "gen-qr" => {
            // Print TOTP OTPAuth URL for external QR generation
            if let (Some(secret), Some(email)) = (args.get(2), args.get(3)) {
                let url = format!(
                    "otpauth://totp/ADPanel:{}?secret={}&issuer=ADPanel",
                    email, secret
                );
                println!("{}", url);
            } else {
                eprintln!("Usage: adpanel gen-qr <secret> <email>");
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("ADPanel - Rust Edition");
            eprintln!();
            eprintln!("Usage: adpanel <command>");
            eprintln!();
            eprintln!("Commands:");
            eprintln!("  serve             Start the web server (default)");
            eprintln!("  init              Initialize panel (create admin user)");
            eprintln!("  create-user       Create a new user");
            eprintln!("  change-password   Change admin password");
            eprintln!("  delete-user       Delete admin user");
            eprintln!("  hash-password     Hash a password (for scripts)");
            eprintln!("  verify-password   Verify password against hash");
            eprintln!("  gen-totp          Generate TOTP secret");
            eprintln!("  gen-qr            Generate OTPAuth URL");
            std::process::exit(1);
        }
    }
}

async fn start_server(base_dir: PathBuf) {
    let https_enabled = std::env::var("HTTPS_ENABLED")
        .map(|v| v == "true")
        .unwrap_or(false);
    let http_port: u16 = std::env::var("HTTP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3000);
    let https_port: u16 = std::env::var("HTTPS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(443);

    let state = AppState::new(base_dir.clone(), https_enabled);
    let router = routes::create_router(state);

    if https_enabled {
        let ssl_key = std::env::var("SSL_KEY_PATH")
            .unwrap_or_else(|_| base_dir.join("ssl/privkey.pem").to_string_lossy().to_string());
        let ssl_cert = std::env::var("SSL_CERT_PATH")
            .unwrap_or_else(|_| base_dir.join("ssl/fullchain.pem").to_string_lossy().to_string());

        if std::path::Path::new(&ssl_key).exists() && std::path::Path::new(&ssl_cert).exists() {
            tracing::info!(
                "ADPanel running on https://localhost:{} (HTTP redirect on {})",
                https_port,
                http_port
            );

            // Start HTTP redirect server
            let redirect_router = axum::Router::new().fallback(move |req: axum::http::Request<axum::body::Body>| async move {
                let host = req
                    .headers()
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("localhost");
                let host = host.split(':').next().unwrap_or(host);
                let port_suffix = if https_port != 443 {
                    format!(":{}", https_port)
                } else {
                    String::new()
                };
                let target = format!("https://{}{}{}", host, port_suffix, req.uri().path());
                axum::response::Redirect::permanent(&target)
            });

            let http_addr = SocketAddr::from(([0, 0, 0, 0], http_port));
            tokio::spawn(async move {
                let listener = tokio::net::TcpListener::bind(http_addr).await.unwrap();
                axum::serve(listener, redirect_router.into_make_service_with_connect_info::<SocketAddr>())
                    .await
                    .ok();
            });

            // Start HTTPS server
            let tls_config = load_tls_config(&ssl_cert, &ssl_key);
            let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls_config));
            let addr = SocketAddr::from(([0, 0, 0, 0], https_port));
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

            loop {
                let (stream, _remote_addr) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let router = router.clone();
                tokio::spawn(async move {
                    if let Ok(tls_stream) = acceptor.accept(stream).await {
                        let io = hyper_util::rt::TokioIo::new(tls_stream);
                        let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                            let router = router.clone();
                            async move {
                                let (parts, body) = req.into_parts();
                                let body = axum::body::Body::new(body);
                                let req = axum::http::Request::from_parts(parts, body);
                                let resp = tower::ServiceExt::oneshot(router, req)
                                    .await
                                    .unwrap_or_else(|e| match e {});
                                Ok::<_, std::convert::Infallible>(resp)
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service)
                            .await;
                    }
                });
            }
        } else {
            tracing::warn!("[HTTPS] SSL files not found, falling back to HTTP");
            start_http(router, http_port).await;
        }
    } else {
        start_http(router, http_port).await;
    }
}

async fn start_http(router: axum::Router, port: u16) {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("ADPanel running on http://localhost:{}", port);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

fn load_tls_config(cert_path: &str, key_path: &str) -> rustls::ServerConfig {
    let cert_file = fs::read(cert_path).expect("Failed to read SSL cert");
    let key_file = fs::read(key_path).expect("Failed to read SSL key");

    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_file[..])
        .filter_map(|r| r.ok())
        .collect();
    let key = rustls_pemfile::private_key(&mut &key_file[..])
        .expect("Failed to parse private key")
        .expect("No private key found");

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Invalid TLS configuration")
}

// --- CLI commands ---

fn cli_init(base_dir: PathBuf) {
    let users_file = base_dir.join("user.json");

    println!("\x1b[35m==============================\x1b[0m");
    println!("\x1b[36m Welcome to ADPanel Initializer \x1b[0m");
    println!("\x1b[35m==============================\x1b[0m");

    let email = prompt("Enter admin email: ");
    let password = prompt_password("Enter admin password: ");

    // Generate TOTP secret
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::generate_secret().to_bytes().unwrap(),
        Some("ADPanel".to_string()),
        email.clone(),
    )
    .unwrap();
    let secret = totp_rs::Secret::Raw(totp.secret.clone())
        .to_encoded()
        .to_string();

    println!("\x1b[33mYour 2FA secret (manual entry):\x1b[0m {}", secret);
    let url = format!(
        "otpauth://totp/ADPanel:{}?secret={}&issuer=ADPanel",
        email, secret
    );
    println!("\x1b[36mOTPAuth URL (for QR generator):\x1b[0m {}", url);

    let hash = bcrypt::hash(&password, 10).expect("Failed to hash password");

    let user = models::User {
        email: email.clone(),
        password: hash,
        secret,
        admin: true,
    };

    let users = vec![user];
    let json = serde_json::to_string_pretty(&users).unwrap();
    fs::write(&users_file, &json).expect("Failed to write user.json");

    println!("\x1b[32mAdmin account created and saved in user.json\x1b[0m");
    println!("\x1b[33mPanel setup complete!\x1b[0m");
}

fn cli_create_user(base_dir: PathBuf) {
    let users_file = base_dir.join("user.json");

    println!("\x1b[36m=== Create New User ===\x1b[0m");

    let email = prompt("Enter user email: ");
    let password = prompt_password("Enter user password: ");
    let confirm = prompt_password("Confirm user password: ");

    if password != confirm {
        eprintln!("\x1b[31mPasswords do not match.\x1b[0m");
        std::process::exit(1);
    }

    let is_admin = prompt("Should this user be an admin? (y/n): ")
        .trim()
        .to_lowercase()
        .starts_with('y');

    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::generate_secret().to_bytes().unwrap(),
        Some("ADPanel".to_string()),
        email.clone(),
    )
    .unwrap();
    let secret = totp_rs::Secret::Raw(totp.secret.clone())
        .to_encoded()
        .to_string();

    println!("\x1b[33mYour 2FA secret:\x1b[0m {}", secret);
    let url = format!(
        "otpauth://totp/ADPanel:{}?secret={}&issuer=ADPanel",
        email, secret
    );
    println!("\x1b[36mOTPAuth URL:\x1b[0m {}", url);

    let hash = bcrypt::hash(&password, 10).expect("Failed to hash password");

    let mut users: Vec<models::User> = if users_file.exists() {
        let raw = fs::read_to_string(&users_file).unwrap_or_default();
        serde_json::from_str(&raw).unwrap_or_default()
    } else {
        vec![]
    };

    users.push(models::User {
        email,
        password: hash,
        secret,
        admin: is_admin,
    });

    let json = serde_json::to_string_pretty(&users).unwrap();
    fs::write(&users_file, &json).expect("Failed to write user.json");

    println!("\x1b[32mUser created successfully!\x1b[0m");
}

fn cli_change_password(base_dir: PathBuf) {
    let users_file = base_dir.join("user.json");

    if !users_file.exists() {
        eprintln!("\x1b[31mAdmin user not found! Initialize the panel first.\x1b[0m");
        std::process::exit(1);
    }

    let mut users: Vec<models::User> =
        serde_json::from_str(&fs::read_to_string(&users_file).unwrap()).unwrap();

    let mut attempts = 3;
    loop {
        let current = prompt_password("Enter current password: ");
        if bcrypt::verify(&current, &users[0].password).unwrap_or(false) {
            break;
        }
        attempts -= 1;
        eprintln!(
            "\x1b[31mIncorrect password. Remaining attempts: {}\x1b[0m",
            attempts
        );
        if attempts == 0 {
            eprintln!("\x1b[31mToo many failed attempts. Exiting.\x1b[0m");
            std::process::exit(1);
        }
    }

    let new_pw = prompt_password("Enter new password: ");
    let confirm = prompt_password("Confirm new password: ");
    if new_pw != confirm {
        eprintln!("\x1b[31mPasswords do not match.\x1b[0m");
        std::process::exit(1);
    }

    users[0].password = bcrypt::hash(&new_pw, 10).expect("Failed to hash");
    let json = serde_json::to_string_pretty(&users).unwrap();
    fs::write(&users_file, &json).expect("Failed to save");

    println!("\x1b[32mPassword changed successfully!\x1b[0m");
}

fn cli_delete_user(base_dir: PathBuf) {
    let users_file = base_dir.join("user.json");

    if !users_file.exists() {
        eprintln!("\x1b[31mNo admin user found to delete.\x1b[0m");
        std::process::exit(1);
    }

    let users: Vec<models::User> =
        serde_json::from_str(&fs::read_to_string(&users_file).unwrap()).unwrap();

    let mut attempts = 3;
    loop {
        let current = prompt_password("Enter current password to confirm deletion: ");
        if bcrypt::verify(&current, &users[0].password).unwrap_or(false) {
            fs::remove_file(&users_file).ok();
            println!("\x1b[32mAdmin user deleted successfully!\x1b[0m");
            return;
        }
        attempts -= 1;
        eprintln!(
            "\x1b[31mIncorrect password. Remaining attempts: {}\x1b[0m",
            attempts
        );
        if attempts == 0 {
            eprintln!("\x1b[31mToo many failed attempts. Exiting.\x1b[0m");
            std::process::exit(1);
        }
    }
}

fn prompt(msg: &str) -> String {
    use std::io::Write;
    print!("{}", msg);
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    input.trim().to_string()
}

fn prompt_password(msg: &str) -> String {
    use std::io::Write;
    print!("{}", msg);
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    input.trim().to_string()
}
