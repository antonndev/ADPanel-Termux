use crate::app::AppState;
use axum::{
    body::Body,
    extract::{
        ConnectInfo, DefaultBodyLimit, Multipart, Path as AxumPath, Query, State, WebSocketUpgrade,
    },
    http::{header, HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tera::Context;
use tower_http::services::ServeDir;

const SESSION_COOKIE: &str = "adpanel_sid";
const SESSION_PREFIX: &str = "adpanel_sid=";
const MAX_UPLOAD_SIZE: usize = 100 * 1024 * 1024;

fn chrono_year() -> i32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    // Approximate year calculation
    (1970 + secs / 31_557_600) as i32
}

pub fn create_router(state: AppState) -> Router {
    let public_dir = state.public_dir.clone();

    let api_routes = Router::new()
        // Auth routes (no auth required)
        .route("/login", get(login_page).post(login_handler))
        .route("/forgot-password", get(forgot_password_page).post(forgot_password_handler))
        .route("/register", get(register_page).post(register_handler))
        .route("/logout", post(logout_handler))
        // Protected routes
        .route("/", get(dashboard_page))
        .route("/settings", get(settings_page))
        .route("/bot/{bot}", get(bot_page))
        .route("/explore/{bot}", get(explore_handler))
        .route("/create", post(create_handler))
        .route("/rename", post(rename_handler))
        .route("/upload", post(upload_handler))
        .route("/extract", post(extract_handler))
        .route("/create-server", post(create_server_handler))
        .route("/api/update-all-packages", post(update_all_packages_handler))
        .route("/api/usercount", get(usercount_handler))
        .route("/api/my-servers", get(my_servers_handler))
        .route("/api/settings/servers", get(list_servers_handler).post(create_server_folder_handler))
        .route("/api/settings/servers/{name}", delete(delete_server_handler))
        .route("/api/settings/background", post(background_handler))
        .route("/api/settings/change-password", post(change_password_handler))
        .route("/api/settings/accounts", get(accounts_handler))
        .route("/api/settings/accounts/{email}/add", post(add_access_handler))
        .route("/api/settings/accounts/{email}/remove", post(remove_access_handler))
        // WebSocket for bot console
        .route("/ws/{bot}", get(ws_handler))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_SIZE))
        .layer(middleware::from_fn_with_state(state.clone(), security_headers_middleware))
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit_middleware))
        .with_state(state);

    Router::new()
        .merge(api_routes)
        .fallback_service(ServeDir::new(public_dir))
}

// --- Middleware ---

async fn security_headers_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    use axum::http::HeaderValue;
    static NOSNIFF: HeaderValue = HeaderValue::from_static("nosniff");
    static DENY: HeaderValue = HeaderValue::from_static("DENY");
    static XSS: HeaderValue = HeaderValue::from_static("1; mode=block");
    static REFERRER: HeaderValue = HeaderValue::from_static("strict-origin-when-cross-origin");
    static PERMISSIONS: HeaderValue = HeaderValue::from_static("camera=(), microphone=(), geolocation=()");
    static HSTS: HeaderValue = HeaderValue::from_static("max-age=31536000; includeSubDomains");

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("X-Content-Type-Options", NOSNIFF.clone());
    headers.insert("X-Frame-Options", DENY.clone());
    headers.insert("X-XSS-Protection", XSS.clone());
    headers.insert("Referrer-Policy", REFERRER.clone());
    headers.insert("Permissions-Policy", PERMISSIONS.clone());
    if state.https_enabled {
        headers.insert("Strict-Transport-Security", HSTS.clone());
    }
    headers.remove("X-Powered-By");
    response
}

async fn rate_limit_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| addr.ip().to_string());

    if let Err(retry_after) = state.check_rate_limit(&ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry_after.to_string())],
            "429 Too Many Requests - Access temporarily blocked by rate limiter.",
        )
            .into_response();
    }

    next.run(request).await
}

// --- Helper functions ---

fn get_session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|c| {
                let c = c.trim();
                if c.starts_with(SESSION_PREFIX) {
                    Some(c[SESSION_PREFIX.len()..].to_string())
                } else {
                    None
                }
            })
        })
}

fn set_session_cookie(sid: &str, https: bool) -> String {
    let secure = if https { "; Secure" } else { "" };
    format!(
        "{}={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000{}",
        SESSION_COOKIE, sid, secure
    )
}

fn clear_session_cookie() -> String {
    format!(
        "{}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        SESSION_COOKIE
    )
}

fn get_client_ip(headers: &HeaderMap, addr: &SocketAddr) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| addr.ip().to_string())
}

fn render_template(state: &AppState, name: &str, ctx: &Context) -> Response {
    match state.templates.render(name, ctx) {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

fn require_auth(state: &AppState, headers: &HeaderMap) -> Result<String, Response> {
    let sid = get_session_id(headers).ok_or_else(|| Redirect::to("/login").into_response())?;
    if !state.is_authenticated(&sid) {
        return Err(Redirect::to("/login").into_response());
    }
    Ok(sid)
}

fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<String, Response> {
    let sid = require_auth(state, headers)?;
    if !state.is_admin(&sid) {
        return Err(Redirect::to("/").into_response());
    }
    Ok(sid)
}

fn require_auth_api(state: &AppState, headers: &HeaderMap) -> Result<String, Response> {
    let sid = get_session_id(headers)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(json!({"error": "not authenticated"}))).into_response())?;
    if !state.is_authenticated(&sid) {
        return Err(
            (StatusCode::UNAUTHORIZED, Json(json!({"error": "not authenticated"}))).into_response(),
        );
    }
    Ok(sid)
}

fn require_admin_api(state: &AppState, headers: &HeaderMap) -> Result<String, Response> {
    let sid = require_auth_api(state, headers)?;
    if !state.is_admin(&sid) {
        return Err(
            (StatusCode::FORBIDDEN, Json(json!({"error": "not authorized"}))).into_response(),
        );
    }
    Ok(sid)
}

// --- Auth Routes ---

async fn login_page(State(state): State<AppState>) -> Response {
    let ctx = Context::new();
    render_template(&state, "login.html", &ctx)
}

#[derive(Deserialize)]
struct LoginForm {
    email: String,
    password: String,
    code: String,
}

async fn login_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::Form(form): axum::Form<LoginForm>,
) -> Response {
    let ip = get_client_ip(&headers, &addr);

    if let Err(retry) = state.check_login_brute_force(&ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            format!("Too many failed attempts. Try again in {} seconds.", retry),
        )
            .into_response();
    }

    let user = match state.find_user_by_email(&form.email) {
        Some(u) => u,
        None => {
            state.record_failed_login(&ip);
            return (StatusCode::BAD_REQUEST, "Email or password incorrect.").into_response();
        }
    };

    if !bcrypt::verify(&form.password, &user.password).unwrap_or(false) {
        state.record_failed_login(&ip);
        return (StatusCode::BAD_REQUEST, "Email or password incorrect.").into_response();
    }

    // Verify TOTP
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::Encoded(user.secret.clone()).to_bytes().unwrap_or_default(),
        Some("ADPanel".to_string()),
        user.email.clone(),
    )
    .unwrap();

    if !totp.check_current(&form.code).unwrap_or(false) {
        state.record_failed_login(&ip);
        return (StatusCode::BAD_REQUEST, "Email or password incorrect.").into_response();
    }

    state.clear_failed_logins(&ip);

    // Create new session
    let sid = state.create_session();
    state.set_session_user(&sid, &user.email);

    let cookie = set_session_cookie(&sid, state.https_enabled);
    ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
}

async fn register_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let sid = get_session_id(&headers).unwrap_or_else(|| state.create_session());

    let secret = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::generate_secret().to_bytes().unwrap(),
        Some("ADPanel".to_string()),
        "user".to_string(),
    )
    .unwrap();

    let base32_secret = totp_rs::Secret::Raw(secret.secret.clone())
        .to_encoded()
        .to_string();
    state.set_session_secret(&sid, &base32_secret);

    let mut ctx = Context::new();
    ctx.insert("secret", &base32_secret);

    let cookie = set_session_cookie(&sid, state.https_enabled);
    let html = state.templates.render("register.html", &ctx).unwrap_or_default();
    ([(header::SET_COOKIE, cookie)], Html(html)).into_response()
}

#[derive(Deserialize)]
struct RegisterForm {
    email: String,
    password: String,
    code: String,
}

async fn register_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<RegisterForm>,
) -> Response {
    let sid = match get_session_id(&headers) {
        Some(s) => s,
        None => return (StatusCode::BAD_REQUEST, "Session required.").into_response(),
    };

    let session = match state.get_session(&sid) {
        Some(s) => s,
        None => return (StatusCode::BAD_REQUEST, "Session expired.").into_response(),
    };

    let secret = match session.totp_secret {
        Some(s) => s,
        None => return (StatusCode::BAD_REQUEST, "No 2FA secret in session.").into_response(),
    };

    if form.email.is_empty() || form.password.is_empty() || form.code.is_empty() {
        return (StatusCode::BAD_REQUEST, "Complete all boxes.").into_response();
    }

    if state.find_user_by_email(&form.email).is_some() {
        return Redirect::to("/login").into_response();
    }

    // Verify TOTP
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::Encoded(secret.clone()).to_bytes().unwrap_or_default(),
        Some("ADPanel".to_string()),
        form.email.clone(),
    )
    .unwrap();

    if !totp.check_current(&form.code).unwrap_or(false) {
        return (StatusCode::BAD_REQUEST, "Invalid 2FA code.").into_response();
    }

    let hashed = bcrypt::hash(&form.password, 10).unwrap_or_default();
    let users = state.load_users();
    let is_first = users.is_empty();
    let new_user = crate::models::User {
        email: form.email,
        password: hashed,
        secret,
        admin: is_first,
    };

    let mut all_users = users;
    all_users.push(new_user);
    state.save_users(&all_users);

    // Clear session secret
    if let Some(mut s) = state.sessions.get_mut(&sid) {
        s.totp_secret = None;
    }

    Redirect::to("/login").into_response()
}

async fn forgot_password_page(State(state): State<AppState>) -> Response {
    let ctx = Context::new();
    render_template(&state, "forgot_password.html", &ctx)
}

#[derive(Deserialize)]
struct ForgotPasswordForm {
    email: String,
    #[serde(rename = "newPassword")]
    new_password: String,
    code: String,
}

async fn forgot_password_handler(
    State(state): State<AppState>,
    axum::Form(form): axum::Form<ForgotPasswordForm>,
) -> Response {
    let mut user = match state.find_user_by_email(&form.email) {
        Some(u) => u,
        None => {
            let mut ctx = Context::new();
            ctx.insert("error", "Email not found.");
            return render_template(&state, "forgot_password.html", &ctx);
        }
    };

    if form.new_password.len() < 8 {
        let mut ctx = Context::new();
        ctx.insert("error", "New password must be at least 8 characters.");
        return render_template(&state, "forgot_password.html", &ctx);
    }

    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::Encoded(user.secret.clone()).to_bytes().unwrap_or_default(),
        Some("ADPanel".to_string()),
        user.email.clone(),
    )
    .unwrap();

    if !totp.check_current(&form.code).unwrap_or(false) {
        let mut ctx = Context::new();
        ctx.insert("error", "Invalid 2FA code.");
        return render_template(&state, "forgot_password.html", &ctx);
    }

    user.password = bcrypt::hash(&form.new_password, 10).unwrap_or_default();
    state.update_user(&user);
    let mut ctx = Context::new();
    ctx.insert("success", "Password has been reset. Please log in with the new password.");
    render_template(&state, "forgot_password.html", &ctx)
}

async fn logout_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(sid) = get_session_id(&headers) {
        state.destroy_session(&sid);
    }
    let cookie = clear_session_cookie();
    ([(header::SET_COOKIE, cookie)], Json(json!({"success": true}))).into_response()
}

// --- Dashboard ---

async fn dashboard_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let sid = match require_auth(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };

    let email = state.session_email(&sid).unwrap_or_default();
    let user = state.find_user_by_email(&email);
    let is_admin = user.as_ref().map(|u| u.admin).unwrap_or(false);

    let all_bots = list_bot_dirs(&state.bots_dir);
    let bots = if is_admin {
        all_bots
    } else {
        let access = state.get_access_for_email(&email);
        if access.iter().any(|s| s == "all") {
            all_bots
        } else {
            all_bots
                .into_iter()
                .filter(|b| access.contains(b))
                .collect()
        }
    };

    // Pass the Unix timestamp (ms) of when the server started, matching original Node.js behavior
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let elapsed_ms = state.server_start.elapsed().as_millis() as u64;
    let start_timestamp_ms = now_ms.saturating_sub(elapsed_ms);

    let mut ctx = Context::new();
    ctx.insert("bots", &bots);
    ctx.insert("isAdmin", &is_admin);
    ctx.insert("email", &email);
    ctx.insert("serverStartTime", &start_timestamp_ms);
    ctx.insert("bot_count", &bots.len());
    ctx.insert("year", &chrono_year());

    render_template(&state, "dashboard.html", &ctx)
}

// --- Settings ---

async fn settings_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let sid = match require_admin(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let email = state.session_email(&sid).unwrap_or_default();
    let mut ctx = Context::new();
    ctx.insert("email", &email);
    render_template(&state, "settings.html", &ctx)
}

// --- Bot page ---

async fn bot_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(bot): AxumPath<String>,
) -> Response {
    let sid = match require_auth(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };

    let bot_name = match state.sanitize_bot_name(&bot) {
        Some(n) => n,
        None => return Redirect::to("/").into_response(),
    };

    let email = state.session_email(&sid).unwrap_or_default();
    if !state.is_admin(&sid) && !state.user_has_access(&email, &bot_name) {
        return Redirect::to("/").into_response();
    }

    let bot_dir = state.bots_dir.join(&bot_name);
    if !bot_dir.exists() {
        return Redirect::to("/").into_response();
    }

    let mut ctx = Context::new();
    ctx.insert("bot", &bot_name);

    // Read runtime from .adpanel.json for package management UI
    let config_path = bot_dir.join(".adpanel.json");
    let runtime = if config_path.exists() {
        std::fs::read_to_string(&config_path)
            .ok()
            .and_then(|raw| serde_json::from_str::<crate::models::BotConfig>(&raw).ok())
            .map(|c| c.runtime)
            .unwrap_or_else(|| "nodejs".to_string())
    } else {
        "nodejs".to_string()
    };
    ctx.insert("runtime", &runtime);

    render_template(&state, "bot.html", &ctx)
}

// --- File Explorer ---

#[derive(Deserialize)]
struct ExploreQuery {
    path: Option<String>,
}

#[derive(Serialize)]
struct ExploreEntry {
    name: String,
    #[serde(rename = "isDir")]
    is_dir: bool,
}

async fn explore_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(bot): AxumPath<String>,
    Query(query): Query<ExploreQuery>,
) -> Response {
    let sid = match require_auth_api(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };

    let bot_name = match state.sanitize_bot_name(&bot) {
        Some(n) => n,
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid bot name"}))).into_response(),
    };

    let email = state.session_email(&sid).unwrap_or_default();
    if !state.is_admin(&sid) && !state.user_has_access(&email, &bot_name) {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "Access denied"}))).into_response();
    }

    let rel = query.path.unwrap_or_default();
    let dir = state.bots_dir.join(&bot_name).join(&rel);

    if !dir.exists() {
        return Json(json!({"error": "No such dir"})).into_response();
    }

    let entries: Vec<ExploreEntry> = match fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| ExploreEntry {
                name: e.file_name().to_string_lossy().to_string(),
                is_dir: e.file_type().map(|ft| ft.is_dir()).unwrap_or(false),
            })
            .collect(),
        Err(_) => vec![],
    };

    Json(json!({"path": rel, "entries": entries})).into_response()
}

// --- File operations ---

#[derive(Deserialize)]
struct CreateForm {
    bot: String,
    r#type: String,
    name: String,
    path: Option<String>,
}

async fn create_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(form): axum::Json<CreateForm>,
) -> Response {
    let sid = match require_auth_api(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };

    let bot_name = match state.sanitize_bot_name(&form.bot) {
        Some(n) => n,
        None => return (StatusCode::BAD_REQUEST, "Invalid bot name").into_response(),
    };

    let email = state.session_email(&sid).unwrap_or_default();
    if !state.is_admin(&sid) && !state.user_has_access(&email, &bot_name) {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    let safe_name = match state.sanitize_filename(&form.name) {
        Some(n) => n,
        None => return (StatusCode::BAD_REQUEST, "Invalid name").into_response(),
    };

    let rel_path = form.path.as_deref().unwrap_or("");
    let dest_dir = state.bots_dir.join(&bot_name).join(rel_path);
    fs::create_dir_all(&dest_dir).ok();

    if form.r#type == "folder" {
        let folder = dest_dir.join(&safe_name);
        fs::create_dir_all(&folder).ok();
        "Folder created".into_response()
    } else if form.r#type == "file" {
        let file = dest_dir.join(&safe_name);
        if !file.exists() {
            fs::write(&file, "").ok();
        }
        "File created".into_response()
    } else {
        (StatusCode::BAD_REQUEST, "Invalid type").into_response()
    }
}

#[derive(Deserialize)]
struct RenameForm {
    bot: String,
    #[serde(rename = "oldPath")]
    old_path: String,
    #[serde(rename = "newName")]
    new_name: String,
}

async fn rename_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(form): axum::Json<RenameForm>,
) -> Response {
    let sid = match require_auth_api(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };

    let bot_name = match state.sanitize_bot_name(&form.bot) {
        Some(n) => n,
        None => return (StatusCode::BAD_REQUEST, "Invalid bot name").into_response(),
    };

    let email = state.session_email(&sid).unwrap_or_default();
    if !state.is_admin(&sid) && !state.user_has_access(&email, &bot_name) {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    let safe_name = match state.sanitize_filename(&form.new_name) {
        Some(n) => n,
        None => return (StatusCode::BAD_REQUEST, "Invalid new name").into_response(),
    };

    let old_full = state.bots_dir.join(&bot_name).join(&form.old_path);
    if !old_full.exists() {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }

    let parent = old_full.parent().unwrap_or(&state.bots_dir);
    let new_full = parent.join(&safe_name);

    match fs::rename(&old_full, &new_full) {
        Ok(_) => "Renamed".into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Rename failed").into_response(),
    }
}

// --- Upload ---

async fn upload_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let sid = match require_auth_api(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };

    let mut bot_field = String::new();
    let mut path_field = String::new();
    let mut file_data: Option<(String, Vec<u8>)> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "bot" => bot_field = field.text().await.unwrap_or_default(),
            "path" => path_field = field.text().await.unwrap_or_default(),
            "file" => {
                let filename = field.file_name().unwrap_or("upload").to_string();
                let data = field.bytes().await.unwrap_or_default().to_vec();
                file_data = Some((filename, data));
            }
            _ => {}
        }
    }

    let (filename, data) = match file_data {
        Some(f) => f,
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "No file uploaded"}))).into_response(),
    };

    // Upload to specific bot folder
    if !bot_field.is_empty() {
        let bot_name = match state.sanitize_bot_name(&bot_field) {
            Some(n) => n,
            None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid bot name"}))).into_response(),
        };

        let email = state.session_email(&sid).unwrap_or_default();
        if !state.is_admin(&sid) && !state.user_has_access(&email, &bot_name) {
            return (StatusCode::FORBIDDEN, Json(json!({"error": "Access denied"}))).into_response();
        }

        let safe_filename = match state.sanitize_filename(&filename) {
            Some(n) => n,
            None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid filename"}))).into_response(),
        };

        let target_dir = state.bots_dir.join(&bot_name).join(&path_field);
        fs::create_dir_all(&target_dir).ok();
        let dest = target_dir.join(&safe_filename);
        return match fs::write(&dest, &data) {
            Ok(_) => Json(json!({"ok": true, "msg": "Uploaded to bot folder"})).into_response(),
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Failed to write file"}))).into_response(),
        };
    }

    // Archive upload and extract
    let lower = filename.to_lowercase();
    let base_name = if lower.ends_with(".tar.gz") {
        &filename[..filename.len() - 7]
    } else if lower.ends_with(".tgz") {
        &filename[..filename.len() - 4]
    } else if let Some(dot) = filename.rfind('.') {
        &filename[..dot]
    } else {
        &filename
    };

    let folder_name: String = base_name
        .trim()
        .replace(char::is_whitespace, "-")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();
    let folder_name = if folder_name.is_empty() {
        format!("uploaded-{}", crate::app::current_time_ms())
    } else {
        folder_name
    };

    let mut final_folder = folder_name.clone();
    let mut counter = 0;
    while state.bots_dir.join(&final_folder).exists() {
        counter += 1;
        final_folder = format!("{}-{}", folder_name, counter);
        if counter > 9999 {
            break;
        }
    }

    let dest_dir = state.bots_dir.join(&final_folder);
    fs::create_dir_all(&dest_dir).ok();

    // Write temp file
    let temp_path = state.uploads_dir.join(format!("tmp-{}", uuid::Uuid::new_v4()));
    if fs::write(&temp_path, &data).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Failed to save temp file"}))).into_response();
    }

    let result = extract_archive(&temp_path, &dest_dir, &lower).await;
    fs::remove_file(&temp_path).ok();

    match result {
        Ok(_) => Json(json!({"ok": true, "folder": final_folder})).into_response(),
        Err(e) => {
            fs::remove_dir_all(&dest_dir).ok();
            (StatusCode::BAD_REQUEST, Json(json!({"error": format!("Upload failed: {}", e)}))).into_response()
        }
    }
}

async fn extract_archive(file_path: &Path, dest: &Path, lower_name: &str) -> Result<(), String> {
    if lower_name.ends_with(".zip") {
        extract_zip(file_path, dest)
    } else if lower_name.ends_with(".tar.gz") || lower_name.ends_with(".tgz") || lower_name.ends_with(".tar") {
        extract_tar(file_path, dest)
    } else {
        Err("Unsupported archive type. Supported: .zip, .tar.gz, .tgz, .tar".to_string())
    }
}

fn extract_zip(file_path: &Path, dest: &Path) -> Result<(), String> {
    let file = fs::File::open(file_path).map_err(|e| e.to_string())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| e.to_string())?;
        let name = entry.name().to_string();
        if name.contains("..") || Path::new(&name).is_absolute() {
            continue;
        }
        let out_path = dest.join(&name);
        if !out_path.starts_with(dest) {
            continue;
        }
        if entry.is_dir() {
            fs::create_dir_all(&out_path).ok();
        } else {
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).ok();
            }
            let mut outfile = fs::File::create(&out_path).map_err(|e| e.to_string())?;
            std::io::copy(&mut entry, &mut outfile).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn extract_tar(file_path: &Path, dest: &Path) -> Result<(), String> {
    let file = fs::File::open(file_path).map_err(|e| e.to_string())?;
    let lower = file_path.to_string_lossy().to_lowercase();

    let mut archive = if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        let decoder = flate2::read::GzDecoder::new(file);
        tar::Archive::new(Box::new(decoder) as Box<dyn std::io::Read>)
    } else {
        tar::Archive::new(Box::new(file) as Box<dyn std::io::Read>)
    };

    for entry in archive.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path().map_err(|e| e.to_string())?;
        let path_str = path.to_string_lossy();
        if path_str.contains("..") || path.is_absolute() {
            continue;
        }
        let out_path = dest.join(&*path);
        if !out_path.starts_with(dest) {
            continue;
        }
        entry.unpack(&out_path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[derive(Deserialize)]
struct ExtractForm {
    bot: String,
    path: String,
}

async fn extract_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(form): axum::Json<ExtractForm>,
) -> Response {
    let sid = match require_auth_api(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };

    let bot_name = match state.sanitize_bot_name(&form.bot) {
        Some(n) => n,
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid bot name"}))).into_response(),
    };

    let email = state.session_email(&sid).unwrap_or_default();
    if !state.is_admin(&sid) && !state.user_has_access(&email, &bot_name) {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "Access denied"}))).into_response();
    }

    let file_path = state.bots_dir.join(&bot_name).join(&form.path);
    if !file_path.exists() || !file_path.is_file() {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "File not found"}))).into_response();
    }

    let dest = file_path.parent().unwrap_or(&state.bots_dir);
    let lower = file_path.to_string_lossy().to_lowercase();

    match extract_archive(&file_path, dest, &lower).await {
        Ok(_) => Json(json!({"ok": true, "msg": "Extracted successfully"})).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("Extraction failed: {}", e)}))).into_response(),
    }
}

// --- Create Server ---

#[derive(Deserialize)]
struct CreateServerForm {
    name: String,
    port: u16,
    #[serde(default = "default_runtime_form")]
    runtime: String,
    #[serde(default)]
    runtime_version: String,
}

fn default_runtime_form() -> String {
    "nodejs".to_string()
}

async fn create_server_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(form): axum::Json<CreateServerForm>,
) -> Response {
    let _sid = match require_admin_api(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };

    let safe_name = form.name.trim().to_string();
    if safe_name.is_empty()
        || safe_name.len() > 40
        || !safe_name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == ' ')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid name. Use letters, numbers, dashes, underscores (max 40)."})),
        )
            .into_response();
    }

    if form.port < 1024 || form.port > 65535 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Port must be between 1024 and 65535."})),
        )
            .into_response();
    }

    // Validate runtime
    let runtime = form.runtime.trim().to_lowercase();
    if runtime != "nodejs" && runtime != "python" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid runtime. Choose 'nodejs' or 'python'."})),
        )
            .into_response();
    }

    // Validate runtime_version format (alphanumeric, dots, 'v' prefix allowed, max 20 chars)
    let runtime_version = form.runtime_version.trim().to_string();
    if !runtime_version.is_empty()
        && (runtime_version.len() > 20
            || !runtime_version
                .chars()
                .all(|c| c.is_alphanumeric() || c == '.' || c == '-'))
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid runtime version format."})),
        )
            .into_response();
    }

    let folder_name = safe_name.replace(char::is_whitespace, "-");
    let server_dir = state.bots_dir.join(&folder_name);

    if server_dir.exists() {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "A server with this name already exists."})),
        )
            .into_response();
    }

    // Check port conflict
    if let Ok(entries) = fs::read_dir(&state.bots_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let cfg_path = entry.path().join(".adpanel.json");
            if cfg_path.exists() {
                if let Ok(raw) = fs::read_to_string(&cfg_path) {
                    if let Ok(cfg) = serde_json::from_str::<crate::models::BotConfig>(&raw) {
                        if cfg.port == form.port {
                            return (
                                StatusCode::CONFLICT,
                                Json(json!({"error": format!("Port {} is already used by \"{}\".", form.port, entry.file_name().to_string_lossy())})),
                            )
                                .into_response();
                        }
                    }
                }
            }
        }
    }

    fs::create_dir_all(&server_dir).ok();

    // Write config
    let config = crate::models::BotConfig {
        name: safe_name.clone(),
        port: form.port,
        runtime: runtime.clone(),
        runtime_version: runtime_version.clone(),
    };
    fs::write(
        server_dir.join(".adpanel.json"),
        serde_json::to_string_pretty(&config).unwrap_or_default(),
    )
    .ok();

    if runtime == "python" {
        // Battery-efficient Python server template
        let starter = format!(
            r#"import http.server
import socketserver
import signal
import sys

PORT = {}

class Handler(http.server.SimpleHTTPRequestHandler):
    # Suppress per-request log output (reduces I/O, saves battery)
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write("Hello from {}! Running on port {{}}".format(PORT).encode())

# Enable address reuse for fast restart
socketserver.TCPServer.allow_reuse_address = True

# Graceful shutdown handler
def signal_handler(sig, frame):
    print("Shutting down...")
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
    print("Server '{}' listening on port {{}}".format(PORT))
    httpd.serve_forever(poll_interval=5)
"#,
            form.port, safe_name, safe_name
        );
        fs::write(server_dir.join("main.py"), &starter).ok();

        // Write requirements.txt
        fs::write(server_dir.join("requirements.txt"), "# Add your dependencies here\n").ok();
    } else {
        // Battery-efficient Node.js server template
        let starter = format!(
            r#"const http = require("http");

const PORT = {};

const server = http.createServer((req, res) => {{
  res.writeHead(200, {{ "Content-Type": "text/plain", "Connection": "keep-alive" }});
  res.end("Hello from {}! Running on port " + PORT);
}});

// Keep-alive settings (reduces connection overhead, saves CPU/battery)
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;
server.maxHeadersCount = 50;

// Graceful shutdown
process.on("SIGTERM", () => {{
  server.close(() => process.exit(0));
}});
process.on("SIGINT", () => {{
  server.close(() => process.exit(0));
}});

// Disable unnecessary Node.js features for battery savings
process.title = "adpanel-{}";

server.listen(PORT, "0.0.0.0", () => {{
  console.log("Server '{}' listening on port " + PORT);
}});
"#,
            form.port, safe_name, safe_name.replace(char::is_whitespace, "-").to_lowercase(), safe_name
        );
        fs::write(server_dir.join("index.js"), &starter).ok();

        // Write package.json
        let pkg = json!({
            "name": folder_name.to_lowercase(),
            "version": "1.0.0",
            "main": "index.js",
            "scripts": {"start": "node index.js"}
        });
        fs::write(
            server_dir.join("package.json"),
            serde_json::to_string_pretty(&pkg).unwrap_or_default(),
        )
        .ok();
    }

    Json(json!({"ok": true, "name": folder_name, "port": form.port, "runtime": runtime})).into_response()
}

// --- API endpoints ---

async fn update_all_packages_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let _sid = match require_admin_api(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };

    let state_clone = state.clone();
    tokio::spawn(async move {
        crate::ws::run_weekly_package_updates(&state_clone).await;
    });

    Json(json!({"ok": true, "message": "Package update started for all servers"})).into_response()
}

async fn usercount_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let _sid = match require_auth_api(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    Json(json!({"userCount": state.user_count()})).into_response()
}

async fn my_servers_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let sid = match require_auth_api(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };

    let all = list_bot_dirs(&state.bots_dir);
    let email = state.session_email(&sid).unwrap_or_default();

    if state.is_admin(&sid) {
        return Json(json!({"names": all})).into_response();
    }

    let access = state.get_access_for_email(&email);
    let names: Vec<String> = if access.iter().any(|s| s == "all") {
        all
    } else {
        all.into_iter().filter(|n| access.contains(n)).collect()
    };

    Json(json!({"names": names})).into_response()
}

async fn list_servers_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let _sid = match require_admin_api(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    Json(json!({"names": list_bot_dirs(&state.bots_dir)})).into_response()
}

#[derive(Deserialize)]
struct ServerNameForm {
    name: String,
}

async fn create_server_folder_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(form): axum::Json<ServerNameForm>,
) -> Response {
    let _sid = match require_admin_api(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };

    let name = match state.sanitize_bot_name(&form.name) {
        Some(n) => n,
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid name"}))).into_response(),
    };

    let target = state.bots_dir.join(&name);
    if target.exists() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "server already exists"}))).into_response();
    }

    match fs::create_dir_all(&target) {
        Ok(_) => Json(json!({"ok": true, "name": name})).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "failed to create server folder"}))).into_response(),
    }
}

async fn delete_server_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> Response {
    let _sid = match require_admin_api(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };

    let decoded = percent_encoding::percent_decode_str(&name)
        .decode_utf8_lossy()
        .to_string();
    let name = match state.sanitize_bot_name(&decoded) {
        Some(n) => n,
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid name"}))).into_response(),
    };

    let target = state.bots_dir.join(&name);
    if !target.exists() {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
    }

    if fs::remove_dir_all(&target).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "failed to delete"}))).into_response();
    }

    // Clean up user-access
    let mut records = state.load_user_access();
    let mut changed = false;
    for rec in &mut records {
        let before = rec.servers.len();
        rec.servers.retain(|s| s != &name);
        if rec.servers.len() != before {
            changed = true;
        }
    }
    if changed {
        state.save_user_access(&records);
    }

    Json(json!({"ok": true})).into_response()
}

// --- Background/Settings ---

#[derive(Deserialize)]
struct BackgroundForm {
    r#type: String,
    value: String,
}

async fn background_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(form): axum::Json<BackgroundForm>,
) -> Response {
    let _sid = match require_admin_api(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };

    let css_val = make_css_background(&form.value, &form.r#type);
    let css_val = match css_val {
        Some(v) => v,
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid background value"}))).into_response(),
    };

    let dashboard_css = state.public_dir.join("dashboard.css");
    let style_css = state.public_dir.join("style.css");

    let ok1 = set_body_background(&dashboard_css, &css_val);
    let ok2 = set_body_background(&style_css, &css_val);

    if ok1 && ok2 {
        Json(json!({"ok": true})).into_response()
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "failed to update files"}))).into_response()
    }
}

fn make_css_background(value: &str, bg_type: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    if bg_type == "color" {
        let color = value.trim();
        // Basic CSS color validation
        if color.starts_with('#') && color.len() <= 9 && color[1..].chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(color.to_string());
        }
        if color.chars().all(|c| c.is_alphabetic()) && color.len() <= 30 {
            return Some(color.to_string());
        }
        None
    } else {
        let url = value.trim();
        if url.contains("javascript:") || url.contains("data:text") || url.contains('(') || url.contains(')') {
            return None;
        }
        Some(format!("url(\"{}\") center/cover no-repeat", url.replace('"', "%22")))
    }
}

fn set_body_background(path: &Path, css_value: &str) -> bool {
    use std::sync::LazyLock;
    static BODY_RE: LazyLock<regex_lite::Regex> = LazyLock::new(|| {
        regex_lite::Regex::new(r"(?s)body\s*\{[^}]*\}").unwrap()
    });
    static BG_PROP_RE: LazyLock<regex_lite::Regex> = LazyLock::new(|| {
        regex_lite::Regex::new(r"background(-image)?\s*:[^;]*;?").unwrap()
    });

    let content = fs::read_to_string(path).unwrap_or_default();

    let new_content = if let Some(m) = BODY_RE.find(&content) {
        let block = m.as_str();
        let new_block = if BG_PROP_RE.is_match(block) {
            BG_PROP_RE.replace(block, format!("background: {};", css_value).as_str()).to_string()
        } else {
            block.replacen('{', &format!("{{ background: {};", css_value), 1)
        };
        format!("{}{}{}", &content[..m.start()], new_block, &content[m.end()..])
    } else {
        format!("body {{ background: {}; }}\n\n{}", css_value, content)
    };

    fs::write(path, new_content).is_ok()
}

#[derive(Deserialize)]
struct ChangePasswordForm {
    current: String,
    #[serde(rename = "newPassword")]
    new_password: String,
    confirm: String,
}

async fn change_password_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(form): axum::Json<ChangePasswordForm>,
) -> Response {
    let sid = match require_admin_api(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };

    if form.new_password.len() < 8 {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "new password too short"}))).into_response();
    }
    if form.new_password != form.confirm {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "Passwords do not match"}))).into_response();
    }

    let email = state.session_email(&sid).unwrap_or_default();
    let mut user = match state.find_user_by_email(&email) {
        Some(u) => u,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "user not found"}))).into_response(),
    };

    if !bcrypt::verify(&form.current, &user.password).unwrap_or(false) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "Current password incorrect"}))).into_response();
    }

    if bcrypt::verify(&form.new_password, &user.password).unwrap_or(false) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "New password is the same as current"}))).into_response();
    }

    user.password = bcrypt::hash(&form.new_password, 10).unwrap_or_default();
    state.update_user(&user);

    Json(json!({"ok": true})).into_response()
}

async fn accounts_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let _sid = match require_admin_api(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };

    let users = state.load_users();
    let admin_emails: Vec<String> = users
        .iter()
        .filter(|u| u.admin)
        .map(|u| u.email.to_lowercase())
        .collect();

    let access = state.load_user_access();
    let accounts: Vec<Value> = access
        .iter()
        .filter(|a| !admin_emails.contains(&a.email.to_lowercase()))
        .map(|a| json!({"email": a.email, "servers": a.servers}))
        .collect();

    let bots = list_bot_dirs(&state.bots_dir);
    Json(json!({"accounts": accounts, "bots": bots})).into_response()
}

#[derive(Deserialize)]
struct AccessForm {
    server: String,
}

async fn add_access_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(email): AxumPath<String>,
    axum::Json(form): axum::Json<AccessForm>,
) -> Response {
    let _sid = match require_admin_api(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };

    let decoded_email = percent_encoding::percent_decode_str(&email)
        .decode_utf8_lossy()
        .to_string();

    let bots = list_bot_dirs(&state.bots_dir);
    if !bots.contains(&form.server) && form.server != "all" {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "server not found"}))).into_response();
    }

    if state.add_access_for_email(&decoded_email, &form.server) {
        Json(json!({"ok": true})).into_response()
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "failed to save access"}))).into_response()
    }
}

async fn remove_access_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(email): AxumPath<String>,
    axum::Json(form): axum::Json<AccessForm>,
) -> Response {
    let _sid = match require_admin_api(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };

    let decoded_email = percent_encoding::percent_decode_str(&email)
        .decode_utf8_lossy()
        .to_string();

    if state.remove_access_for_email(&decoded_email, &form.server) {
        Json(json!({"ok": true})).into_response()
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "failed to remove access"}))).into_response()
    }
}

// --- WebSocket handler ---

async fn ws_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(bot): AxumPath<String>,
    ws: WebSocketUpgrade,
) -> Response {
    let sid = match get_session_id(&headers) {
        Some(s) => s,
        None => return (StatusCode::UNAUTHORIZED, "Authentication required").into_response(),
    };

    if !state.is_authenticated(&sid) {
        return (StatusCode::UNAUTHORIZED, "Authentication required").into_response();
    }

    let bot_name = match state.sanitize_bot_name(&bot) {
        Some(n) => n,
        None => return (StatusCode::BAD_REQUEST, "Invalid bot name").into_response(),
    };

    let email = state.session_email(&sid).unwrap_or_default();
    if !state.is_admin(&sid) && !state.user_has_access(&email, &bot_name) {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    ws.on_upgrade(move |socket| crate::ws::handle_ws(socket, state, bot_name, email))
}

// --- Helpers ---

fn list_bot_dirs(bots_dir: &Path) -> Vec<String> {
    match fs::read_dir(bots_dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect(),
        Err(_) => vec![],
    }
}
