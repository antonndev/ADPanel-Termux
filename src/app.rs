use crate::models::{SecurityConfig, User, UserAccessRecord};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tera::Tera;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct AppState {
    pub base_dir: PathBuf,
    pub bots_dir: PathBuf,
    pub uploads_dir: PathBuf,
    pub public_dir: PathBuf,
    pub users_file: PathBuf,
    pub user_access_file: PathBuf,
    pub security_file: PathBuf,
    pub session_secret_file: PathBuf,
    pub sessions_file: PathBuf,
    pub templates: Arc<Tera>,
    pub sessions: Arc<DashMap<String, SessionData>>,
    pub security: Arc<RwLock<SecurityConfig>>,
    pub rate_requests: Arc<DashMap<String, Vec<u64>>>,
    pub login_attempts: Arc<DashMap<String, LoginAttemptRecord>>,
    pub processes: Arc<DashMap<String, ProcessHandle>>,
    pub log_buffers: Arc<DashMap<String, VecDeque<Arc<str>>>>,
    pub bot_channels: Arc<DashMap<String, broadcast::Sender<Arc<str>>>>,
    pub server_start: Instant,
    pub session_secret: Arc<[u8]>,
    pub https_enabled: bool,
    pub users_cache: Arc<RwLock<Vec<User>>>,
    pub user_access_cache: Arc<RwLock<Vec<UserAccessRecord>>>,
    pub sessions_dirty: Arc<AtomicBool>,
    /// Cached python command ("python3" or "python"), detected once at startup
    pub python_cmd: Arc<str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub user_email: Option<String>,
    pub totp_secret: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone)]
pub struct LoginAttemptRecord {
    pub count: u32,
    pub last_attempt: u64,
}

pub struct ProcessHandle {
    pub child: tokio::process::Child,
}

// Cannot derive Clone for ProcessHandle since Child isn't Clone
// We'll wrap it in Arc<Mutex> where needed

const LOG_BUFFER_SIZE: usize = 200;
const LOGIN_MAX_ATTEMPTS: u32 = 5;
const LOGIN_LOCKOUT_MS: u64 = 15 * 60 * 1000;

impl AppState {
    pub fn new(base_dir: PathBuf, https_enabled: bool) -> Self {
        let bots_dir = base_dir.join("bots");
        let uploads_dir = base_dir.join("uploads");
        let public_dir = base_dir.join("public");
        let users_file = base_dir.join("user.json");
        let user_access_file = base_dir.join("user-access.json");
        let security_file = base_dir.join("security.json");
        let session_secret_file = base_dir.join(".session-secret");
        let sessions_file = base_dir.join(".sessions.json");

        for dir in [&bots_dir, &uploads_dir, &public_dir] {
            fs::create_dir_all(dir).ok();
        }

        // Load or create session secret
        let session_secret = load_or_create_session_secret(&session_secret_file);

        // Load security config
        let security = load_security_config(&security_file);

        // Ensure user-access.json exists
        if !user_access_file.exists() {
            fs::write(&user_access_file, "[]").ok();
        }

        // Load templates
        let templates_dir = base_dir.join("templates/**/*");
        let tera = match Tera::new(templates_dir.to_str().unwrap_or("templates/**/*")) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Template parsing error: {}", e);
                Tera::default()
            }
        };

        // Load persisted sessions
        let sessions: Arc<DashMap<String, SessionData>> = Arc::new(DashMap::with_shard_amount(4));
        if let Ok(raw) = fs::read_to_string(&sessions_file) {
            if let Ok(map) = serde_json::from_str::<HashMap<String, SessionData>>(&raw) {
                let now = current_time_ms();
                // Max session age: 30 days
                const MAX_SESSION_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1000;
                for (k, v) in map {
                    if now.saturating_sub(v.created_at) < MAX_SESSION_AGE_MS && v.user_email.is_some() {
                        sessions.insert(k, v);
                    }
                }
                tracing::info!("[sessions] Restored {} sessions from disk", sessions.len());
            }
        }

        // Pre-load users and user-access into memory caches (avoids disk I/O per request)
        let users_cache = Arc::new(RwLock::new(load_users_from_file(&users_file)));
        let user_access_cache = Arc::new(RwLock::new(load_user_access_from_file(&user_access_file)));

        // Detect python command once at startup
        let python_cmd: Arc<str> = if std::process::Command::new("python3")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok()
        {
            Arc::from("python3")
        } else {
            Arc::from("python")
        };

        let state = Self {
            base_dir,
            bots_dir,
            uploads_dir,
            public_dir,
            users_file,
            user_access_file,
            security_file: security_file.clone(),
            session_secret_file,
            sessions_file: sessions_file.clone(),
            templates: Arc::new(tera),
            sessions,
            security: Arc::new(RwLock::new(security)),
            rate_requests: Arc::new(DashMap::with_shard_amount(4)),
            login_attempts: Arc::new(DashMap::with_shard_amount(4)),
            processes: Arc::new(DashMap::with_shard_amount(4)),
            log_buffers: Arc::new(DashMap::with_shard_amount(4)),
            bot_channels: Arc::new(DashMap::with_shard_amount(4)),
            server_start: Instant::now(),
            session_secret: session_secret.into(),
            https_enabled,
            users_cache,
            user_access_cache,
            sessions_dirty: Arc::new(AtomicBool::new(false)),
            python_cmd,
        };

        // Sync user access
        state.sync_user_access();

        // Spawn security config watcher
        let sf = security_file;
        let sec = state.security.clone();
        tokio::spawn(async move {
            watch_security_config(sf, sec).await;
        });

        // Spawn rate limit cleanup (every 5 minutes — low CPU wake frequency)
        let rr = state.rate_requests.clone();
        let sec2 = state.security.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                cleanup_rate_requests(&rr, &sec2);
            }
        });

        // Spawn login attempt cleanup (every 10 minutes)
        let la = state.login_attempts.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(600)).await;
                let now = current_time_ms();
                la.retain(|_, v| now - v.last_attempt < LOGIN_LOCKOUT_MS);
            }
        });

        // Spawn session persistence (flush to disk every 2 minutes, only if changed)
        let sess = state.sessions.clone();
        let sess_file = sessions_file;
        let sess_dirty = state.sessions_dirty.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(120)).await;
                if sess_dirty.swap(false, Ordering::Relaxed) {
                    let map: HashMap<String, SessionData> = sess.iter()
                        .map(|e| (e.key().clone(), e.value().clone()))
                        .collect();
                    if let Ok(json) = serde_json::to_string(&map) {
                        let _ = fs::write(&sess_file, json);
                    }
                }
            }
        });

        // Spawn weekly package auto-update (every 7 days)
        let update_state = state.clone();
        tokio::spawn(async move {
            loop {
                // Wait 7 days between updates
                tokio::time::sleep(std::time::Duration::from_secs(7 * 24 * 60 * 60)).await;
                tracing::info!("[auto-update] Running weekly package updates...");
                crate::ws::run_weekly_package_updates(&update_state).await;
                tracing::info!("[auto-update] Weekly package updates complete");
            }
        });

        state
    }

    // --- User operations ---

    pub fn load_users(&self) -> Vec<User> {
        self.users_cache.read().unwrap().clone()
    }

    pub fn save_users(&self, users: &[User]) -> bool {
        match serde_json::to_string_pretty(users) {
            Ok(json) => {
                if fs::write(&self.users_file, &json).is_ok() {
                    *self.users_cache.write().unwrap() = users.to_vec();
                    true
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    pub fn find_user_by_email(&self, email: &str) -> Option<User> {
        let cache = self.users_cache.read().unwrap();
        let lower = email.to_lowercase();
        cache.iter().find(|u| u.email.to_lowercase() == lower).cloned()
    }

    /// Check if user exists without cloning the User struct
    pub fn user_exists(&self, email: &str) -> bool {
        let cache = self.users_cache.read().unwrap();
        let lower = email.to_lowercase();
        cache.iter().any(|u| u.email.to_lowercase() == lower)
    }

    /// Check if user is admin without cloning the User struct
    pub fn is_user_admin(&self, email: &str) -> bool {
        let cache = self.users_cache.read().unwrap();
        let lower = email.to_lowercase();
        cache.iter().find(|u| u.email.to_lowercase() == lower).map(|u| u.admin).unwrap_or(false)
    }

    pub fn update_user(&self, updated: &User) -> bool {
        let mut users = self.load_users();
        if let Some(idx) = users
            .iter()
            .position(|u| u.email.to_lowercase() == updated.email.to_lowercase())
        {
            users[idx] = updated.clone();
        } else {
            users.push(updated.clone());
        }
        self.save_users(&users)
    }

    pub fn user_count(&self) -> usize {
        self.users_cache.read().unwrap().len()
    }

    // --- User access operations ---

    pub fn load_user_access(&self) -> Vec<UserAccessRecord> {
        self.user_access_cache.read().unwrap().clone()
    }

    pub fn save_user_access(&self, records: &[UserAccessRecord]) -> bool {
        match serde_json::to_string_pretty(records) {
            Ok(json) => {
                if fs::write(&self.user_access_file, &json).is_ok() {
                    *self.user_access_cache.write().unwrap() = records.to_vec();
                    true
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    pub fn get_access_for_email(&self, email: &str) -> Vec<String> {
        let cache = self.user_access_cache.read().unwrap();
        let lower = email.to_lowercase();
        cache
            .iter()
            .find(|r| r.email.to_lowercase() == lower)
            .map(|r| r.servers.clone())
            .unwrap_or_default()
    }

    pub fn add_access_for_email(&self, email: &str, server: &str) -> bool {
        let mut records = self.load_user_access();
        if let Some(rec) = records
            .iter_mut()
            .find(|r| r.email.to_lowercase() == email.to_lowercase())
        {
            if !rec.servers.iter().any(|s| s == server) {
                rec.servers.push(server.to_string());
            }
        } else {
            records.push(UserAccessRecord {
                email: email.to_string(),
                servers: vec![server.to_string()],
            });
        }
        self.save_user_access(&records)
    }

    pub fn remove_access_for_email(&self, email: &str, server: &str) -> bool {
        let mut records = self.load_user_access();
        if let Some(rec) = records
            .iter_mut()
            .find(|r| r.email.to_lowercase() == email.to_lowercase())
        {
            rec.servers.retain(|s| s != server);
        }
        self.save_user_access(&records)
    }

    pub fn user_has_access(&self, email: &str, bot_name: &str) -> bool {
        if self.is_user_admin(email) {
            return true;
        }
        let cache = self.user_access_cache.read().unwrap();
        let lower = email.to_lowercase();
        cache.iter()
            .find(|r| r.email.to_lowercase() == lower)
            .map(|r| r.servers.iter().any(|s| s == "all" || s == bot_name))
            .unwrap_or(false)
    }

    pub fn sync_user_access(&self) {
        let users = self.load_users();
        if users.is_empty() {
            return;
        }
        let mut access = self.load_user_access();
        let existing: std::collections::HashSet<String> =
            access.iter().map(|r| r.email.to_lowercase()).collect();
        let mut added = 0;
        for u in &users {
            if !existing.contains(&u.email.to_lowercase()) {
                access.push(UserAccessRecord {
                    email: u.email.clone(),
                    servers: vec![],
                });
                added += 1;
            }
        }
        if added > 0 {
            self.save_user_access(&access);
            tracing::info!("[user-access] Synced: added {} entries", added);
        }
    }

    // --- Session operations ---

    pub fn create_session(&self) -> String {
        let sid = uuid::Uuid::new_v4().to_string();
        self.sessions.insert(
            sid.clone(),
            SessionData {
                user_email: None,
                totp_secret: None,
                created_at: current_time_ms(),
            },
        );
        self.sessions_dirty.store(true, Ordering::Relaxed);
        sid
    }

    pub fn get_session(&self, sid: &str) -> Option<SessionData> {
        self.sessions.get(sid).map(|s| s.clone())
    }

    pub fn set_session_user(&self, sid: &str, email: &str) {
        if let Some(mut s) = self.sessions.get_mut(sid) {
            s.user_email = Some(email.to_string());
        }
        self.persist_sessions();
    }

    pub fn set_session_secret(&self, sid: &str, secret: &str) {
        if let Some(mut s) = self.sessions.get_mut(sid) {
            s.totp_secret = Some(secret.to_string());
        }
        self.sessions_dirty.store(true, Ordering::Relaxed);
    }

    pub fn destroy_session(&self, sid: &str) {
        self.sessions.remove(sid);
        self.persist_sessions();
    }

    pub fn is_authenticated(&self, sid: &str) -> bool {
        if let Some(session) = self.sessions.get(sid) {
            if let Some(ref email) = session.user_email {
                return self.user_exists(email);
            }
        }
        false
    }

    pub fn is_admin(&self, sid: &str) -> bool {
        if let Some(session) = self.sessions.get(sid) {
            if let Some(ref email) = session.user_email {
                return self.is_user_admin(email);
            }
        }
        false
    }

    pub fn session_email(&self, sid: &str) -> Option<String> {
        self.sessions
            .get(sid)
            .and_then(|s| s.user_email.clone())
    }

    // --- Session persistence ---

    fn persist_sessions(&self) {
        self.sessions_dirty.store(true, Ordering::Relaxed);
    }

    // --- Rate limiting ---

    pub fn check_rate_limit(&self, ip: &str) -> Result<(), u64> {
        let security = self.security.read().unwrap();
        if !security.rate_limiting {
            return Ok(());
        }
        let now = current_time_ms();
        let window_ms = security.window_seconds * 1000;
        let limit = security.limit;

        let mut entry = self.rate_requests.entry(ip.to_string()).or_default();
        let arr = entry.value_mut();
        arr.retain(|&ts| now - ts <= window_ms);

        if arr.len() as u32 >= limit {
            let oldest = arr.first().copied().unwrap_or(now);
            let retry_after = (oldest + window_ms - now) / 1000 + 1;
            return Err(retry_after);
        }
        arr.push(now);
        Ok(())
    }

    // --- Login brute force ---

    pub fn check_login_brute_force(&self, ip: &str) -> Result<(), u64> {
        if let Some(record) = self.login_attempts.get(ip) {
            if record.count >= LOGIN_MAX_ATTEMPTS {
                let elapsed = current_time_ms() - record.last_attempt;
                if elapsed < LOGIN_LOCKOUT_MS {
                    return Err((LOGIN_LOCKOUT_MS - elapsed) / 1000 + 1);
                }
                self.login_attempts.remove(ip);
            }
        }
        Ok(())
    }

    pub fn record_failed_login(&self, ip: &str) {
        let now = current_time_ms();
        let mut entry = self
            .login_attempts
            .entry(ip.to_string())
            .or_insert(LoginAttemptRecord {
                count: 0,
                last_attempt: 0,
            });
        entry.count += 1;
        entry.last_attempt = now;
    }

    pub fn clear_failed_logins(&self, ip: &str) {
        self.login_attempts.remove(ip);
    }

    // --- Bot log buffers ---

    /// Push a pre-allocated Arc<str> log line (avoids double allocation)
    #[inline]
    pub fn push_log(&self, bot: &str, arc_line: Arc<str>) {
        let mut entry = self.log_buffers.entry(bot.to_string()).or_default();
        let buf = entry.value_mut();
        buf.push_back(arc_line);
        if buf.len() > LOG_BUFFER_SIZE {
            buf.pop_front();
        }
    }

    pub fn get_log_buffer(&self, bot: &str) -> Vec<Arc<str>> {
        self.log_buffers
            .get(bot)
            .map(|b| b.value().iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_or_create_channel(&self, bot: &str) -> broadcast::Sender<Arc<str>> {
        if let Some(ch) = self.bot_channels.get(bot) {
            return ch.clone();
        }
        self.bot_channels
            .entry(bot.to_string())
            .or_insert_with(|| broadcast::channel(64).0)
            .clone()
    }

    // --- Path safety ---

    pub fn sanitize_bot_name(&self, name: &str) -> Option<String> {
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.len() > 120 {
            return None;
        }
        if trimmed.contains("..") || trimmed.contains('/') || trimmed.contains('\\') {
            return None;
        }
        if trimmed.bytes().any(|b| b < 0x20) {
            return None;
        }
        Some(trimmed.to_string())
    }

    pub fn safe_resolve_path(&self, segments: &[&str]) -> Option<PathBuf> {
        let mut p = self.bots_dir.clone();
        for seg in segments {
            p = p.join(seg);
        }
        let resolved = match p.canonicalize() {
            Ok(r) => r,
            Err(_) => {
                // Path doesn't exist yet, resolve manually
                let mut resolved = self.bots_dir.canonicalize().ok()?;
                for seg in segments {
                    resolved = resolved.join(seg);
                }
                resolved
            }
        };
        let bots_resolved = self.bots_dir.canonicalize().ok()?;
        if resolved == bots_resolved || resolved.starts_with(&bots_resolved) {
            Some(resolved)
        } else {
            None
        }
    }

    pub fn sanitize_filename(&self, name: &str) -> Option<String> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return None;
        }
        if trimmed.contains("..") || trimmed.contains('/') || trimmed.contains('\\') {
            return None;
        }
        if trimmed.bytes().any(|b| b < 0x20) {
            return None;
        }
        Some(trimmed.to_string())
    }
}

// --- Helper functions ---

pub fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn load_or_create_session_secret(path: &Path) -> Vec<u8> {
    if let Ok(data) = fs::read_to_string(path) {
        let trimmed = data.trim();
        if trimmed.len() >= 32 {
            return trimmed.as_bytes().to_vec();
        }
    }
    let secret: Vec<u8> = (0..48).map(|_| rand::random::<u8>()).collect();
    let hex_secret = hex::encode(&secret);
    let _ = fs::write(path, &hex_secret);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    tracing::info!("[security] Generated new session secret");
    hex_secret.as_bytes().to_vec()
}

fn load_security_config(path: &Path) -> SecurityConfig {
    if !path.exists() {
        let config = SecurityConfig::default();
        if let Ok(json) = serde_json::to_string_pretty(&config) {
            fs::write(path, json).ok();
        }
        return config;
    }
    match fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(_) => SecurityConfig::default(),
    }
}

fn load_users_from_file(path: &Path) -> Vec<User> {
    if !path.exists() {
        return vec![];
    }
    match fs::read_to_string(path) {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return vec![];
            }
            serde_json::from_str(trimmed).unwrap_or_default()
        }
        Err(_) => vec![],
    }
}

fn load_user_access_from_file(path: &Path) -> Vec<UserAccessRecord> {
    if !path.exists() {
        return vec![];
    }
    match fs::read_to_string(path) {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return vec![];
            }
            serde_json::from_str(trimmed).unwrap_or_default()
        }
        Err(_) => vec![],
    }
}

async fn watch_security_config(
    path: PathBuf,
    security: Arc<RwLock<SecurityConfig>>,
) {
    let mut last_modified = fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok();

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        if let Ok(meta) = fs::metadata(&path) {
            if let Ok(modified) = meta.modified() {
                if last_modified.as_ref() != Some(&modified) {
                    last_modified = Some(modified);
                    if let Ok(raw) = fs::read_to_string(&path) {
                        if let Ok(config) = serde_json::from_str::<SecurityConfig>(&raw) {
                            if let Ok(mut sec) = security.write() {
                                *sec = config;
                                tracing::info!("[rate-limiter] security.json reloaded");
                            }
                        }
                    }
                }
            }
        }
    }
}

fn cleanup_rate_requests(
    requests: &DashMap<String, Vec<u64>>,
    security: &RwLock<SecurityConfig>,
) {
    let now = current_time_ms();
    let window_ms = security
        .read()
        .map(|s| s.window_seconds * 1000)
        .unwrap_or(120_000);
    requests.retain(|_, arr| {
        arr.retain(|&ts| now - ts <= window_ms);
        !arr.is_empty()
    });
}
