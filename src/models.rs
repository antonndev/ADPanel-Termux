use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub email: String,
    pub password: String,
    pub secret: String,
    #[serde(default)]
    pub admin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccessRecord {
    pub email: String,
    #[serde(default)]
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub rate_limiting: bool,
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default = "default_window")]
    pub window_seconds: u64,
}

fn default_limit() -> u32 {
    5
}
fn default_window() -> u64 {
    120
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            rate_limiting: false,
            limit: default_limit(),
            window_seconds: default_window(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotConfig {
    pub name: String,
    pub port: u16,
    #[serde(default = "default_runtime")]
    pub runtime: String,
    #[serde(default)]
    pub runtime_version: String,
}

fn default_runtime() -> String {
    "nodejs".to_string()
}
