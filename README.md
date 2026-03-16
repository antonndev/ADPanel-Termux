# 🔥 What is this?
**A powerful, easy-to-use panel for Termux or any Linux OS to run your Discord bots right from your phone!**

Built with **Rust** (axum + tokio) for maximum performance, minimal memory usage, and rock-solid security.

<p align="center">
  <img src="https://files.catbox.moe/1m6ydq.png" alt="ADPanel preview" width="600"/>
  ``` ```
  <img src="https://files.catbox.moe/7u7x5b.png" alt="ADPanel preview" width="600"/>
</p>

---

# 🚀 One-Command Install (Termux & Linux)

Paste this single command — it works on both **Termux (Android)** and any **Linux** distro:

```bash
curl -sL https://sh.rustup.rs | sh -s -- -y && . "$HOME/.cargo/env" && (command -v pkg >/dev/null 2>&1 && pkg install -y openssl git nodejs python || true) && (command -v apt-get >/dev/null 2>&1 && sudo apt-get install -y git nodejs npm python3 python3-pip || true) && git clone https://github.com/antonndev/ADPanel-Termux.git && cd ADPanel-Termux && chmod +x initialize.sh start.sh && bash initialize.sh
```

> **What it does:** Installs Rust via rustup, installs system dependencies (git, Node.js, Python) for your platform, clones the repo, and launches the setup wizard.

### Start the panel (after initial setup)
```bash
cd ADPanel-Termux && bash start.sh
```

---

# ⚙️ Manual Install (step by step)

<details>
<summary>Termux (Android)</summary>

```bash
pkg install -y openssl git nodejs python
curl -sL https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
git clone https://github.com/antonndev/ADPanel-Termux.git
cd ADPanel-Termux && chmod +x initialize.sh start.sh && bash initialize.sh
```
</details>

<details>
<summary>Linux (Ubuntu/Debian)</summary>

```bash
sudo apt-get install -y git nodejs npm python3 python3-pip
curl -sL https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
git clone https://github.com/antonndev/ADPanel-Termux.git
cd ADPanel-Termux && chmod +x initialize.sh start.sh && bash initialize.sh
```
</details>

The initialize script will:
1. Install Rust if needed and build the panel
2. Create your admin account with 2FA
3. Configure HTTP/HTTPS settings
4. Start the panel

---

### CLI Commands
The `adpanel` binary supports these commands:
```
./adpanel serve             # Start the web servers
./adpanel init              # Initialize panel (create admin user)
./adpanel create-user       # Create a new user
./adpanel change-password   # Change admin password
./adpanel delete-user       # Delete admin user
```

# How to change password for Admin user or something else?
 **Just run this in your terminal:**
 
```
bash initialize.sh
```

 **Or you can access Panel Settings from the dashboard and click on Account category**

 # How to set a default user limited servers access?
 **You can do this in account settings.**

# Does this Discord Panel have protection against DDoS attacks?
**Absolutely, it has rate limiting enabled by default, set to 10 requests per minute. You can change the limit by running ./rate-limiting.sh and choosing option 3.**
<br>
<br>

# Tech Stack
- **Backend**: Rust (axum, tokio, rustls)
- **Frontend**: HTML + Tailwind CSS + HTMX
- **Real-time Console**: WebSocket (native axum)
- **Auth**: bcrypt + TOTP 2FA
- **TLS**: rustls (no OpenSSL dependency at runtime
 
