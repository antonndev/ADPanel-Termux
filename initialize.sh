#!/usr/bin/env bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[1;35m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_FILE="$SCRIPT_DIR/user.json"
ENV_FILE="$SCRIPT_DIR/.env"
BINARY="$SCRIPT_DIR/adpanel"

echo -e "${MAGENTA}==============================${NC}"
echo -e "${CYAN} Welcome to ADPanel Initializer ${NC}"
echo -e "${MAGENTA}==============================${NC}"

# ── Build or check binary ────────────────────────────────────
ensure_binary() {
  if [ -f "$BINARY" ]; then
    return 0
  fi

  echo -e "${CYAN}Building ADPanel (Rust)...${NC}"

  # Rust 1.85+ is required (crate ecosystem uses edition 2024)
  # Termux 'pkg install rust' gives 1.75 which is too old - must use rustup
  MIN_MINOR=85
  NEED_INSTALL=false

  if ! command -v cargo &> /dev/null; then
    NEED_INSTALL=true
  else
    RUST_MINOR=$(rustc --version | sed -n 's/rustc 1\.\([0-9]*\).*/\1/p')
    if [ -z "$RUST_MINOR" ] || [ "$RUST_MINOR" -lt "$MIN_MINOR" ]; then
      echo -e "${YELLOW}Rust 1.${RUST_MINOR:-??} detected — need 1.${MIN_MINOR}+${NC}"
      NEED_INSTALL=true
    fi
  fi

  if [ "$NEED_INSTALL" = true ]; then
    echo -e "${YELLOW}Installing/updating Rust via rustup (required >= 1.${MIN_MINOR})...${NC}"
    echo -e "${YELLOW}NOTE: Do NOT use 'pkg install rust' — it gives an outdated version.${NC}"
    if command -v rustup &> /dev/null; then
      rustup update stable 2>&1
    else
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
      export PATH="$HOME/.cargo/bin:$PATH"
      . "$HOME/.cargo/env" 2>/dev/null
    fi
    if ! command -v cargo &> /dev/null; then
      echo -e "${RED}Failed to install Rust. Install manually:${NC}"
      echo -e "${RED}  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh${NC}"
      exit 1
    fi
    RUST_MINOR=$(rustc --version | sed -n 's/rustc 1\.\([0-9]*\).*/\1/p')
    if [ -n "$RUST_MINOR" ] && [ "$RUST_MINOR" -lt "$MIN_MINOR" ]; then
      echo -e "${RED}Rust is still too old (1.${RUST_MINOR}). Need 1.${MIN_MINOR}+.${NC}"
      echo -e "${RED}Try: rustup update stable${NC}"
      exit 1
    fi
  fi

  cd "$SCRIPT_DIR" && cargo build --release 2>&1
  if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed! Check errors above.${NC}"
    exit 1
  fi

  cp "$SCRIPT_DIR/target/release/adpanel" "$BINARY" 2>/dev/null
  chmod +x "$BINARY"
  echo -e "${GREEN}Build successful!${NC}"
}

echo -e "${YELLOW}Choose an option:${NC}"
echo -e "1) Initialize Panel"
echo -e "2) Change Admin Password"
echo -e "3) Delete Admin User"
echo -e "4) Create User"
read -p "Enter choice (1, 2, 3 or 4): " CHOICE

setup_https() {
  echo ""
  echo -e "${YELLOW}Do you want to enable HTTPS?${NC}"
  read -p "Enable HTTPS? (y/n): " ENABLE_HTTPS

  if [[ ! "$ENABLE_HTTPS" =~ ^[Yy] ]]; then
    echo -e "${CYAN}Skipping HTTPS setup. Panel will run on HTTP.${NC}"
    read -p "HTTP port [3000]: " HTTP_PORT
    HTTP_PORT="${HTTP_PORT:-3000}"
    cat > "$ENV_FILE" <<ENVEOF
# ADPanel Configuration
HTTPS_ENABLED=false
HTTP_PORT=$HTTP_PORT
ENVEOF
    chmod 600 "$ENV_FILE"
    echo -e "${GREEN}.env created (HTTP mode, port $HTTP_PORT)${NC}"
    return
  fi

  read -p "Enter your domain (e.g. panel.example.com): " DOMAIN
  if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Domain is required for HTTPS. Aborting HTTPS setup.${NC}"
    cat > "$ENV_FILE" <<ENVEOF
# ADPanel Configuration
HTTPS_ENABLED=false
HTTP_PORT=3000
ENVEOF
    chmod 600 "$ENV_FILE"
    return
  fi

  read -p "HTTP port [80]: " HTTP_PORT
  HTTP_PORT="${HTTP_PORT:-80}"
  read -p "HTTPS port [443]: " HTTPS_PORT
  HTTPS_PORT="${HTTPS_PORT:-443}"

  SSL_DIR="$SCRIPT_DIR/ssl"
  mkdir -p "$SSL_DIR"

  echo -e "${CYAN}Choose SSL certificate method:${NC}"
  echo -e "1) Let's Encrypt (certbot) — requires public domain and ports 80/443"
  echo -e "2) Self-signed certificate — works locally, browsers will warn"
  read -p "Choice [2]: " SSL_METHOD
  SSL_METHOD="${SSL_METHOD:-2}"

  if [ "$SSL_METHOD" == "1" ]; then
    if ! command -v certbot &> /dev/null; then
      echo -e "${YELLOW}Installing certbot...${NC}"
      if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y certbot 2>/dev/null || {
          echo -e "${RED}Failed to install certbot. Install it manually and re-run.${NC}"
          echo -e "${YELLOW}Falling back to self-signed certificate.${NC}"
          SSL_METHOD="2"
        }
      elif command -v pkg &> /dev/null; then
        pkg install -y certbot 2>/dev/null || {
          echo -e "${RED}Failed to install certbot. Falling back to self-signed certificate.${NC}"
          SSL_METHOD="2"
        }
      else
        echo -e "${RED}Cannot install certbot automatically. Falling back to self-signed.${NC}"
        SSL_METHOD="2"
      fi
    fi
  fi

  if [ "$SSL_METHOD" == "1" ]; then
    echo -e "${CYAN}Requesting Let's Encrypt certificate for $DOMAIN...${NC}"
    certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email \
      --cert-path "$SSL_DIR/fullchain.pem" --key-path "$SSL_DIR/privkey.pem" 2>/dev/null

    if [ $? -eq 0 ]; then
      LE_LIVE="/etc/letsencrypt/live/$DOMAIN"
      if [ -d "$LE_LIVE" ]; then
        cp "$LE_LIVE/fullchain.pem" "$SSL_DIR/fullchain.pem"
        cp "$LE_LIVE/privkey.pem" "$SSL_DIR/privkey.pem"
      fi
      echo -e "${GREEN}Let's Encrypt certificate obtained!${NC}"
    else
      echo -e "${RED}Certbot failed. Generating self-signed certificate instead.${NC}"
      SSL_METHOD="2"
    fi
  fi

  if [ "$SSL_METHOD" == "2" ]; then
    echo -e "${CYAN}Generating self-signed SSL certificate for $DOMAIN...${NC}"
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$SSL_DIR/privkey.pem" \
      -out "$SSL_DIR/fullchain.pem" \
      -days 365 \
      -subj "/CN=$DOMAIN" 2>/dev/null

    if [ $? -ne 0 ]; then
      echo -e "${RED}Failed to generate SSL certificate. Is openssl installed?${NC}"
      echo -e "${YELLOW}Continuing without HTTPS.${NC}"
      cat > "$ENV_FILE" <<ENVEOF
# ADPanel Configuration
HTTPS_ENABLED=false
HTTP_PORT=3000
ENVEOF
      chmod 600 "$ENV_FILE"
      return
    fi
    echo -e "${GREEN}Self-signed certificate generated!${NC}"
    echo -e "${YELLOW}Note: Browsers will show a security warning for self-signed certificates.${NC}"
  fi

  chmod 600 "$SSL_DIR/privkey.pem" "$SSL_DIR/fullchain.pem" 2>/dev/null

  cat > "$ENV_FILE" <<ENVEOF
# ADPanel Configuration
HTTPS_ENABLED=true
HTTP_PORT=$HTTP_PORT
HTTPS_PORT=$HTTPS_PORT
DOMAIN=$DOMAIN
SSL_KEY_PATH=$SSL_DIR/privkey.pem
SSL_CERT_PATH=$SSL_DIR/fullchain.pem
ENVEOF
  chmod 600 "$ENV_FILE"

  echo -e "${GREEN}HTTPS configured!${NC}"
  echo -e "${CYAN}  Domain:     $DOMAIN${NC}"
  echo -e "${CYAN}  HTTP port:  $HTTP_PORT (redirects to HTTPS)${NC}"
  echo -e "${CYAN}  HTTPS port: $HTTPS_PORT${NC}"
  echo -e "${CYAN}  SSL cert:   $SSL_DIR/fullchain.pem${NC}"
  echo -e "${CYAN}  SSL key:    $SSL_DIR/privkey.pem${NC}"
}

initialize_panel() {
  ensure_binary

  echo -e "${CYAN}=== Panel Initialization ===${NC}"

  # The binary handles user creation interactively
  cd "$SCRIPT_DIR" && "$BINARY" init

  # HTTPS / .env setup
  setup_https

  echo -e "${YELLOW}Panel setup complete!${NC}"
  echo -e "${CYAN}Starting panel in background...${NC}"
  cd "$SCRIPT_DIR" && nohup "$BINARY" serve > /dev/null 2>&1 &
  echo -e "${GREEN}Panel running (PID: $!).${NC}"
}

change_password() {
  ensure_binary
  cd "$SCRIPT_DIR" && "$BINARY" change-password
}

delete_user() {
  ensure_binary
  cd "$SCRIPT_DIR" && "$BINARY" delete-user
}

create_user() {
  ensure_binary
  cd "$SCRIPT_DIR" && "$BINARY" create-user
}

if [ "$CHOICE" == "1" ]; then
  initialize_panel
elif [ "$CHOICE" == "2" ]; then
  change_password
elif [ "$CHOICE" == "3" ]; then
  delete_user
elif [ "$CHOICE" == "4" ]; then
  create_user
else
  echo -e "${RED}Invalid choice. Exiting.${NC}"
  exit 1
fi
