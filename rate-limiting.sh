#!/usr/bin/env bash
# rate-limiting.sh

FILE="security.json"
DEFAULT_LIMIT=10
DEFAULT_WINDOW=60

json_read_number() {
  local key="$1"
  if [ -f "$FILE" ]; then
    if grep -Pq "\"$key\"\s*:\s*[0-9]+" "$FILE" 2>/dev/null; then
      grep -P "\"$key\"\s*:\s*[0-9]+" "$FILE" | head -n1 | grep -oP "[0-9]+" || echo ""
    else
      sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p" "$FILE" | head -n1 || echo ""
    fi
  else
    echo ""
  fi
}

json_read_rate_flag() {
  if [ -f "$FILE" ]; then
    if grep -Pq '"rate_limiting"\s*:\s*true' "$FILE" 2>/dev/null; then
      echo "true"
    elif grep -Pq '"rate_limiting"\s*:\s*false' "$FILE" 2>/dev/null; then
      echo "false"
    else
      echo "absent"
    fi
  else
    echo "absent"
  fi
}

if [ ! -f "$FILE" ]; then
  cat > "$FILE" <<EOF
{
  "rate_limiting": false,
  "limit": $DEFAULT_LIMIT,
  "window_seconds": $DEFAULT_WINDOW
}
EOF
  echo "Created default $FILE"
fi

ensure_json_minimal() {
  if [ ! -f "$FILE" ]; then
    echo "{}" > "$FILE"
    return
  fi
  if ! grep -q '{' "$FILE" || ! grep -q '}' "$FILE"; then
    echo "{}" > "$FILE"
    return
  fi
  if ! grep -q '"[A-Za-z0-9_:-]\+"' "$FILE"; then
    echo "{}" > "$FILE"
  fi
}

remove_keys_from_json() {
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<PY
import json,sys
f='${FILE}'
try:
    with open(f,'r', encoding='utf-8') as fh:
        data=json.load(fh)
except Exception:
    data={}
for k in ('rate_limiting','limit','window_seconds'):
    if k in data: data.pop(k)
with open(f,'w', encoding='utf-8') as fh:
    json.dump(data, fh, indent=2)
PY
    return $?
  elif command -v python >/dev/null 2>&1; then
    python - <<PY
import json,sys
f='${FILE}'
try:
    with open(f,'r', encoding='utf-8') as fh:
        data=json.load(fh)
except Exception:
    data={}
for k in ('rate_limiting','limit','window_seconds'):
    if k in data: data.pop(k)
with open(f,'w', encoding='utf-8') as fh:
    json.dump(data, fh, indent=2)
PY
    return $?
  elif command -v jq >/dev/null 2>&1; then
    tmp=$(mktemp)
    jq 'del(.rate_limiting, .limit, .window_seconds)' "$FILE" > "$tmp" && mv "$tmp" "$FILE"
    return $?
  else
    tmp=$(mktemp)
    perl -0777 -pe '
      s/,\s*"rate_limiting"\s*:\s*(?:true|false)\s*//s;
      s/"rate_limiting"\s*:\s*(?:true|false)\s*,\s*//s;
      s/,\s*"limit"\s*:\s*\d+\s*//s;
      s/"limit"\s*:\s*\d+\s*,\s*//s;
      s/,\s*"window_seconds"\s*:\s*\d+\s*//s;
      s/"window_seconds"\s*:\s*\d+\s*,\s*//s;
      s/,\s*}/}/s;
      s/{\s*,/{/s;
      s/,\s*,+/,/g;
    ' "$FILE" > "$tmp" && mv "$tmp" "$FILE"
    ensure_json_minimal
    return $?
  fi
}

while true; do
  echo ""
  echo "=== Rate Limiting Manager ==="
  echo "1) Start rate limiting"
  echo "2) Stop rate limiting (set rate_limiting=false if true)"
  echo "3) Set custom limit & window (window is in seconds)"
  echo "4) Exit"
  read -p "Choose an option [1-4]: " opt

  case "$opt" in
    1)
      echo ""
      read -p "Use default values? (limit=${DEFAULT_LIMIT}, window=${DEFAULT_WINDOW}s) [y/N]: " yn
      if [[ "$yn" =~ ^[Yy]$ ]]; then
        limit=$DEFAULT_LIMIT
        window=$DEFAULT_WINDOW
      else
        read -p "Enter limit (number of requests allowed): " limit
        read -p "Enter window in seconds (e.g. 120): " window
      fi

      if ! [[ "$limit" =~ ^[0-9]+$ ]] || ! [[ "$window" =~ ^[0-9]+$ ]]; then
        echo "Invalid input. Limit and window must be positive integers."
      else
        cat > "$FILE" <<EOF
{
  "rate_limiting": true,
  "limit": $limit,
  "window_seconds": $window
}
EOF
        echo "Rate limiting ENABLED: limit=$limit, window=${window}s"
        echo "NOTE: You must restart your application for this change to take effect."
      fi
      ;;
    2)
      echo ""
      if [ -f "$FILE" ]; then
        if grep -q '"rate_limiting"\s*:\s*true' "$FILE"; then
          sed -i.bak -E 's/("rate_limiting"\s*:\s*)true/\1false/' "$FILE"
          echo "Rate limiting DISABLED in $FILE."
          rm -f "$FILE.bak"
        else
          echo "Rate limiting already false or absent."
        fi
      else
        echo "$FILE does not exist. Creating default with rate_limiting=false."
        cat > "$FILE" <<EOF
{
  "rate_limiting": false,
  "limit": $DEFAULT_LIMIT,
  "window_seconds": $DEFAULT_WINDOW
}
EOF
      fi
      ;;
    3)
      echo ""
      echo "Set custom values. Window is specified in SECONDS (e.g. 120 = 2 minutes)."
      read -p "Enter new limit (number of requests allowed, leave empty to keep current): " newlimit
      read -p "Enter new window in seconds (leave empty to keep current): " newwindow

      cur_flag=$(json_read_rate_flag)
      if [ "$cur_flag" = "true" ]; then
        rl_state=true
      elif [ "$cur_flag" = "false" ]; then
        rl_state=false
      else
        rl_state= # absent
      fi

      cur_limit=$(json_read_number "limit")
      cur_window=$(json_read_number "window_seconds")
      if ! [[ "$cur_limit" =~ ^[0-9]+$ ]]; then cur_limit=$DEFAULT_LIMIT; fi
      if ! [[ "$cur_window" =~ ^[0-9]+$ ]]; then cur_window=$DEFAULT_WINDOW; fi

      if [[ -z "$newlimit" ]]; then
        final_limit=$cur_limit
      else
        if ! [[ "$newlimit" =~ ^[0-9]+$ ]]; then
          echo "Invalid limit. Must be a positive integer. Aborting change."
          continue
        fi
        final_limit=$newlimit
      fi

      if [[ -z "$newwindow" ]]; then
        final_window=$cur_window
      else
        if ! [[ "$newwindow" =~ ^[0-9]+$ ]]; then
          echo "Invalid window. Must be a positive integer number of seconds. Aborting change."
          continue
        fi
        final_window=$newwindow
      fi

      if [ "$rl_state" = "true" ]; then
        cat > "$FILE" <<EOF
{
  "rate_limiting": true,
  "limit": $final_limit,
  "window_seconds": $final_window
}
EOF
      elif [ "$rl_state" = "false" ]; then
        cat > "$FILE" <<EOF
{
  "rate_limiting": false,
  "limit": $final_limit,
  "window_seconds": $final_window
}
EOF
      else
        cat > "$FILE" <<EOF
{
  "limit": $final_limit,
  "window_seconds": $final_window
}
EOF
      fi

      echo "Updated $FILE with limit=$final_limit and window=${final_window}s."
      echo "Note: rate_limiting flag was preserved as: ${rl_state:-'absent'}."
      echo "If you changed the limit/window and want them active, ensure rate_limiting=true (use option 1)."
      ;;
    4)
      echo "Exit."
      exit 0
      ;;
    *)
      echo "Invalid option."
      ;;
  esac
done
