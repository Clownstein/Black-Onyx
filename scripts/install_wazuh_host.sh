#!/usr/bin/env bash
# Install a real Wazuh manager on this host and attach the Black Onyx shipper.
# Invoked by scripts/bootstrap_full_stack.sh when INSTALL_WAZUH=1 (default).
#
# Security posture:
#   - wazuh-manager comes from the GPG-signed packages.wazuh.com repository and
#     the signing key fingerprint is pinned (no curl | bash installer).
#   - The default Wazuh API credentials are rotated to generated passwords.
#   - Agent enrollment (authd, 1515/tcp) requires a registration password.
#   - Secrets move through environment variables, never argv.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT/.env}"
WAZUH_REPO_MAJOR="${WAZUH_REPO_MAJOR:-4.x}"
WAZUH_GPG_FINGERPRINT="${WAZUH_GPG_FINGERPRINT:-0DCFCA5547B19D2A6099506096B3EE5F29111145}"
WAZUH_API_URL="${WAZUH_API_URL:-https://127.0.0.1:55000}"
WAZUH_API_CERT="/var/ossec/api/configuration/ssl/server.crt"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
AUTHD_PASS="/var/ossec/etc/authd.pass"
SHIPPER_ENV="/etc/black-onyx-shipper/shipper.env"

if [[ "${INSTALL_WAZUH:-1}" != "1" ]]; then
  echo "INSTALL_WAZUH is not 1; skipping host Wazuh install"
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Wazuh host install needs root. Re-run: sudo INSTALL_WAZUH=1 $0" >&2
  exit 1
fi

for tool in curl gpg python3 systemctl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool is required" >&2; exit 1; }
done

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

# set_kv FILE KEY value comes from $KV_VALUE so secrets never hit argv.
# Rewrites in place, preserving the file's owner and mode (new files are 0600).
set_kv() {
  FILE="$1" KEY="$2" python3 - <<'PY'
import os, re, stat
path, key, value = os.environ["FILE"], os.environ["KEY"], os.environ.get("KV_VALUE", "")
if "\n" in value:
    raise SystemExit(f"refusing multi-line value for {key}")
exists = os.path.exists(path)
lines = open(path, encoding="utf-8").read().splitlines() if exists else []
pattern = re.compile(rf"^{re.escape(key)}=")
out, done = [], False
for line in lines:
    if pattern.match(line):
        if not done:
            out.append(f"{key}={value}")
            done = True
        continue
    out.append(line)
if not done:
    out.append(f"{key}={value}")
st = os.stat(path) if exists else None
tmp = f"{path}.tmp-{os.getpid()}"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IMODE(st.st_mode) if st else 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    fh.write("\n".join(out) + "\n")
if st:
    os.chown(tmp, st.st_uid, st.st_gid)
os.replace(tmp, path)
PY
}

# Wazuh passwords need 8-64 chars with upper, lower, digit and symbol.
gen_wazuh_password() {
  python3 - <<'PY'
import secrets, string
alphabet = string.ascii_letters + string.digits + ".*+?-_"
while True:
    pw = "".join(secrets.choice(alphabet) for _ in range(32))
    if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw) and any(c in ".*+?-_" for c in pw)):
        print(pw)
        break
PY
}

install_manager_package() {
  if [[ -x /var/ossec/bin/wazuh-control ]]; then
    echo "Wazuh manager already installed"
    return
  fi
  local key_tmp
  key_tmp="$(mktemp)"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$key_tmp" https://packages.wazuh.com/key/GPG-KEY-WAZUH
  local fpr
  fpr="$(gpg --show-keys --with-colons "$key_tmp" | awk -F: '/^fpr/ {print $10; exit}')"
  if [[ "$fpr" != "$WAZUH_GPG_FINGERPRINT" ]]; then
    echo "ERROR: Wazuh signing key fingerprint mismatch (got ${fpr:-none})" >&2
    rm -f "$key_tmp"
    exit 1
  fi
  if command -v apt-get >/dev/null 2>&1; then
    gpg --dearmor < "$key_tmp" > /usr/share/keyrings/wazuh.gpg
    chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/${WAZUH_REPO_MAJOR}/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      "wazuh-manager${WAZUH_VERSION:+=${WAZUH_VERSION}-1}"
  elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    install -m 0644 "$key_tmp" /etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH
    rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH
    cat > /etc/yum.repos.d/wazuh.repo <<EOF
[wazuh]
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/${WAZUH_REPO_MAJOR}/yum/
protect=1
EOF
    local pm
    pm="$(command -v dnf || command -v yum)"
    "$pm" install -y "wazuh-manager${WAZUH_VERSION:+-${WAZUH_VERSION}}"
  else
    echo "ERROR: unsupported package manager (need apt-get, dnf or yum)" >&2
    rm -f "$key_tmp"
    exit 1
  fi
  rm -f "$key_tmp"
  systemctl daemon-reload
  systemctl enable --now wazuh-manager
}

configure_enrollment_password() {
  local reg_pass="${WAZUH_REGISTRATION_PASSWORD:-}"
  if [[ -z "$reg_pass" ]]; then
    reg_pass="$(gen_wazuh_password)"
    KV_VALUE="$reg_pass" set_kv "$ENV_FILE" WAZUH_REGISTRATION_PASSWORD
  fi
  umask 027
  printf '%s\n' "$reg_pass" > "$AUTHD_PASS"
  chown root:wazuh "$AUTHD_PASS"
  chmod 640 "$AUTHD_PASS"
  # Require the password for authd enrollment.
  python3 - "$OSSEC_CONF" <<'PY'
import re, sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
auth = re.search(r"<auth>.*?</auth>", text, flags=re.S)
if not auth:
    raise SystemExit("ossec.conf has no <auth> section")
block = auth.group(0)
if re.search(r"<use_password>\s*\w+\s*</use_password>", block):
    new = re.sub(r"<use_password>\s*\w+\s*</use_password>", "<use_password>yes</use_password>", block)
else:
    new = block.replace("</auth>", "  <use_password>yes</use_password>\n  </auth>")
open(path, "w", encoding="utf-8").write(text.replace(block, new))
PY
  export WAZUH_REGISTRATION_PASSWORD="$reg_pass"
}

# Rotate default API credentials (wazuh/wazuh, wazuh-wui/wazuh-wui) and verify.
# The API's self-signed certificate is used as the trust anchor (pinned).
rotate_api_credentials() {
  local new_api new_wui
  new_api="${WAZUH_API_PASSWORD:-}"
  new_wui=""
  if [[ -z "$new_api" ]]; then
    new_api="$(gen_wazuh_password)"
    new_wui="$(gen_wazuh_password)"
  fi
  WAZUH_API_URL="$WAZUH_API_URL" WAZUH_API_CERT="$WAZUH_API_CERT" \
    NEW_API_PASSWORD="$new_api" NEW_WUI_PASSWORD="$new_wui" \
    WAZUH_API_USER="${WAZUH_API_USER:-wazuh}" python3 - <<'PY'
import base64, json, os, ssl, sys, time, urllib.error, urllib.request

base = os.environ["WAZUH_API_URL"].rstrip("/")
ctx = ssl.create_default_context(cafile=os.environ["WAZUH_API_CERT"])
ctx.check_hostname = False  # self-signed cert pinned as the only trust anchor
user = os.environ["WAZUH_API_USER"]
new_api = os.environ["NEW_API_PASSWORD"]
new_wui = os.environ.get("NEW_WUI_PASSWORD", "")

def request(method, path, *, token=None, basic=None, body=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if basic:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        return json.loads(resp.read() or b"{}")

def token_for(name, password):
    try:
        return request("POST", "/security/user/authenticate", basic=(name, password))["data"]["token"]
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return None
        raise

for _ in range(60):
    try:
        request("GET", "/")
        break
    except urllib.error.HTTPError:
        break  # API is answering (401 without auth)
    except (urllib.error.URLError, ConnectionError, TimeoutError):
        time.sleep(2)
else:
    sys.exit("Wazuh API did not become reachable")

if token_for(user, new_api):
    print("Wazuh API credentials already valid")
    sys.exit(0)
if not new_wui:
    sys.exit("WAZUH_API_PASSWORD in .env is rejected by the Wazuh API; fix it or clear it to rotate")
token = token_for("wazuh", "wazuh")
if not token:
    sys.exit("default Wazuh API credentials were already changed; set WAZUH_API_PASSWORD in .env")
users = request("GET", "/security/users", token=token)["data"]["affected_items"]
ids = {u["username"]: u["id"] for u in users}
for name, password in (("wazuh-wui", new_wui), ("wazuh", new_api)):
    if name in ids:
        request("PUT", f"/security/users/{ids[name]}", token=token, body={"password": password})
if not token_for("wazuh", new_api):
    sys.exit("rotated Wazuh API password did not verify")
print("Rotated Wazuh API credentials")
PY
  KV_VALUE="$new_api" set_kv "$ENV_FILE" WAZUH_API_PASSWORD
  if [[ -n "$new_wui" ]]; then
    KV_VALUE="$new_wui" set_kv "$ENV_FILE" WAZUH_WUI_PASSWORD
  fi
  export WAZUH_API_PASSWORD="$new_api"
}

install_manager_package
configure_enrollment_password
systemctl restart wazuh-manager
rotate_api_credentials

SHIPPER_SOURCES="${SHIPPER_SOURCES:-wazuh}" \
  WITH_INTEGRATOR="${WITH_INTEGRATOR:-false}" \
  bash "$ROOT/detection/collectors/wazuh/install-manager.sh"

mkdir -p /etc/black-onyx-shipper
if [[ ! -f "$SHIPPER_ENV" ]]; then
  install -m 0600 /dev/null "$SHIPPER_ENV"
fi

gateway_url="${BLACK_ONYX_COLLECTOR_GATEWAY_URL:-http://127.0.0.1:${INGEST_GATEWAY_HOST_PORT:-18090}}"
if [[ -n "${INGEST_GATEWAY_REMOTE_BIND:-}" && "${INGEST_GATEWAY_REMOTE_BIND}" != "127.0.0.1" ]]; then
  gateway_url="http://${INGEST_GATEWAY_REMOTE_BIND}:${INGEST_GATEWAY_REMOTE_PORT:-18091}"
fi
registry_url="${ASSET_REGISTRY_URL:-http://127.0.0.1:${ASSET_REGISTRY_HOST_PORT:-18081}}"
if [[ -n "${ASSET_REGISTRY_REMOTE_BIND:-}" && "${ASSET_REGISTRY_REMOTE_BIND}" != "127.0.0.1" ]]; then
  registry_url="http://${ASSET_REGISTRY_REMOTE_BIND}:${ASSET_REGISTRY_REMOTE_PORT:-18082}"
fi
tip_url="${BLACK_ONYX_URL:-http://127.0.0.1:${BLACK_ONYX_PORT:-8000}}"
tenant_id="${BLACK_ONYX_COLLECTOR_TENANT_ID:-${BLACK_ONYX_DETECTION_TENANT:-default}}"
api_keys="${API_KEYS:-}"
ingest_key="${BLACK_ONYX_COLLECTOR_INGEST_KEY:-${api_keys%%,*}}"
if [[ -z "$ingest_key" ]]; then
  echo "ERROR: BLACK_ONYX_COLLECTOR_INGEST_KEY / API_KEYS is unset in $ENV_FILE; the shipper cannot authenticate" >&2
  exit 1
fi
# Integrator mode pushes from integratord, so the shipper must not double-push.
wazuh_push="${SHIPPER_WAZUH_PUSH:-true}"
if [[ "${WITH_INTEGRATOR:-false}" == "true" ]]; then
  wazuh_push="false"
fi

KV_VALUE="${SHIPPER_SOURCES:-wazuh}" set_kv "$SHIPPER_ENV" SHIPPER_SOURCES
KV_VALUE="$tenant_id" set_kv "$SHIPPER_ENV" BLACK_ONYX_COLLECTOR_TENANT_ID
KV_VALUE="$gateway_url" set_kv "$SHIPPER_ENV" BLACK_ONYX_COLLECTOR_GATEWAY_URL
KV_VALUE="$ingest_key" set_kv "$SHIPPER_ENV" BLACK_ONYX_COLLECTOR_INGEST_KEY
KV_VALUE="$registry_url" set_kv "$SHIPPER_ENV" ASSET_REGISTRY_URL
KV_VALUE="${ASSET_REGISTRY_SERVICE_KEY:-}" set_kv "$SHIPPER_ENV" ASSET_REGISTRY_SERVICE_KEY
KV_VALUE="$WAZUH_API_URL" set_kv "$SHIPPER_ENV" WAZUH_API_URL
KV_VALUE="${WAZUH_API_USER:-wazuh}" set_kv "$SHIPPER_ENV" WAZUH_API_USER
KV_VALUE="$WAZUH_API_PASSWORD" set_kv "$SHIPPER_ENV" WAZUH_API_PASSWORD
KV_VALUE="$WAZUH_API_CERT" set_kv "$SHIPPER_ENV" WAZUH_API_CA_FILE
KV_VALUE="$tip_url" set_kv "$SHIPPER_ENV" BLACK_ONYX_URL
KV_VALUE="$wazuh_push" set_kv "$SHIPPER_ENV" SHIPPER_WAZUH_PUSH

# Create (or reuse) the push-only Wazuh connector in TIP and rotate its push
# token so the shipper can push alerts without an admin session.
if [[ -n "${BLACK_ONYX_ADMIN_EMAIL:-}" && -n "${BLACK_ONYX_ADMIN_PASSWORD:-}" ]]; then
  if connector_out="$(TIP_URL="$tip_url" TENANT_ID="$tenant_id" WAZUH_API_URL="$WAZUH_API_URL" python3 - <<'PY'
import http.cookiejar, json, os, sys, urllib.error, urllib.request

tip = os.environ["TIP_URL"].rstrip("/")
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
headers = {"Content-Type": "application/json", "Origin": tip}

def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(tip + path, data=data, method=method, headers=headers)
    with opener.open(req, timeout=20) as resp:
        return json.loads(resp.read() or b"null")

try:
    login = call("POST", "/api/v1/auth/login", {
        "email": os.environ["BLACK_ONYX_ADMIN_EMAIL"],
        "password": os.environ["BLACK_ONYX_ADMIN_PASSWORD"],
    })
    headers["X-CSRF-Token"] = login["csrf_token"]
    connector_id = next(
        (row["id"] for row in call("GET", "/api/v1/connectors") if row.get("connector_type") == "wazuh"),
        None,
    )
    if connector_id is None:
        connector_id = call("POST", "/api/v1/connectors", {
            "name": "wazuh-host",
            "connector_type": "wazuh",
            "base_url": os.environ["WAZUH_API_URL"],
            "tenant_id": os.environ["TENANT_ID"],
            "config": {"poll_enabled": False},
            "enabled": True,
        })["id"]
    token = call("POST", f"/api/v1/connectors/{connector_id}/push-token")["token"]
except (urllib.error.URLError, KeyError, TypeError) as exc:
    sys.exit(f"TIP connector setup failed: {exc}")
print(connector_id)
print(token)
PY
  )"; then
    connector_id="$(sed -n 1p <<<"$connector_out")"
    KV_VALUE="$connector_id" set_kv "$SHIPPER_ENV" BLACK_ONYX_CONNECTOR_ID
    KV_VALUE="$(sed -n 2p <<<"$connector_out")" set_kv "$SHIPPER_ENV" BLACK_ONYX_CONNECTOR_TOKEN
    unset connector_out
    echo "Wazuh connector $connector_id ready with a fresh push token"
  else
    echo "Could not create the Wazuh connector in TIP; add it from Detections" >&2
  fi
else
  echo "BLACK_ONYX_ADMIN_EMAIL/PASSWORD unset; add the Wazuh connector from Detections" >&2
fi

systemctl restart black-onyx-shipper
failed=0
systemctl is-active --quiet wazuh-manager || { echo "wazuh-manager is not active" >&2; failed=1; }
systemctl is-active --quiet black-onyx-shipper || { echo "black-onyx-shipper is not active" >&2; failed=1; }
if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

echo "Wazuh manager + shipper configured."
echo "Agents enroll against this host (1514/1515 tcp) with WAZUH_REGISTRATION_PASSWORD from $ENV_FILE;"
echo "they appear as wazuh:<agent_id> assets. See Assets → Endpoint / sensor enrollment."
