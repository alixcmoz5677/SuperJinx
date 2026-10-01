"""Zero-touch setup for PasarGuard on Railway. Idempotent: safe on every boot."""
import json, os, sys, time, urllib.error, urllib.parse, urllib.request

BASE = "http://127.0.0.1:8000"
DATA = "/var/lib/pasarguard"
DOMAIN = (os.getenv("PUBLIC_DOMAIN") or os.getenv("RAILWAY_PUBLIC_DOMAIN") or "").strip()
USER = os.environ["SUDO_USERNAME"]
PASS = os.environ["SUDO_PASSWORD"]
CORE_NAME, NODE_NAME, GROUP_NAME = "jinx-core", "jinx-local", "jinx-all"
TITLE = os.getenv("CONFIG_TITLE", "جینکس | 𝙎𝙪𝙥𝙚𝙧 𝗝𝗶𝗻𝗫")
GB = 1024 ** 3
DAY = 86400

# 5 inbounds, all plain behind Railway's TLS edge (443)
INBOUNDS = [
    ("JX-VLESS-WS",     "vless",  10001, "ws",          "/jx-vless-ws"),
    ("JX-VMESS-WS",     "vmess",  10002, "ws",          "/jx-vmess-ws"),
    ("JX-TROJAN-WS",    "trojan", 10003, "ws",          "/jx-trojan-ws"),
    ("JX-VLESS-HTTPUP", "vless",  10004, "httpupgrade", "/jx-vless-hu"),
    ("JX-VLESS-XHTTP",  "vless",  10005, "xhttp",       "/jx-vless-xh"),
]
TEMPLATES = [  # name, GB, days
    ("10GB - 30 روز", 10, 30), ("30GB - 30 روز", 30, 30), ("50GB - 30 روز", 50, 30),
    ("100GB - 30 روز", 100, 30), ("200GB - 60 روز", 200, 60), ("نامحدود - 30 روز", 0, 30),
]
FIRST_USER = os.getenv("FIRST_USER", "jinx_user1")
FIRST_USER_GB = int(os.getenv("FIRST_USER_GB", "50"))
FIRST_USER_DAYS = int(os.getenv("FIRST_USER_DAYS", "30"))

TOKEN = None

def log(*a): print("[bootstrap]", *a, flush=True)

def req(method, path, body=None, form=False, ok=(200, 201, 204)):
    url = BASE + path
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body).encode(); headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body).encode(); headers["Content-Type"] = "application/json"
    if TOKEN: headers["Authorization"] = f"Bearer {TOKEN}"
    r = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            raw = resp.read().decode()
            try: return resp.status, json.loads(raw) if raw.strip() else None
            except ValueError: return resp.status, raw
    except urllib.error.HTTPError as e:
        txt = e.read().decode(errors="ignore")
        try: return e.code, json.loads(txt)
        except Exception: return e.code, txt

def must(method, path, body=None):
    code, res = req(method, path, body)
    if code not in (200, 201, 204):
        raise RuntimeError(f"{method} {path} -> {code}: {res}")
    return res

def as_list(res, key):
    if isinstance(res, list): return res
    if isinstance(res, dict): return res.get(key) or []
    return []

def wait_panel():
    for _ in range(180):
        try:
            code, _ = req("GET", "/api/system")
            if code in (200, 401, 403): return
        except Exception: pass
        time.sleep(2)
    raise RuntimeError("panel did not come up")

def login():
    global TOKEN
    for _ in range(30):
        code, res = req("POST", "/api/admin/token", {"username": USER, "password": PASS}, form=True)
        if code == 200: TOKEN = res["access_token"]; return
        time.sleep(3)
    raise RuntimeError(f"login failed: {code} {res}")

def inbound(tag, proto, port, net, path):
    stream = {"network": net, "security": "none"}
    if net == "ws": stream["wsSettings"] = {"path": path}
    elif net == "httpupgrade": stream["httpupgradeSettings"] = {"path": path}
    elif net == "xhttp": stream["xhttpSettings"] = {"path": path, "mode": "auto"}
    settings = {"clients": []}
    if proto == "vless": settings["decryption"] = "none"
    return {"tag": tag, "listen": "127.0.0.1", "port": port, "protocol": proto,
            "settings": settings, "streamSettings": stream,
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}}

CORE_CONFIG = {
    "log": {"loglevel": "warning"},
    "dns": {"servers": ["https+local://1.1.1.1/dns-query", "8.8.8.8", "localhost"]},
    "inbounds": [inbound(*i) for i in INBOUNDS],
    "outbounds": [
        {"protocol": "freedom", "tag": "DIRECT", "settings": {"domainStrategy": "UseIPv4"}},
        {"protocol": "blackhole", "tag": "BLOCK"},
    ],
    "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
        {"type": "field", "ip": ["geoip:private"], "outboundTag": "BLOCK"},
        {"type": "field", "protocol": ["bittorrent"], "outboundTag": "BLOCK"},
    ]},
    "policy": {"levels": {"0": {"handshake": 4, "connIdle": 300, "uplinkOnly": 1, "downlinkOnly": 1, "bufferSize": 512}}},
}

def ensure_core():
    cores = as_list(must("GET", "/api/cores"), "cores")
    for c in cores:
        if c.get("name") == CORE_NAME:
            must("PUT", f"/api/core/{c['id']}?restart_nodes=true",
                 {"name": CORE_NAME, "config": CORE_CONFIG, "exclude_inbound_tags": [], "fallbacks_inbound_tags": []})
            log("core updated", c["id"]); return c["id"]
    c = must("POST", "/api/core", {"name": CORE_NAME, "config": CORE_CONFIG,
                                    "exclude_inbound_tags": [], "fallbacks_inbound_tags": []})
    log("core created", c["id"]); return c["id"]

def ensure_node(core_id):
    api_key = open(f"{DATA}/node_api_key").read().strip()
    cert = open(f"{DATA}/node-certs/cert.pem").read().strip()
    body = {"name": NODE_NAME, "address": "127.0.0.1", "port": 62050, "usage_coefficient": 1,
            "connection_type": "grpc", "server_ca": cert, "keep_alive": 60,
            "core_config_id": core_id, "api_key": api_key}
    for n in as_list(must("GET", "/api/nodes"), "nodes"):
        if n.get("name") == NODE_NAME:
            must("PUT", f"/api/node/{n['id']}", body); log("node updated"); return
    must("POST", "/api/node", body); log("node created")

def ensure_group():
    tags = [i[0] for i in INBOUNDS]
    for g in as_list(must("GET", "/api/groups"), "groups"):
        if g.get("name") == GROUP_NAME:
            must("PUT", f"/api/group/{g['id']}", {"name": GROUP_NAME, "inbound_tags": tags})
            return g["id"]
    g = must("POST", "/api/group", {"name": GROUP_NAME, "inbound_tags": tags})
    log("group created", g["id"]); return g["id"]

def ensure_hosts():
    if not DOMAIN:
        log("WARNING: no public domain yet (Settings > Networking > Generate Domain), hosts skipped"); return
    existing = as_list(must("GET", "/api/hosts"), "hosts")
    for idx, (tag, proto, port, net, path) in enumerate(INBOUNDS):
        body = {"remark": TITLE, "address": [DOMAIN], "inbound_tag": tag, "port": 443,
                "sni": [DOMAIN], "host": [DOMAIN], "path": path, "security": "tls",
                "alpn": ["http/1.1"], "fingerprint": "chrome", "priority": idx + 1,
                "is_disabled": False}
        if net == "xhttp":
            body["transport_settings"] = {"xhttp_settings": {"mode": "packet-up"}}
        mine = [h for h in existing if h.get("inbound_tag") == tag]
        if mine:
            must("PUT", f"/api/host/{mine[0]['id']}", {**body, "id": mine[0]["id"]})
            for extra in mine[1:]:  # remove auto-created duplicates
                req("DELETE", f"/api/host/{extra['id']}")
        else:
            must("POST", "/api/host/", body)
    log("5 hosts ready on", DOMAIN)

def ensure_settings():
    if not DOMAIN: return
    code, s = req("GET", "/api/settings")
    if code != 200 or not isinstance(s, dict) or "subscription" not in s:
        log("settings endpoint not as expected, skipped"); return
    sub = s["subscription"]
    sub["url_prefix"] = f"https://{DOMAIN}"
    sub["profile_title"] = TITLE
    sub["update_interval"] = 12
    code, res = req("PUT", "/api/settings", {"subscription": sub})
    log("subscription settings", "ok" if code in (200, 201) else f"skipped ({code})")

def ensure_templates(group_id):
    have = {t.get("name") for t in as_list(must("GET", "/api/user_templates"), "templates")}
    for name, gb, days in TEMPLATES:
        if name in have: continue
        must("POST", "/api/user_template", {"name": name, "data_limit": gb * GB, "expire_duration": days * DAY,
                                            "group_ids": [group_id], "status": "active",
                                            "data_limit_reset_strategy": "no_reset"})
    log("user templates ready")

def ensure_first_user(group_id):
    code, _ = req("GET", f"/api/user/{FIRST_USER}")
    if code == 200: return
    u = must("POST", "/api/user", {"username": FIRST_USER, "group_ids": [group_id], "status": "active",
                                   "data_limit": FIRST_USER_GB * GB,
                                   "expire": int(time.time()) + FIRST_USER_DAYS * DAY,
                                   "data_limit_reset_strategy": "no_reset", "note": "auto-created"})
    log("first user:", FIRST_USER, "sub:", u.get("subscription_url"))

def step(name, fn, *a):
    try: return fn(*a)
    except Exception as e: log(f"{name} failed: {e}")

def main():
    wait_panel(); login()
    core_id = ensure_core()
    time.sleep(2)
    step("node", ensure_node, core_id)
    gid = ensure_group()
    step("hosts", ensure_hosts)
    step("settings", ensure_settings)
    step("templates", ensure_templates, gid)
    step("first user", ensure_first_user, gid)
    log("DONE ->", f"https://{DOMAIN}/dashboard/" if DOMAIN else "generate a Railway domain")

if __name__ == "__main__":
    try: main()
    except Exception as e: log("FATAL", e); sys.exit(1)
