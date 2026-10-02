#!/usr/bin/env python3
"""End-to-end tests against a real Kong Gateway in DB-less mode.

Starts an echo upstream and Kong (two workers) with this plugin, generates the
fixture databases, and checks enrichment, spoofing protection, client-IP
handling, policy, routing on enrichment headers, failure handling and database
updates.

usage: spec/e2e/e2e.py            (run from the repository root)
       E2E_SLOW=1 spec/e2e/e2e.py also exercises database_refresh_interval
                                  (waits ~80 seconds)
Requires: kong and resty on PATH (a Kong package install), python3.
"""
import http.client
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PROXY = "http://127.0.0.1:18000"
UPSTREAM_PORT = 18999

# The header-smuggling test sends more headers than http.server accepts by default.
http.client._MAXHEADERS = 1000

results = []


class Echo(http.server.BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        Echo.hits += 1
        body = json.dumps({
            "path": self.path,
            "headers": [[k.lower(), v] for k, v in self.headers.items()],
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_echo():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", UPSTREAM_PORT), Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def request(path, headers=None):
    req = urllib.request.Request(PROXY + path, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}"), dict(r.headers)
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            body = json.loads(body)
        except ValueError:
            body = body.decode(errors="replace")
        return e.code, body, dict(e.headers)


def upstream_headers(body):
    out = {}
    if not isinstance(body, dict):
        return {"__non_json_body__": [str(body)[:200]]}
    for k, v in body.get("headers", []):
        out.setdefault(k, []).append(v)
    return out


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  -> " + str(detail)))


def build_fixtures(dbdir):
    lua = ('local fx = require "spec.ipgeolocation.fixtures"; '
           'for k, v in pairs(fx.build_all("%s")) do print(k, v) end') % dbdir
    subprocess.run(["resty", "-I", REPO, "-e", lua], check=True, capture_output=True)


def write_location(path, country_code):
    lua = ('local W = require "spec.ipgeolocation.mmdb_writer"; local w = W.new(); '
           'w:insert("203.0.113.0/24", { location = { country = { code2 = "%s" }, city = { name = { en = "Updated" } } } }); '
           'w:write("%s")') % (country_code, path)
    subprocess.run(["resty", "-I", REPO, "-e", lua], check=True, capture_output=True)


def declarative(db, extra_route_plugins):
    loc, asn, sec = db + "/location.mmdb", db + "/asn.mmdb", db + "/security.mmdb"
    route_plugin = lambda conf: [{"name": "ipgeolocation", "config": conf}]
    services = [
        {"name": "echo", "url": "http://127.0.0.1:%d" % UPSTREAM_PORT, "routes": [
            {"name": "enrich", "paths": ["/enrich"], "plugins": route_plugin(
                {"databases": [loc, asn, sec], "headers": {"preset": "standard"}})},
            {"name": "block", "paths": ["/block"], "plugins": route_plugin(
                {"databases": [loc, asn, sec],
                 "policy": {"block_tor": True, "block_known_attacker": True, "block_threat_score_above": 80}})},
            {"name": "dryrun", "paths": ["/dryrun"], "plugins": route_plugin(
                {"databases": [loc, sec], "policy": {"block_vpn": True, "dry_run": True}})},
            {"name": "countries", "paths": ["/countries"], "plugins": route_plugin(
                {"databases": [loc], "policy": {"allowed_countries": ["DE", "US"], "status_code": 451,
                                                 "message": "Not available in your region"}})},
            {"name": "failclosed", "paths": ["/failclosed"], "plugins": route_plugin(
                {"databases": ["/nonexistent/db-ip-security.mmdb"], "policy": {"fail_open": False}})},
            {"name": "failopen", "paths": ["/failopen"], "plugins": route_plugin(
                {"databases": ["/nonexistent/db-ip-security.mmdb", loc], "policy": {"block_tor": True}})},
            {"name": "custom", "paths": ["/custom"], "plugins": route_plugin(
                {"databases": [loc, sec], "headers": {"preset": "none", "boolean_format": "one_zero",
                                                     "custom": {"X-Country": "country_code", "X-VPN": "is_vpn"}}})},
            {"name": "refresh", "paths": ["/refresh"], "plugins": route_plugin(
                {"databases": [db + "/refresh.mmdb"], "database_refresh_interval": 60})},
            {"name": "logged", "paths": ["/logged"], "plugins": [
                {"name": "ipgeolocation", "config": {"databases": [loc, sec], "log_serialize": True}},
                {"name": "file-log", "config": {"path": db + "/access.log"}},
            ]},
            {"name": "interop", "paths": ["/interop"], "plugins": [
                {"name": "ipgeolocation", "config": {"databases": [loc, asn, sec], "headers": {"preset": "standard"}}},
                {"name": "request-transformer", "config": {"rename": {"headers": ["X-IPGeo-City-Name:X-City"]}}},
                {"name": "post-function", "config": {"access": [
                    "local r = kong.ctx.shared.ipgeolocation "
                    "kong.service.request.set_header('X-From-Ctx', r and r.fields.country_code or 'none')"]}},
            ]},
            {"name": "ratelimit", "paths": ["/ratelimit"], "plugins": [
                {"name": "ipgeolocation", "config": {"databases": [loc]}},
                {"name": "rate-limiting", "config": {"minute": 2, "limit_by": "header",
                                                     "header_name": "X-IPGeo-Country-Code", "policy": "local"}},
            ]},
            {"name": "geo-default", "paths": ["/geo"]},
        ] + extra_route_plugins},
        {"name": "echo-de", "url": "http://127.0.0.1:%d/routed-de" % UPSTREAM_PORT, "routes": [
            {"name": "geo-de", "paths": ["/geo"], "headers": {"x-ipgeo-country-code": ["DE"]}},
        ]},
    ]
    return {
        "_format_version": "3.0",
        "services": services,
        # Global instance: runs in rewrite, so the router can match on its headers.
        "plugins": [{"name": "ipgeolocation", "config": {"databases": [loc, asn, sec]}}],
    }


def start_kong(work, trusted):
    env = dict(os.environ)
    env.update({
        "KONG_PREFIX": work + "/prefix",
        "KONG_DATABASE": "off",
        "KONG_DECLARATIVE_CONFIG": work + "/kong.yml",
        "KONG_PLUGINS": "bundled,ipgeolocation",
        "KONG_LUA_PACKAGE_PATH": REPO + "/?.lua;;",
        "KONG_PROXY_LISTEN": "127.0.0.1:18000",
        "KONG_ADMIN_LISTEN": "127.0.0.1:18001",
        "KONG_STATUS_LISTEN": "off",
        "KONG_UNTRUSTED_LUA": "on",
        "KONG_NGINX_WORKER_PROCESSES": "2",
        "KONG_LOG_LEVEL": "info",
        "KONG_PROXY_ERROR_LOG": work + "/error.log",
        "KONG_ADMIN_ERROR_LOG": work + "/error.log",
    })
    if trusted:
        env.update({"KONG_TRUSTED_IPS": "127.0.0.1,::1", "KONG_REAL_IP_HEADER": "X-Forwarded-For",
                    "KONG_REAL_IP_RECURSIVE": "on"})
    out = subprocess.run(["kong", "start"], env=env, capture_output=True, text=True)
    if out.returncode != 0:
        print(out.stdout, out.stderr)
        sys.exit(2)
    for _ in range(50):
        try:
            urllib.request.urlopen("http://127.0.0.1:18001/status", timeout=1)
            break
        except Exception:
            time.sleep(0.2)
    time.sleep(0.5)
    return env


def stop_kong(env):
    subprocess.run(["kong", "stop"], env=env, capture_output=True)


def xff(ip, **extra):
    h = {"X-Forwarded-For": ip}
    h.update(extra)
    return h


def main():
    if not shutil.which("kong") or not shutil.which("resty"):
        print("kong and resty must be on PATH")
        sys.exit(2)
    os.chdir(REPO)
    work = tempfile.mkdtemp(prefix="ipgeo-e2e-")
    # Kong's workers run as the unprivileged nginx_user: everything they read
    # (prefix, databases) must be reachable by that user.
    os.chmod(work, 0o755)
    db = work + "/db"
    os.makedirs(db)
    os.chmod(db, 0o755)
    open(db + "/access.log", "w").close()
    os.chmod(db + "/access.log", 0o666)  # written by the unprivileged worker
    build_fixtures(db)
    write_location(db + "/refresh.mmdb", "AA")
    with open(work + "/kong.yml", "w") as f:
        json.dump(declarative(db, []), f)   # JSON is valid YAML
    start_echo()

    # ------------------------------------------------------------------
    print("== Kong with trusted proxy 127.0.0.1 (real_ip_header X-Forwarded-For, recursive)")
    env = start_kong(work, trusted=True)
    try:
        s, b, _ = request("/enrich", xff("203.0.113.5"))
        h = upstream_headers(b)
        check("enrichment: country", s == 200 and h.get("x-ipgeo-country-code") == ["PK"], (s, h))
        check("enrichment: city", h.get("x-ipgeo-city-name") == ["Lahore"], h)
        check("enrichment: ASN", h.get("x-ipgeo-asn") == ["AS64500"], h)
        check("enrichment: time zone and coordinates",
              h.get("x-ipgeo-time-zone") == ["Asia/Karachi"] and h.get("x-ipgeo-latitude") == ["31.54972"], h)
        check("enrichment: no security record means no security headers", "x-ipgeo-is-tor" not in h, h)

        s, b, _ = request("/enrich", xff("203.0.113.5", **{
            "X-IPGeo-Country-Code": "US", "X-IPGeo-City-Name": "Springfield", "X_IPGeo_Is_VPN": "false",
            "x-ipgeo-is-known-attacker": "false", "X-IPGeo-Dry-Run": "x"}))
        h = upstream_headers(b)
        check("spoofing: client X-IPGeo-Country-Code: US replaced with PK", h.get("x-ipgeo-country-code") == ["PK"], h)
        check("spoofing: client city replaced", h.get("x-ipgeo-city-name") == ["Lahore"], h)
        check("spoofing: underscore variant removed", "x_ipgeo_is_vpn" not in h, h)
        check("spoofing: headers this route does not set are removed too",
              "x-ipgeo-is-known-attacker" not in h and "x-ipgeo-dry-run" not in h, h)

        many = {"X-Filler-%03d" % i: "v" for i in range(150)}
        many["X-IPGeo-Is-Tor"] = "false"
        s, b, _ = request("/enrich", xff("203.0.113.5", **many))
        h = upstream_headers(b)
        check("spoofing: header hidden behind 150 others is still removed", "x-ipgeo-is-tor" not in h, len(h))

        s, b, _ = request("/enrich", xff("198.51.100.7, 203.0.113.5"))
        h = upstream_headers(b)
        check("client IP: Kong's recursive real-IP ignores the spoofed left-most X-Forwarded-For entry",
              h.get("x-ipgeo-country-code") == ["PK"], h)

        s, b, _ = request("/enrich", xff("2001:db8:1::abcd"))
        h = upstream_headers(b)
        check("IPv6 enrichment", h.get("x-ipgeo-country-code") == ["JP"] and h.get("x-ipgeo-asn") == ["AS64503"], h)

        s, b, _ = request("/enrich", xff("::ffff:203.0.113.5"))
        h = upstream_headers(b)
        check("IPv4-mapped IPv6 client looked up as IPv4", h.get("x-ipgeo-country-code") == ["PK"], h)

        s, b, _ = request("/enrich")
        h = upstream_headers(b)
        check("private client (no X-Forwarded-For): no lookup, no headers",
              s == 200 and not any(k.startswith("x-ipgeo-") for k in h), h)

        before = Echo.hits
        s, b, rh = request("/block", xff("203.0.113.10"))
        check("policy: Tor exit node blocked with 403", s == 403, (s, b))
        # Kong 3.x adds a request_id to its error bodies; nothing else may appear.
        check("policy: generic message, no reason disclosed",
              isinstance(b, dict) and b.get("message") == "Access denied"
              and set(b) <= {"message", "request_id"} and "Tor" not in json.dumps(b), b)
        check("policy: blocked request never reached the upstream", Echo.hits == before, Echo.hits - before)
        s, _, _ = request("/block", xff("203.0.113.13"))
        check("policy: known attacker blocked", s == 403, s)
        s, _, _ = request("/block", xff("203.0.113.20"))
        check("policy: threat score 85 > 80 blocked", s == 403, s)
        s, _, _ = request("/block", xff("203.0.113.11"))
        check("policy: VPN with score 60 allowed (block_vpn off)", s == 200, s)
        s, _, _ = request("/block", xff("203.0.113.200"))
        check("policy: address without a security record is not blocked", s == 200, s)
        s, _, _ = request("/block", xff("2001:db8:1::10"))
        check("policy: IPv6 Tor exit node blocked", s == 403, s)

        s, b, _ = request("/dryrun", xff("203.0.113.11"))
        h = upstream_headers(b)
        check("dry run: request passes with X-IPGeo-Dry-Run reason",
              s == 200 and h.get("x-ipgeo-dry-run") == ["address is flagged as a VPN"], (s, h))

        s, b, _ = request("/countries", xff("203.0.113.5"))
        check("allowed_countries: PK refused with configured 451 and message",
              s == 451 and isinstance(b, dict) and b.get("message") == "Not available in your region", (s, b))
        s, _, _ = request("/countries", xff("198.51.100.7"))
        check("allowed_countries: DE allowed", s == 200, s)

        s, _, _ = request("/failclosed", xff("203.0.113.5"))
        check("fail_open false: missing database blocks", s == 403, s)
        s, b, _ = request("/failopen", xff("203.0.113.5"))
        h = upstream_headers(b)
        check("fail_open true: missing database still enriches from the others",
              s == 200 and h.get("x-ipgeo-country-code") == ["PK"], (s, h))

        s, b, _ = request("/custom", xff("203.0.113.11", **{"X-Country": "US"}))
        h = upstream_headers(b)
        check("custom header names and one_zero booleans",
              h.get("x-country") == ["PK"] and h.get("x-vpn") == ["1"] and "x-ipgeo-country-code" not in h, h)

        s, b, _ = request("/geo", xff("198.51.100.7"))
        check("routing: global rewrite enrichment lets Kong's router send DE to its own service",
              s == 200 and b.get("path", "").startswith("/routed-de"), b.get("path"))
        s, b, _ = request("/geo", xff("203.0.113.5"))
        # strip_path is on by default, so the default route forwards "/".
        check("routing: other countries use the default route", s == 200 and b.get("path") == "/", b.get("path"))
        s, b, _ = request("/geo", xff("203.0.113.5", **{"X-IPGeo-Country-Code": "DE"}))
        check("routing: a spoofed country header cannot steer routing",
              s == 200 and b.get("path") == "/", b.get("path"))

        request("/logged", xff("203.0.113.9"))
        time.sleep(1)
        entries = [json.loads(line) for line in open(db + "/access.log") if line.strip()]
        g = entries[-1].get("ipgeolocation", {}) if entries else {}
        check("interop: file-log receives the lookup result through log_serialize",
              g.get("ip") == "203.0.113.9" and (g.get("fields") or {}).get("country_code") == "PK", g)

        s, b, _ = request("/interop", xff("203.0.113.5"))
        h = upstream_headers(b)
        check("interop: request-transformer (runs later) sees and renames the enrichment headers",
              h.get("x-city") == ["Lahore"] and "x-ipgeo-city-name" not in h, h)
        check("interop: another plugin reads kong.ctx.shared.ipgeolocation", h.get("x-from-ctx") == ["PK"], h)

        codes = [request("/ratelimit", xff("203.0.113.%d" % i))[0] for i in (1, 2, 3)]
        de = request("/ratelimit", xff("198.51.100.7"))[0]
        check("interop: rate-limiting keyed on X-IPGeo-Country-Code limits per country",
              codes == [200, 200, 429] and de == 200, (codes, de))

        statuses = set()
        for i in range(200):
            s, _, _ = request("/enrich", xff("203.0.113.%d" % (i % 250 + 1)))
            statuses.add(s)
        check("200 requests across two workers", statuses == {200}, statuses)

        # Database update procedure: atomic rename + kong reload.
        write_location(db + "/location.mmdb.tmp", "ZZ")
        os.rename(db + "/location.mmdb.tmp", db + "/location.mmdb")
        subprocess.run(["kong", "reload"], env=env, capture_output=True)
        time.sleep(2)
        s, b, _ = request("/enrich", xff("203.0.113.5"))
        h = upstream_headers(b)
        check("update: atomic rename + kong reload serves the new release", h.get("x-ipgeo-country-code") == ["ZZ"], h)

        if os.environ.get("E2E_SLOW"):
            s, b, _ = request("/refresh", xff("203.0.113.5"))
            first = upstream_headers(b).get("x-ipgeo-country-code")
            write_location(db + "/refresh.mmdb.tmp", "BB")
            os.rename(db + "/refresh.mmdb.tmp", db + "/refresh.mmdb")
            time.sleep(80)
            seen = set()
            for _ in range(10):
                s, b, _ = request("/refresh", xff("203.0.113.5"))
                seen.update(upstream_headers(b).get("x-ipgeo-country-code") or [])
            check("refresh: database_refresh_interval picks up an atomically replaced file without reload",
                  first == ["AA"] and seen == {"BB"}, (first, seen))

        log = open(work + "/error.log").read()
        check("log: databases loaded in every worker", log.count("[ipgeolocation] loaded") >= 2,
              log.count("[ipgeolocation] loaded"))
        check("log: missing database reported", "is unavailable" in log)
        check("log: blocks logged with reason", "address is flagged as a Tor exit node" in log)
        lua_errors = [l for l in log.splitlines() if "[error]" in l and "ipgeolocation" in l
                      and "is unavailable" not in l]
        check("log: no unexpected plugin errors", not lua_errors, lua_errors[:3])
    finally:
        stop_kong(env)

    # ------------------------------------------------------------------
    print("== Kong without trusted proxies (the default)")
    with open(work + "/kong.yml", "w") as f:
        json.dump(declarative(db, []), f)
    env = start_kong(work, trusted=False)
    try:
        s, b, _ = request("/enrich", xff("203.0.113.5"))
        h = upstream_headers(b)
        check("untrusted X-Forwarded-For is ignored: client stays 127.0.0.1 (private, no headers)",
              s == 200 and "x-ipgeo-country-code" not in h, h)
        s, _, _ = request("/block", xff("203.0.113.10"))
        check("untrusted X-Forwarded-For cannot change the identity used for policy", s == 200, s)
    finally:
        stop_kong(env)

    failed = [n for n, ok in results if not ok]
    print("\n%d checks, %d failed" % (len(results), len(failed)))
    shutil.rmtree(work, ignore_errors=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
