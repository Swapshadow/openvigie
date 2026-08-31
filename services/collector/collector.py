"""OpenVigie local collector: durable NVD/CISA cache with scheduled refresh."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.environ.get("OPENVIGIE_DB_PATH", "/data/openvigie.db")
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REFRESH_SECONDS = max(300, int(os.environ.get("OPENVIGIE_REFRESH_SECONDS", "900")))
HTTP_TIMEOUT = 25
MAX_RESULTS = 100
SAFE_TEXT = re.compile(r"^[\w .+()/,:-]*$", re.UNICODE)

database_lock = threading.Lock()
sync_locks: dict[str, threading.Lock] = {}
sync_locks_guard = threading.Lock()
kev_lock = threading.Lock()
kev_cache: tuple[float, dict[str, dict]] | None = None
nvd_rate_lock = threading.Lock()
last_nvd_request = 0.0


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=20)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA busy_timeout=20000")
    return connection


def initialize_database() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS monitored_queries (
              cache_key TEXT PRIMARY KEY,
              query_json TEXT NOT NULL,
              payload_json TEXT,
              last_attempt INTEGER,
              last_success INTEGER,
              next_refresh INTEGER NOT NULL DEFAULT 0,
              last_error TEXT
            )
            """
        )


def validate_text(value: str, maximum: int) -> str:
    value = value.strip()[:maximum]
    if not SAFE_TEXT.fullmatch(value):
        raise ValueError("Paramètre invalide")
    return value


def normalize_query(parameters: dict[str, list[str]]) -> dict[str, str]:
    def first(name: str, maximum: int = 100) -> str:
        return validate_text(parameters.get(name, [""])[0], maximum)

    query = {
        "vendor": first("vendor"),
        "product": first("product"),
        "version": first("version", 60),
        "part": first("part", 1) or "a",
        "cpeVendor": first("cpeVendor"),
        "cpeProduct": first("cpeProduct"),
    }
    if not query["vendor"] or not query["product"]:
        raise ValueError("vendor et product sont requis")
    if query["part"] not in {"a", "o", "h"}:
        query["part"] = "a"
    return query


def cache_key(query: dict[str, str]) -> str:
    canonical = json.dumps(query, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def fetch_json(url: str) -> dict:
    global last_nvd_request
    headers = {
        "Accept": "application/json",
        "User-Agent": "OpenVigie/0.3 (+https://github.com/Swapshadow/openvigie)",
    }
    if NVD_API_KEY and url.startswith(NVD_API):
        headers["apiKey"] = NVD_API_KEY
    if url.startswith(NVD_API):
        with nvd_rate_lock:
            minimum_interval = 0.7 if NVD_API_KEY else 6.2
            wait = minimum_interval - (time.monotonic() - last_nvd_request)
            if wait > 0:
                time.sleep(wait)
            last_nvd_request = time.monotonic()
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}")
        if int(response.headers.get("Content-Length", "0") or 0) > 15_000_000:
            raise RuntimeError("Réponse trop volumineuse")
        return json.loads(response.read(15_000_001))


def get_kev() -> dict[str, dict]:
    global kev_cache
    with kev_lock:
        if kev_cache and kev_cache[0] > time.time():
            return kev_cache[1]
        data = fetch_json(CISA_KEV_API)
        entries = {item["cveID"]: item for item in data.get("vulnerabilities", []) if item.get("cveID")}
        kev_cache = (time.time() + 3600, entries)
        return entries


def cpe_component(value: str) -> str:
    value = re.sub(r"\s+", "_", value.lower())
    return re.sub(r"([!\"#$%&'()+,/:;<=>?@\[\]^`{|}~])", r"\\\1", value)


def choose_metric(cve: dict) -> dict:
    metrics = cve.get("metrics", {})
    for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        candidates = metrics.get(name, [])
        if candidates:
            return candidates[0].get("cvssData", {})
    return {}


def normalize_cve(cve: dict, kev: dict[str, dict]) -> dict:
    metric = choose_metric(cve)
    descriptions = cve.get("descriptions", [])
    description = next((item.get("value") for item in descriptions if item.get("lang") == "fr"), None)
    description = description or next((item.get("value") for item in descriptions if item.get("lang") == "en"), None)
    weaknesses = []
    for weakness in cve.get("weaknesses", []):
        weaknesses.extend(item.get("value") for item in weakness.get("description", []) if item.get("lang") == "en")
    references = [
        {"url": item.get("url", ""), "source": item.get("source", "Source publique"), "tags": item.get("tags", [])}
        for item in cve.get("references", [])[:20]
        if item.get("url", "").startswith(("https://", "http://"))
    ]
    kev_entry = kev.get(cve.get("id", ""))
    normalized_kev = None
    if kev_entry:
        normalized_kev = {
            "dateAdded": kev_entry.get("dateAdded", ""),
            "dueDate": kev_entry.get("dueDate", ""),
            "requiredAction": kev_entry.get("requiredAction", ""),
            "knownRansomwareCampaignUse": kev_entry.get("knownRansomwareCampaignUse", "Unknown"),
        }
    return {
        "id": cve.get("id", "CVE inconnue"),
        "description": description or "Description non disponible.",
        "score": metric.get("baseScore"),
        "severity": metric.get("baseSeverity", "UNKNOWN"),
        "vector": metric.get("vectorString"),
        "attackVector": metric.get("attackVector"),
        "privilegesRequired": metric.get("privilegesRequired"),
        "userInteraction": metric.get("userInteraction"),
        "confidentialityImpact": metric.get("confidentialityImpact"),
        "integrityImpact": metric.get("integrityImpact"),
        "availabilityImpact": metric.get("availabilityImpact"),
        "weaknesses": list(dict.fromkeys(weaknesses)),
        "published": cve.get("published", ""),
        "lastModified": cve.get("lastModified", ""),
        "references": references,
        "kev": normalized_kev,
    }


def collect(query: dict[str, str]) -> dict:
    use_cpe = bool(query["cpeVendor"] and query["cpeProduct"] and query["version"])
    method = "cpe" if use_cpe else "keyword"
    cpe = ""
    if use_cpe:
        cpe = (
            f"cpe:2.3:{query['part']}:{cpe_component(query['cpeVendor'])}:"
            f"{cpe_component(query['cpeProduct'])}:{cpe_component(query['version'])}:*:*:*:*:*:*:*"
        )
    keyword = " ".join(value for value in (query["vendor"], query["product"], query["version"]) if value)

    def nvd_url(kind: str) -> str:
        parameter = {"resultsPerPage": str(MAX_RESULTS)}
        parameter["cpeName" if kind == "cpe" else "keywordSearch"] = cpe if kind == "cpe" else keyword
        return f"{NVD_API}?{urllib.parse.urlencode(parameter)}"

    nvd = fetch_json(nvd_url(method))
    if method == "cpe" and not nvd.get("totalResults", 0):
        method = "keyword"
        nvd = fetch_json(nvd_url(method))

    sources = [{
        "name": "NVD / NIST", "status": "online", "url": "https://nvd.nist.gov/",
        "detail": "Correspondance CPE et version exacte" if method == "cpe" else "Recherche textuelle de repli à vérifier",
    }]
    try:
        kev = get_kev()
        sources.append({"name": "CISA KEV", "status": "online", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "detail": "Catalogue des vulnérabilités exploitées"})
    except Exception:
        kev = {}
        sources.append({"name": "CISA KEV", "status": "degraded", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "detail": "Source temporairement indisponible"})

    vulnerabilities = [normalize_cve(item["cve"], kev) for item in nvd.get("vulnerabilities", []) if item.get("cve")]
    vulnerabilities.sort(key=lambda item: (bool(item["kev"]), item["score"] or 0), reverse=True)
    return {
        "asset": {"vendor": query["vendor"], "product": query["product"], "version": query["version"]},
        "matching": {"method": method, "confidence": "high" if method == "cpe" else "medium", "query": cpe if method == "cpe" else keyword},
        "vulnerabilities": vulnerabilities,
        "totalResults": nvd.get("totalResults", len(vulnerabilities)),
        "fetchedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cached": False,
        "sources": sources,
    }


def register_query(key: str, query: dict[str, str]) -> None:
    with database_lock, connect() as connection:
        connection.execute(
            "INSERT INTO monitored_queries(cache_key, query_json, next_refresh) VALUES(?, ?, 0) "
            "ON CONFLICT(cache_key) DO UPDATE SET query_json=excluded.query_json",
            (key, json.dumps(query, separators=(",", ":"))),
        )


def read_cached(key: str) -> sqlite3.Row | None:
    with database_lock, connect() as connection:
        return connection.execute("SELECT * FROM monitored_queries WHERE cache_key = ?", (key,)).fetchone()


def lock_for(key: str) -> threading.Lock:
    with sync_locks_guard:
        return sync_locks.setdefault(key, threading.Lock())


def refresh_query(key: str, query: dict[str, str], force: bool = False) -> dict:
    register_query(key, query)
    row = read_cached(key)
    now = int(time.time())
    if not force and row and row["payload_json"] and (row["last_success"] or 0) + REFRESH_SECONDS > now:
        payload = json.loads(row["payload_json"])
        payload["cached"] = True
        return payload

    with lock_for(key):
        row = read_cached(key)
        now = int(time.time())
        if not force and row and row["payload_json"] and (row["last_success"] or 0) + REFRESH_SECONDS > now:
            payload = json.loads(row["payload_json"])
            payload["cached"] = True
            return payload
        try:
            payload = collect(query)
            with database_lock, connect() as connection:
                connection.execute(
                    "UPDATE monitored_queries SET payload_json=?, last_attempt=?, last_success=?, next_refresh=?, last_error=NULL WHERE cache_key=?",
                    (json.dumps(payload, separators=(",", ":")), now, now, now + REFRESH_SECONDS, key),
                )
            return payload
        except Exception as error:
            with database_lock, connect() as connection:
                connection.execute(
                    "UPDATE monitored_queries SET last_attempt=?, next_refresh=?, last_error=? WHERE cache_key=?",
                    (now, now + min(300, REFRESH_SECONDS), str(error)[:300], key),
                )
            row = read_cached(key)
            if row and row["payload_json"]:
                payload = json.loads(row["payload_json"])
                payload["cached"] = True
                payload["stale"] = True
                payload["warning"] = "Les sources sont indisponibles ; dernier instantané connu affiché."
                return payload
            raise


def delete_query(key: str) -> None:
    with database_lock, connect() as connection:
        connection.execute("DELETE FROM monitored_queries WHERE cache_key = ?", (key,))


def scheduler() -> None:
    while True:
        time.sleep(30)
        now = int(time.time())
        with database_lock, connect() as connection:
            rows = connection.execute(
                "SELECT cache_key, query_json FROM monitored_queries WHERE next_refresh <= ? ORDER BY next_refresh LIMIT 10",
                (now,),
            ).fetchall()
        for row in rows:
            try:
                refresh_query(row["cache_key"], json.loads(row["query_json"]), force=True)
            except Exception as error:
                print(f"collector refresh failed for {row['cache_key'][:8]}: {error}", flush=True)
            time.sleep(7 if not NVD_API_KEY else 1)


class Handler(BaseHTTPRequestHandler):
    server_version = "OpenVigieCollector/0.3"

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def parse_query(self) -> tuple[dict[str, str], str]:
        parsed = urllib.parse.urlparse(self.path)
        query = normalize_query(urllib.parse.parse_qs(parsed.query, keep_blank_values=True))
        return query, cache_key(query)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/health":
            self.send_json(200, {"status": "ok", "refreshSeconds": REFRESH_SECONDS})
            return
        if parsed.path != "/vulnerabilities":
            self.send_json(404, {"error": "Route inconnue"})
            return
        try:
            query, key = self.parse_query()
            parameters = urllib.parse.parse_qs(parsed.query)
            force = parameters.get("force", ["0"])[0] == "1"
            row = read_cached(key)
            if force and row and (row["last_attempt"] or 0) > int(time.time()) - 60:
                force = False
            self.send_json(200, refresh_query(key, query, force=force))
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
        except (urllib.error.URLError, TimeoutError, RuntimeError) as error:
            self.send_json(503, {"error": f"Source externe indisponible : {error}"})
        except Exception as error:
            print(f"collector error: {error}", flush=True)
            self.send_json(500, {"error": "Erreur interne du collecteur"})

    def do_DELETE(self) -> None:  # noqa: N802
        if urllib.parse.urlparse(self.path).path != "/vulnerabilities":
            self.send_json(404, {"error": "Route inconnue"})
            return
        try:
            _, key = self.parse_query()
            delete_query(key)
            self.send_json(200, {"success": True})
        except ValueError as error:
            self.send_json(400, {"error": str(error)})

    def log_message(self, message: str, *args: object) -> None:
        print(f"collector {self.address_string()} {message % args}", flush=True)


if __name__ == "__main__":
    initialize_database()
    threading.Thread(target=scheduler, name="openvigie-scheduler", daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", 8787), Handler)
    print(f"OpenVigie collector listening on :8787, refresh every {REFRESH_SECONDS}s", flush=True)
    server.serve_forever()
