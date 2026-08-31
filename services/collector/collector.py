"""OpenVigie local collector: CVE monitoring and attributed RSS/Atom bulletins."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import sqlite3
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DB_PATH = os.environ.get("OPENVIGIE_DB_PATH", "/data/openvigie.db")
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REFRESH_SECONDS = max(300, int(os.environ.get("OPENVIGIE_REFRESH_SECONDS", "900")))
FEED_REFRESH_SECONDS = max(1800, int(os.environ.get("OPENVIGIE_FEED_REFRESH_SECONDS", "10800")))
HTTP_TIMEOUT = 25
MAX_RESULTS = 100
MAX_FEED_BYTES = 2_000_000
SAFE_TEXT = re.compile(r"^[\w .+()/,:-]*$", re.UNICODE)
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
TRACKING_PARAMETERS = {"fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source"}

FEED_SOURCES = (
    {
        "id": "freedom-press", "name": "Freedom of the Press Foundation",
        "feed_url": "https://freedom.press/news/feed/", "homepage": "https://freedom.press/",
        "kind": "Liberté de la presse", "default_category": "Presse & lanceurs d’alerte",
        "priority": 10, "filter": "all", "license": "CC BY 4.0 sauf indication contraire",
    },
    {
        "id": "eff", "name": "Electronic Frontier Foundation",
        "feed_url": "https://www.eff.org/rss/updates.xml", "homepage": "https://www.eff.org/",
        "kind": "Droits numériques", "default_category": "Vie privée & droits numériques",
        "priority": 9, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "citizen-lab", "name": "The Citizen Lab",
        "feed_url": "https://citizenlab.ca/feed/", "homepage": "https://citizenlab.ca/",
        "kind": "Recherche indépendante", "default_category": "Surveillance & spyware",
        "priority": 10, "filter": "all", "license": "Attribution et lien vers la publication",
    },
    {
        "id": "cert-fr", "name": "CERT-FR / ANSSI",
        "feed_url": "https://www.cert.ssi.gouv.fr/feed/", "homepage": "https://www.cert.ssi.gouv.fr/",
        "kind": "Autorité nationale", "default_category": "Vulnérabilités & correctifs",
        "priority": 10, "filter": "all", "license": "Source publique attribuée",
    },
    {
        "id": "cisa-advisories", "name": "CISA Cybersecurity Advisories",
        "feed_url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "homepage": "https://www.cisa.gov/news-events/cybersecurity-advisories",
        "kind": "Autorité publique", "default_category": "Vulnérabilités & correctifs",
        "priority": 10, "filter": "all", "license": "Source publique attribuée",
    },
    {
        "id": "cert-eu", "name": "CERT-EU Security Advisories",
        "feed_url": "https://cert.europa.eu/publications/security-advisories-rss", "homepage": "https://cert.europa.eu/publications/security-advisories/",
        "kind": "Autorité européenne", "default_category": "Vulnérabilités & correctifs",
        "priority": 10, "filter": "all", "license": "Source publique attribuée",
    },
    {
        "id": "ncsc-uk", "name": "NCSC UK",
        "feed_url": "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
        "homepage": "https://www.ncsc.gov.uk/section/keep-up-to-date/reports",
        "kind": "Autorité nationale", "default_category": "Cyberconflits & menaces",
        "priority": 9, "filter": "all", "license": "Source publique attribuée",
    },
    {
        "id": "amnesty-security-lab", "name": "Amnesty Security Lab",
        "feed_url": "https://securitylab.amnesty.org/latest/feed/", "homepage": "https://securitylab.amnesty.org/",
        "kind": "Recherche forensique", "default_category": "Surveillance & spyware",
        "priority": 10, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "access-now", "name": "Access Now",
        "feed_url": "https://www.accessnow.org/feed/", "homepage": "https://www.accessnow.org/",
        "kind": "Droits numériques", "default_category": "Vie privée & droits numériques",
        "priority": 8, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "msrc", "name": "Microsoft Security Response Center",
        "feed_url": "https://api.msrc.microsoft.com/update-guide/rss", "homepage": "https://msrc.microsoft.com/update-guide/",
        "kind": "PSIRT éditeur", "default_category": "Vulnérabilités & correctifs",
        "priority": 9, "filter": "all", "max_bytes": 3_000_000,
        "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "cisco-psirt", "name": "Cisco PSIRT",
        "feed_url": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
        "homepage": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
        "kind": "PSIRT éditeur", "default_category": "Vulnérabilités & correctifs",
        "priority": 10, "filter": "all", "license": "RSS Cisco : extrait court et attribution",
    },
    {
        "id": "palo-alto-psirt", "name": "Palo Alto Networks Security Advisories",
        "feed_url": "https://security.paloaltonetworks.com/rss.xml",
        "homepage": "https://security.paloaltonetworks.com/",
        "kind": "PSIRT éditeur", "default_category": "Vulnérabilités & correctifs",
        "priority": 10, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "openssf", "name": "OpenSSF",
        "feed_url": "https://openssf.org/feed/", "homepage": "https://openssf.org/",
        "kind": "Sécurité open source", "default_category": "Supply chain logicielle",
        "priority": 9, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "github-supply-chain", "name": "GitHub Supply Chain Security",
        "feed_url": "https://github.blog/security/supply-chain-security/feed/",
        "homepage": "https://github.blog/security/supply-chain-security/",
        "kind": "Sécurité de la chaîne logicielle", "default_category": "Supply chain logicielle",
        "priority": 8, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "google-security", "name": "Google Security Blog",
        "feed_url": "https://security.googleblog.com/feeds/posts/default", "homepage": "https://security.googleblog.com/",
        "kind": "Recherche éditeur", "default_category": "Cybersécurité",
        "priority": 8, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "mozilla-security", "name": "Mozilla Security Blog",
        "feed_url": "https://blog.mozilla.org/security/feed/", "homepage": "https://blog.mozilla.org/security/",
        "kind": "Sécurité éditeur", "default_category": "Vulnérabilités & correctifs",
        "priority": 8, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "cloudflare", "name": "Cloudflare Blog",
        "feed_url": "https://blog.cloudflare.com/rss/", "homepage": "https://blog.cloudflare.com/",
        "kind": "Recherche éditeur", "default_category": "Cybersécurité",
        "priority": 7, "filter": "cyber", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "sans-isc", "name": "SANS Internet Storm Center",
        "feed_url": "https://isc.sans.edu/rssfeed.xml", "homepage": "https://isc.sans.edu/",
        "kind": "Veille opérationnelle", "default_category": "Cyberconflits & menaces",
        "priority": 8, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "forbidden-stories", "name": "Forbidden Stories",
        "feed_url": "https://forbiddenstories.org/feed/", "homepage": "https://forbiddenstories.org/",
        "kind": "Journalisme d’investigation", "default_category": "Presse & lanceurs d’alerte",
        "priority": 8, "filter": "cyber", "license": "Titre et extrait court avec attribution",
    },
)

CATEGORY_RULES = (
    ("Supply chain logicielle", ("supply chain", "software supply chain", "dependency", "dependencies", "malicious package", "package registry", "npm", "pypi", "rubygems", "dependency confusion", "typosquatting", "sbom", "slsa", "sigstore", "provenance", "ci/cd", "github actions", "build system", "artifact signing", "open source security")),
    ("VPN & accès distant", ("vpn", "ssl-vpn", "ssl vpn", "ipsec", "remote access", "remote desktop gateway", "secure client", "anyconnect", "globalprotect", "connect secure", "pulse secure", "netscaler gateway", "citrix gateway", "secure mobile access", "sonicwall sma")),
    ("Surveillance & spyware", ("pegasus", "spyware", "stalkerware", "mercenary surveillance", "surveillance", "zero-click", "zero click", "nso group", "forensic")),
    ("Vulnérabilités & correctifs", ("cve-", "vulnerability", "vulnerabilities", "vulnerabilite", "vulnerabilites", "security advisory", "security update", "patch", "correctif", "zero-day", "zero day", "exploit", "rce", "critical flaw")),
    ("Cyberconflits & menaces", ("apt", "state-backed", "nation-state", "cyberwar", "cyber war", "cyber conflict", "threat actor", "espionage", "ukraine", "russia", "iran", "north korea", "china-linked", "disinformation")),
    ("Cybercriminalité", ("ransomware", "malware", "botnet", "phishing", "fraud", "cybercrime", "cyber crime", "cryptocurrency theft", "crypto laundering", "infostealer")),
    ("Presse & lanceurs d’alerte", ("journalist", "journalism", "press freedom", "whistleblower", "source protection", "securedrop", "reporter", "media freedom")),
    ("Vie privée & droits numériques", ("privacy", "digital rights", "encryption", "censorship", "internet shutdown", "freedom of expression", "civil liberties", "data protection")),
    ("IA & souveraineté", ("artificial intelligence", " ai ", "machine learning", "digital sovereignty", "sovereignty", "cloud act", "platform regulation", "dma", "dsa")),
)

SOURCE_BY_ID = {source["id"]: source for source in FEED_SOURCES}
try:
    PARIS = ZoneInfo("Europe/Paris")
except ZoneInfoNotFoundError:
    PARIS = timezone.utc

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
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
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
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS articles (
              id TEXT PRIMARY KEY,
              source_id TEXT NOT NULL,
              source_name TEXT NOT NULL,
              source_home TEXT NOT NULL,
              source_kind TEXT NOT NULL,
              license_note TEXT NOT NULL,
              title TEXT NOT NULL,
              url TEXT NOT NULL UNIQUE,
              summary TEXT NOT NULL,
              author TEXT,
              published_at INTEGER NOT NULL,
              fetched_at INTEGER NOT NULL,
              category TEXT NOT NULL,
              cves_json TEXT NOT NULL DEFAULT '[]'
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS feed_runs (
              source_id TEXT PRIMARY KEY,
              source_name TEXT NOT NULL,
              feed_url TEXT NOT NULL,
              homepage TEXT NOT NULL,
              source_kind TEXT NOT NULL,
              etag TEXT,
              last_modified TEXT,
              last_attempt INTEGER,
              last_success INTEGER,
              next_refresh INTEGER NOT NULL DEFAULT 0,
              failures INTEGER NOT NULL DEFAULT 0,
              last_error TEXT
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_articles_published ON articles(published_at DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_articles_category_published ON articles(category, published_at DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_feeds_next_refresh ON feed_runs(next_refresh)")
        for source in FEED_SOURCES:
            connection.execute(
                """
                INSERT INTO feed_runs(source_id, source_name, feed_url, homepage, source_kind, next_refresh)
                VALUES(?, ?, ?, ?, ?, 0)
                ON CONFLICT(source_id) DO UPDATE SET
                  source_name=excluded.source_name,
                  feed_url=excluded.feed_url,
                  homepage=excluded.homepage,
                  source_kind=excluded.source_kind
                """,
                (source["id"], source["name"], source["feed_url"], source["homepage"], source["kind"]),
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


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def clean_excerpt(value: str, maximum: int = 360) -> str:
    extractor = _TextExtractor()
    try:
        extractor.feed(html.unescape(value or ""))
        text = " ".join(extractor.parts)
    except Exception:
        text = value or ""
    text = re.sub(r"\s+", " ", html.unescape(text)).strip()
    if len(text) <= maximum:
        return text
    shortened = text[: maximum - 1].rsplit(" ", 1)[0].rstrip(".,;:!?")
    return f"{shortened or text[:maximum - 1]}…"


def normalized_search_text(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value.lower())
    return "".join(character for character in decomposed if not unicodedata.combining(character))


def classify_article(title: str, summary: str, default: str) -> tuple[str, bool]:
    searchable = f" {normalized_search_text(title)} {normalized_search_text(summary)} "
    for category, keywords in CATEGORY_RULES:
        if any(normalized_search_text(keyword) in searchable for keyword in keywords):
            return category, True
    return default, False


def canonicalize_url(value: str, base_url: str) -> str:
    absolute = urllib.parse.urljoin(base_url, value.strip())
    parsed = urllib.parse.urlsplit(absolute)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    filtered_query = []
    for key, item in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        if key.lower().startswith("utm_") or key.lower() in TRACKING_PARAMETERS:
            continue
        filtered_query.append((key, item))
    host = parsed.hostname.lower()
    try:
        port = parsed.port
    except ValueError:
        return ""
    if port and not ((parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80)):
        host = f"{host}:{port}"
    path = parsed.path or "/"
    return urllib.parse.urlunsplit((parsed.scheme.lower(), host, path, urllib.parse.urlencode(filtered_query), ""))


def element_name(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1].lower()


def element_text(element: ET.Element, names: tuple[str, ...]) -> str:
    wanted = set(names)
    for child in element.iter():
        if element_name(child) in wanted:
            text = " ".join(part.strip() for part in child.itertext() if part.strip())
            if text:
                return text
    return ""


def entry_link(element: ET.Element, base_url: str) -> str:
    candidates: list[tuple[int, str]] = []
    for child in element.iter():
        if element_name(child) != "link":
            continue
        href = child.attrib.get("href", "").strip()
        rel = child.attrib.get("rel", "alternate").lower()
        content_type = child.attrib.get("type", "").lower()
        value = href or (child.text or "").strip()
        if not value:
            continue
        priority = 0 if rel == "alternate" and "atom" not in content_type else 1
        candidates.append((priority, value))
    for _, value in sorted(candidates):
        canonical = canonicalize_url(value, base_url)
        if canonical:
            return canonical
    return ""


def parse_published_at(value: str, fallback: int) -> int:
    if not value:
        return fallback
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except (TypeError, ValueError, OverflowError):
            return fallback
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    timestamp = int(parsed.timestamp())
    return fallback if timestamp < 0 or timestamp > fallback + 7 * 86400 else timestamp


def parse_feed(data: bytes, source: dict, fetched_at: int) -> list[dict]:
    upper_prefix = data[:4096].upper()
    root_match = re.search(br"<(?:[A-Z0-9_-]+:)?(?:RSS|FEED|RDF)\b", upper_prefix)
    preamble = upper_prefix[:root_match.start()] if root_match else upper_prefix
    if b"<!DOCTYPE" in preamble or b"<!ENTITY" in preamble:
        raise RuntimeError("Flux XML non sûr")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise RuntimeError(f"Flux XML invalide : {error}") from error

    entries = [element for element in root.iter() if element_name(element) in {"item", "entry"}]
    if not entries:
        raise RuntimeError("Aucun article RSS/Atom détecté")

    articles: list[dict] = []
    for entry in entries[:100]:
        title = clean_excerpt(element_text(entry, ("title",)), 240)
        url = entry_link(entry, source["feed_url"])
        if not title or not url:
            continue
        summary = clean_excerpt(element_text(entry, ("description", "summary")), 360)
        category, matched_topic = classify_article(title, summary, source["default_category"])
        if source["filter"] == "cyber" and not matched_topic:
            continue
        published_value = element_text(entry, ("pubdate", "published", "updated", "date"))
        published_at = parse_published_at(published_value, fetched_at)
        author = clean_excerpt(element_text(entry, ("creator", "author")), 100)
        cves = sorted({match.upper() for match in CVE_PATTERN.findall(f"{title} {summary}")})
        articles.append({
            "id": hashlib.sha256(url.encode()).hexdigest(),
            "source_id": source["id"],
            "source_name": source["name"],
            "source_home": source["homepage"],
            "source_kind": source["kind"],
            "license_note": source["license"],
            "title": title,
            "url": url,
            "summary": summary,
            "author": author,
            "published_at": published_at,
            "fetched_at": fetched_at,
            "category": category,
            "cves_json": json.dumps(cves, ensure_ascii=False, separators=(",", ":")),
        })
    return articles


def store_articles(articles: list[dict]) -> None:
    if not articles:
        return
    with database_lock, connect() as connection:
        connection.executemany(
            """
            INSERT INTO articles(
              id, source_id, source_name, source_home, source_kind, license_note,
              title, url, summary, author, published_at, fetched_at, category, cves_json
            ) VALUES(
              :id, :source_id, :source_name, :source_home, :source_kind, :license_note,
              :title, :url, :summary, :author, :published_at, :fetched_at, :category, :cves_json
            )
            ON CONFLICT(id) DO UPDATE SET
              source_id=excluded.source_id,
              source_name=excluded.source_name,
              source_home=excluded.source_home,
              source_kind=excluded.source_kind,
              license_note=excluded.license_note,
              title=excluded.title,
              summary=excluded.summary,
              author=excluded.author,
              published_at=excluded.published_at,
              fetched_at=excluded.fetched_at,
              category=excluded.category,
              cves_json=excluded.cves_json
            """,
            articles,
        )


def refresh_feed(source: dict) -> int:
    now = int(time.time())
    with database_lock, connect() as connection:
        row = connection.execute("SELECT * FROM feed_runs WHERE source_id = ?", (source["id"],)).fetchone()
        connection.execute("UPDATE feed_runs SET last_attempt=? WHERE source_id=?", (now, source["id"]))

    headers = {
        "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9",
        "User-Agent": "OpenVigie/0.4 (+https://github.com/Swapshadow/openvigie)",
    }
    if row and row["etag"]:
        headers["If-None-Match"] = row["etag"]
    if row and row["last_modified"]:
        headers["If-Modified-Since"] = row["last_modified"]

    try:
        request = urllib.request.Request(source["feed_url"], headers=headers)
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            content_length = int(response.headers.get("Content-Length", "0") or 0)
            maximum_bytes = int(source.get("max_bytes", MAX_FEED_BYTES))
            if content_length > maximum_bytes:
                raise RuntimeError("Flux trop volumineux")
            data = response.read(maximum_bytes + 1)
            if len(data) > maximum_bytes:
                raise RuntimeError("Flux trop volumineux")
            articles = parse_feed(data, source, now)
            store_articles(articles)
            etag = response.headers.get("ETag")
            last_modified = response.headers.get("Last-Modified")
        with database_lock, connect() as connection:
            connection.execute(
                """
                UPDATE feed_runs SET etag=?, last_modified=?, last_success=?, next_refresh=?,
                  failures=0, last_error=NULL WHERE source_id=?
                """,
                (etag, last_modified, now, now + FEED_REFRESH_SECONDS, source["id"]),
            )
        return len(articles)
    except urllib.error.HTTPError as error:
        if error.code == 304:
            with database_lock, connect() as connection:
                connection.execute(
                    "UPDATE feed_runs SET last_success=?, next_refresh=?, failures=0, last_error=NULL WHERE source_id=?",
                    (now, now + FEED_REFRESH_SECONDS, source["id"]),
                )
            return 0
        raise
    except Exception as error:
        failures = int(row["failures"] or 0) + 1 if row else 1
        retry_seconds = min(21600, 1800 * (2 ** min(failures - 1, 4)))
        with database_lock, connect() as connection:
            connection.execute(
                "UPDATE feed_runs SET next_refresh=?, failures=?, last_error=? WHERE source_id=?",
                (now + retry_seconds, failures, str(error)[:300], source["id"]),
            )
        raise


def refresh_due_feeds(limit: int = 5) -> int:
    now = int(time.time())
    with database_lock, connect() as connection:
        rows = connection.execute(
            "SELECT source_id FROM feed_runs WHERE next_refresh <= ? ORDER BY next_refresh, source_id LIMIT ?",
            (now, limit),
        ).fetchall()
    refreshed = 0
    for row in rows:
        source = SOURCE_BY_ID.get(row["source_id"])
        if not source:
            continue
        try:
            count = refresh_feed(source)
            print(f"feed {source['id']} refreshed: {count} articles", flush=True)
            refreshed += 1
        except Exception as error:
            print(f"feed refresh failed for {source['id']}: {error}", flush=True)
    return refreshed


def iso_timestamp(timestamp: int | None) -> str | None:
    if not timestamp:
        return None
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace("+00:00", "Z")


def feed_statuses() -> list[dict]:
    with database_lock, connect() as connection:
        rows = connection.execute("SELECT * FROM feed_runs ORDER BY source_name").fetchall()
    statuses = []
    for row in rows:
        if not row["last_attempt"]:
            status = "pending"
        elif row["last_error"]:
            status = "degraded"
        else:
            status = "online"
        statuses.append({
            "id": row["source_id"],
            "name": row["source_name"],
            "homepage": row["homepage"],
            "kind": row["source_kind"],
            "status": status,
            "lastSuccess": iso_timestamp(row["last_success"]),
            "nextRefresh": iso_timestamp(row["next_refresh"]),
            "error": row["last_error"] if status == "degraded" else None,
        })
    return statuses


def bulletin_window(cadence: str) -> tuple[int, str]:
    windows = {
        "daily": (48 * 3600, "Les dernières 48 heures"),
        "weekly": (8 * 86400, "Les 8 derniers jours"),
        "monthly": (35 * 86400, "Les 35 derniers jours"),
    }
    if cadence not in windows:
        raise ValueError("cadence doit être daily, weekly ou monthly")
    return windows[cadence]


def build_bulletin(cadence: str, limit: int, category: str = "") -> dict:
    window_seconds, label = bulletin_window(cadence)
    now = int(time.time())
    cutoff = now - window_seconds
    parameters: list[object] = [cutoff]
    category_clause = ""
    if category:
        category_clause = " AND category = ?"
        parameters.append(category)

    with database_lock, connect() as connection:
        rows = connection.execute(
            f"SELECT * FROM articles WHERE published_at >= ?{category_clause} ORDER BY published_at DESC LIMIT 300",
            tuple(parameters),
        ).fetchall()
        counts = connection.execute(
            "SELECT category, COUNT(*) AS count FROM articles WHERE published_at >= ? GROUP BY category ORDER BY count DESC, category",
            (cutoff,),
        ).fetchall()
        archive_fallback = False
        if not rows:
            fallback_parameters: tuple[object, ...] = (category,) if category else ()
            fallback_clause = "WHERE category = ?" if category else ""
            rows = connection.execute(
                f"SELECT * FROM articles {fallback_clause} ORDER BY published_at DESC LIMIT 100",
                fallback_parameters,
            ).fetchall()
            archive_fallback = bool(rows)

    ranked: list[tuple[float, sqlite3.Row]] = []
    for row in rows:
        source = SOURCE_BY_ID.get(row["source_id"], {})
        age = max(0, now - int(row["published_at"]))
        freshness = max(0.0, 40.0 * (1 - age / max(window_seconds, 1)))
        cves = json.loads(row["cves_json"] or "[]")
        score = float(source.get("priority", 5) * 4) + freshness + min(10, len(cves) * 3)
        ranked.append((score, row))
    ranked.sort(key=lambda item: (item[0], item[1]["published_at"]), reverse=True)

    selected: list[tuple[float, sqlite3.Row]] = []
    per_source: dict[str, int] = {}
    source_cap = max(2, (limit + 3) // 4)
    for score, row in ranked:
        if per_source.get(row["source_id"], 0) >= source_cap:
            continue
        selected.append((score, row))
        per_source[row["source_id"]] = per_source.get(row["source_id"], 0) + 1
        if len(selected) >= limit:
            break
    if len(selected) < limit:
        selected_ids = {row["id"] for _, row in selected}
        remaining = [item for item in ranked if item[1]["id"] not in selected_ids]
        selected.extend(remaining[: limit - len(selected)])

    articles = []
    for score, row in selected:
        articles.append({
            "id": row["id"],
            "title": row["title"],
            "url": row["url"],
            "excerpt": row["summary"],
            "author": row["author"] or None,
            "publishedAt": iso_timestamp(row["published_at"]),
            "fetchedAt": iso_timestamp(row["fetched_at"]),
            "category": row["category"],
            "cves": json.loads(row["cves_json"] or "[]"),
            "score": round(score, 1),
            "source": {
                "id": row["source_id"],
                "name": row["source_name"],
                "homepage": row["source_home"],
                "kind": row["source_kind"],
                "license": row["license_note"],
            },
        })

    local_start = datetime.fromtimestamp(cutoff, PARIS).isoformat()
    local_end = datetime.fromtimestamp(now, PARIS).isoformat()
    return {
        "cadence": cadence,
        "generatedAt": iso_timestamp(now),
        "period": {"label": label, "start": local_start, "end": local_end},
        "archiveFallback": archive_fallback,
        "articles": articles,
        "categories": [{"name": row["category"], "count": row["count"]} for row in counts],
        "sources": feed_statuses(),
        "ranking": {
            "method": "Classement automatique par fraîcheur, autorité de la source et signaux CVE, avec diversité des sources.",
            "warning": "Ce classement ne constitue pas une validation éditoriale ni une preuve de véracité.",
        },
    }


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


def vulnerability_scheduler() -> None:
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


def cleanup_old_articles() -> None:
    cutoff = int(time.time()) - 180 * 86400
    with database_lock, connect() as connection:
        connection.execute("DELETE FROM articles WHERE published_at < ?", (cutoff,))
        connection.execute("PRAGMA optimize")


def feed_scheduler() -> None:
    last_cleanup = 0
    while True:
        refresh_due_feeds(limit=5)
        now = int(time.time())
        if last_cleanup < now - 86400:
            cleanup_old_articles()
            last_cleanup = now
        time.sleep(30)


class Handler(BaseHTTPRequestHandler):
    server_version = "OpenVigieCollector/0.4"

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
            with database_lock, connect() as connection:
                article_count = connection.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
                active_feeds = connection.execute("SELECT COUNT(*) FROM feed_runs WHERE last_success IS NOT NULL").fetchone()[0]
            self.send_json(200, {
                "status": "ok",
                "refreshSeconds": REFRESH_SECONDS,
                "feedRefreshSeconds": FEED_REFRESH_SECONDS,
                "articles": article_count,
                "activeFeeds": active_feeds,
                "configuredFeeds": len(FEED_SOURCES),
            })
            return
        if parsed.path == "/feeds/status":
            self.send_json(200, {"sources": feed_statuses(), "refreshSeconds": FEED_REFRESH_SECONDS})
            return
        if parsed.path == "/articles":
            try:
                parameters = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                cadence = parameters.get("cadence", ["daily"])[0]
                category = parameters.get("category", [""])[0].strip()[:80]
                try:
                    limit = int(parameters.get("limit", ["18"])[0])
                except ValueError:
                    raise ValueError("limit doit être un nombre") from None
                limit = min(30, max(1, limit))
                self.send_json(200, build_bulletin(cadence, limit, category))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            except Exception as error:
                print(f"bulletin error: {error}", flush=True)
                self.send_json(500, {"error": "Erreur interne du bulletin"})
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
    threading.Thread(target=vulnerability_scheduler, name="openvigie-cve-scheduler", daemon=True).start()
    threading.Thread(target=feed_scheduler, name="openvigie-feed-scheduler", daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", 8787), Handler)
    print(
        f"OpenVigie collector listening on :8787; CVE {REFRESH_SECONDS}s; feeds {FEED_REFRESH_SECONDS}s",
        flush=True,
    )
    server.serve_forever()
