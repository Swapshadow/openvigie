"""OpenVigie local collector: CVE monitoring and attributed RSS/Atom bulletins."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
from difflib import SequenceMatcher
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
REFRESH_SECONDS = max(300, int(os.environ.get("OPENVIGIE_REFRESH_SECONDS", "86400")))
FEED_REFRESH_SECONDS = max(1800, int(os.environ.get("OPENVIGIE_FEED_REFRESH_SECONDS", "10800")))
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://ollama:11434").rstrip("/")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b-instruct")
HTTP_TIMEOUT = 25
MAX_RESULTS = 100
MAX_FEED_BYTES = 2_000_000
SAFE_TEXT = re.compile(r"^[\w .+()/,:-]*$", re.UNICODE)
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
TRACKING_PARAMETERS = {"fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source"}

FEED_SOURCES = (
    {
        "id": "anssi-actualites", "name": "ANSSI · Actualités",
        "feed_url": "https://cyber.gouv.fr/actualites/rss/", "homepage": "https://cyber.gouv.fr/actualites/",
        "kind": "Autorité nationale · réglementation", "default_category": "Cybersécurité",
        "priority": 10, "filter": "regulatory", "license": "Source publique attribuée",
    },
    {
        "id": "eu-digital-strategy", "name": "Commission européenne · Numérique",
        "feed_url": "https://digital-strategy.ec.europa.eu/en/rss.xml", "homepage": "https://digital-strategy.ec.europa.eu/en/news",
        "kind": "Institution européenne · réglementation", "default_category": "Cybersécurité",
        "priority": 10, "filter": "regulatory", "license": "Source institutionnelle attribuée",
    },
    {
        "id": "french-breaches", "name": "FrenchBreaches",
        "feed_url": "https://frenchbreaches.com/feed.xml", "homepage": "https://frenchbreaches.com/",
        "kind": "Fuites de données · France", "default_category": "Fuites de données · France",
        "priority": 10, "filter": "all", "fixed_category": True,
        "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "bonjour-la-fuite", "name": "BonjourLaFuite",
        "feed_url": "https://bonjourlafuite.eu.org/feed.xml", "homepage": "https://bonjourlafuite.eu.org/",
        "kind": "Registre citoyen de fuites · France", "default_category": "Fuites de données · France",
        "priority": 10, "filter": "all", "fixed_category": True,
        "license": "Titre et données concernées avec attribution",
    },
    {
        "id": "french-breaches-blog", "name": "FrenchBreaches · International",
        "feed_url": "https://frenchbreaches.com/blog/feed.xml", "homepage": "https://frenchbreaches.com/blog/",
        "kind": "Actualité des fuites internationales", "default_category": "Cybersécurité",
        "priority": 9, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
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
        "id": "cert-fr-alertes", "name": "CERT-FR · Alertes de sécurité",
        "feed_url": "https://cert.ssi.gouv.fr/alerte/feed/", "homepage": "https://cert.ssi.gouv.fr/alerte/",
        "kind": "Alerte nationale urgente", "default_category": "CERT-FR · Alertes",
        "priority": 10, "filter": "all", "fixed_category": True, "license": "Source publique attribuée",
    },
    {
        "id": "cert-fr-avis", "name": "CERT-FR · Avis de sécurité",
        "feed_url": "https://cert.ssi.gouv.fr/avis/feed/", "homepage": "https://cert.ssi.gouv.fr/avis/",
        "kind": "Avis national de vulnérabilité", "default_category": "CERT-FR · Avis",
        "priority": 10, "filter": "all", "fixed_category": True, "license": "Source publique attribuée",
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
        "id": "sentinel-labs", "name": "SentinelLabs",
        "feed_url": "https://www.sentinelone.com/labs/feed/", "homepage": "https://www.sentinelone.com/labs/",
        "kind": "Recherche menaces", "default_category": "Cyberconflits & menaces",
        "priority": 10, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "cisco-talos", "name": "Cisco Talos Intelligence",
        "feed_url": "https://blog.talosintelligence.com/rss/", "homepage": "https://blog.talosintelligence.com/",
        "kind": "Recherche menaces", "default_category": "Cyberconflits & menaces",
        "priority": 10, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "unit-42", "name": "Unit 42",
        "feed_url": "https://unit42.paloaltonetworks.com/feed/", "homepage": "https://unit42.paloaltonetworks.com/",
        "kind": "Recherche menaces", "default_category": "Cyberconflits & menaces",
        "priority": 10, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "crowdstrike", "name": "CrowdStrike Counter Adversary Operations",
        "feed_url": "https://www.crowdstrike.com/en-us/blog/feed/", "homepage": "https://www.crowdstrike.com/en-us/blog/",
        "kind": "Threat intelligence", "default_category": "Cyberconflits & menaces",
        "priority": 9, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "eset-research", "name": "ESET WeLiveSecurity",
        "feed_url": "https://www.welivesecurity.com/en/rss/feed/", "homepage": "https://www.welivesecurity.com/",
        "kind": "Recherche menaces", "default_category": "Cyberconflits & menaces",
        "priority": 9, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "zdi", "name": "Zero Day Initiative",
        "feed_url": "https://www.zerodayinitiative.com/rss/published/", "homepage": "https://www.zerodayinitiative.com/blog/",
        "kind": "Recherche vulnérabilités", "default_category": "Vulnérabilités & correctifs",
        "priority": 10, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "watchtowr", "name": "watchTowr Labs",
        "feed_url": "https://labs.watchtowr.com/rss/", "homepage": "https://labs.watchtowr.com/",
        "kind": "Recherche vulnérabilités", "default_category": "Vulnérabilités & correctifs",
        "priority": 10, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "portswigger", "name": "PortSwigger Research",
        "feed_url": "https://portswigger.net/research/rss", "homepage": "https://portswigger.net/research",
        "kind": "Recherche sécurité web", "default_category": "Vulnérabilités & correctifs",
        "priority": 10, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "bleeping-computer", "name": "BleepingComputer",
        "feed_url": "https://www.bleepingcomputer.com/feed/", "homepage": "https://www.bleepingcomputer.com/",
        "kind": "Presse cybersécurité", "default_category": "Cybersécurité",
        "priority": 9, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "the-record", "name": "The Record",
        "feed_url": "https://therecord.media/feed", "homepage": "https://therecord.media/",
        "kind": "Presse cybersécurité", "default_category": "Cyberconflits & menaces",
        "priority": 9, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "krebs", "name": "Krebs on Security",
        "feed_url": "https://krebsonsecurity.com/feed/", "homepage": "https://krebsonsecurity.com/",
        "kind": "Journalisme d’investigation", "default_category": "Cybercriminalité",
        "priority": 9, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
    {
        "id": "schneier", "name": "Schneier on Security",
        "feed_url": "https://www.schneier.com/feed/atom/", "homepage": "https://www.schneier.com/",
        "kind": "Analyse indépendante", "default_category": "Vie privée & droits numériques",
        "priority": 8, "filter": "all", "license": "Titre et extrait court avec attribution",
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
    {
        "id": "zataz", "name": "ZATAZ",
        "feed_url": "https://www.zataz.com/feed/", "homepage": "https://www.zataz.com/",
        "kind": "Presse cybersécurité française", "default_category": "Cybercriminalité",
        "priority": 8, "filter": "all", "license": "Titre et extrait court avec attribution",
    },
)

CATEGORY_RULES = (
    ("Réglementation & conformité", ("iso 27001", "iso/iec 27001", "iso27001", "nis 2", "nis2", "directive nis", "dora", "digital operational resilience act", "cyber resilience act", " ai act", "artificial intelligence act", "digital services act", "dsa enforcement", "rgpd", "gdpr", "reglementation cyber", "cybersecurity regulation", "conformite cyber", "compliance requirement", "implementing regulation", "certification scheme")),
    ("Fuites de données · International", ("data breach", "data leak", "breach exposed", "records exposed", "stolen data", "fuite de donnees", "vol de donnees", "donnees volees", "donnees exposees")),
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
        # Migration from the former mixed CERT-FR feed to the two official,
        # separately classified alert and advisory feeds.
        connection.execute("DELETE FROM feed_runs WHERE source_id = 'cert-fr'")
        connection.execute("DELETE FROM articles WHERE source_id = 'cert-fr'")


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
    # Some public registries (notably BonjourLaFuite) use stable fragments as
    # per-incident permalinks, so the fragment is part of the article identity.
    return urllib.parse.urlunsplit((parsed.scheme.lower(), host, path, urllib.parse.urlencode(filtered_query), parsed.fragment))


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
    guid = element_text(element, ("guid", "id"))
    if guid:
        return canonicalize_url(guid, base_url)
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
        if source.get("fixed_category"):
            category, matched_topic = source["default_category"], True
        else:
            category, matched_topic = classify_article(title, summary, source["default_category"])
        if source["filter"] == "cyber" and not matched_topic:
            continue
        if source["filter"] == "regulatory" and category != "Réglementation & conformité":
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


def store_history_articles(articles: list[dict]) -> None:
    """Backfill archive-only rows without replacing richer RSS descriptions."""
    if not articles:
        return
    with database_lock, connect() as connection:
        connection.executemany(
            """
            INSERT OR IGNORE INTO articles(
              id, source_id, source_name, source_home, source_kind, license_note,
              title, url, summary, author, published_at, fetched_at, category, cves_json
            ) VALUES(
              :id, :source_id, :source_name, :source_home, :source_kind, :license_note,
              :title, :url, :summary, :author, :published_at, :fetched_at, :category, :cves_json
            )
            """,
            articles,
        )


def history_article(source: dict, title: str, url: str, summary: str, published_at: int, fetched_at: int) -> dict:
    return {
        "id": hashlib.sha256(url.encode()).hexdigest(), "source_id": source["id"],
        "source_name": source["name"], "source_home": source["homepage"],
        "source_kind": source["kind"], "license_note": source["license"],
        "title": clean_excerpt(title, 240), "url": url, "summary": clean_excerpt(summary, 360),
        "author": "", "published_at": published_at, "fetched_at": fetched_at,
        "category": "Fuites de données · France", "cves_json": "[]",
    }


def refresh_leak_histories() -> int:
    """Backfill the complete public indexes; RSS feeds only expose recent rows."""
    now = int(time.time())
    articles: list[dict] = []

    request = urllib.request.Request("https://bonjourlafuite.eu.org/", headers={"User-Agent": "OpenVigie/0.6 (+https://github.com/Swapshadow/openvigie)"})
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
        document = response.read(3_000_000).decode("utf-8", "replace")
    source = SOURCE_BY_ID["bonjour-la-fuite"]
    entries = list(re.finditer(r'<div\s+class="timeline-entry[^"]*"(?P<attrs>.*?)>', document, re.DOTALL | re.IGNORECASE))
    for index, match in enumerate(entries):
        attrs = match.group("attrs")
        title_match = re.search(r'data-title="([^"]+)"', attrs, re.IGNORECASE)
        date_match = re.search(r'data-date="([^"]+)"', attrs, re.IGNORECASE)
        if not title_match or not date_match:
            continue
        title = html.unescape(title_match.group(1)).strip()
        try:
            published_at = int(datetime.strptime(date_match.group(1).split(" GMT", 1)[0], "%a %b %d %Y %H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            continue
        segment_end = entries[index + 1].start() if index + 1 < len(entries) else min(len(document), match.end() + 6000)
        segment = document[match.end():segment_end]
        anchor = re.search(r'href="#([^"]+)"', segment, re.IGNORECASE)
        tags = [clean_excerpt(value, 80) for value in re.findall(r'class="leak-data-tag"[^>]*>(.*?)</span>', segment, re.DOTALL | re.IGNORECASE)]
        url = "https://bonjourlafuite.eu.org/#" + (anchor.group(1) if anchor else urllib.parse.quote(f"{title}-{datetime.fromtimestamp(published_at, timezone.utc).date()}"))
        status = html.unescape(re.search(r'data-status="([^"]+)"', attrs, re.IGNORECASE).group(1)) if re.search(r'data-status="([^"]+)"', attrs, re.IGNORECASE) else "signalé"
        summary = f"Statut : {status}." + (f" Données concernées : {', '.join(tags)}." if tags else "")
        articles.append(history_article(source, title, url, summary, published_at, now))

    request = urllib.request.Request("https://frenchbreaches.com/archives", headers={"User-Agent": "OpenVigie/0.6 (+https://github.com/Swapshadow/openvigie)"})
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
        document = response.read(4_000_000).decode("utf-8", "replace")
    source = SOURCE_BY_ID["french-breaches"]
    pattern = re.compile(r'<li\s+class="ab-item"[^>]*>(?P<body>.*?)</li>', re.DOTALL | re.IGNORECASE)
    for match in pattern.finditer(document):
        body = match.group("body")
        date_match = re.search(r'class="ab-date"[^>]*>(\d{2}/\d{2}/\d{4})</time>', body, re.IGNORECASE)
        link_match = re.search(r'class="ab-link"\s+href="([^"]+)">(.*?)</a>', body, re.DOTALL | re.IGNORECASE)
        if not date_match or not link_match:
            continue
        try:
            published_at = int(datetime.strptime(date_match.group(1), "%d/%m/%Y").replace(tzinfo=PARIS).timestamp())
        except ValueError:
            continue
        title = clean_excerpt(link_match.group(2), 240)
        url = canonicalize_url(link_match.group(1), "https://frenchbreaches.com/archives")
        badges = [clean_excerpt(value, 80) for value in re.findall(r'class="ab-badge[^"]*"[^>]*>(.*?)</span>', body, re.DOTALL | re.IGNORECASE)]
        if title and url:
            articles.append(history_article(source, title, url, " · ".join(badges) or "Signalement archivé", published_at, now))

    store_history_articles(articles)
    return len(articles)


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
            "SELECT category, COUNT(*) AS count FROM articles GROUP BY category ORDER BY count DESC, category",
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


def build_ai_news_brief(cadence: str, limit: int, topic: str = "") -> dict:
    """Ask the local model to analyze already collected, attributed news."""
    bulletin = build_bulletin(cadence, limit)
    topic = re.sub(r"\s+", " ", topic).strip()[:160]
    evidence = [
        {
            "title": article["title"],
            "excerpt": article["excerpt"],
            "publishedAt": article["publishedAt"],
            "category": article["category"],
            "source": article["source"]["name"],
            "url": article["url"],
            "cves": article["cves"],
        }
        for article in bulletin["articles"]
    ]
    if not evidence:
        raise RuntimeError("Aucune actualité collectée à analyser")

    system = (
        "Tu es l'analyste de veille cyber d'OpenVigie. Tu ne navigues pas sur le Web : "
        "tu analyses exclusivement les articles attribués fournis par le collecteur. "
        "Rédige en français une synthèse concise et opérationnelle. Distingue faits, "
        "signaux faibles et incertitudes. N'invente aucun fait, date, source ou URL. "
        "Chaque point doit citer le nom de la source et conserver son URL. Signale "
        "explicitement quand les éléments fournis ne permettent pas de conclure."
    )
    instruction = "Prépare le brief de veille"
    if topic:
        instruction += f" centré sur : {topic}"
    instruction += ". Retourne du Markdown lisible, sans bloc de code.\n\nArticles JSON :\n"
    request_body = json.dumps({
        "model": OLLAMA_MODEL,
        "stream": False,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": instruction + json.dumps(evidence, ensure_ascii=False)},
        ],
        "options": {"temperature": 0.2},
    }, ensure_ascii=False).encode()
    request = urllib.request.Request(
        f"{OLLAMA_BASE_URL}/api/chat",
        data=request_body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            result = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Ollama indisponible : {error}") from error
    content = result.get("message", {}).get("content", "").strip()
    if not content:
        raise RuntimeError("Ollama a retourné une réponse vide")
    return {
        "generatedAt": iso_timestamp(int(time.time())),
        "cadence": cadence,
        "topic": topic or None,
        "model": OLLAMA_MODEL,
        "analysis": content,
        "evidence": evidence,
        "notice": "Synthèse IA locale fondée uniquement sur les sources listées.",
    }


def build_ai_triage(cadence: str, limit: int, assets: list[dict]) -> dict:
    """Return bulletin, asset matrix and alerts; factual rules always win."""
    bulletin = build_bulletin(cadence, min(30, max(3, limit)))
    articles = bulletin["articles"]
    if not articles:
        raise RuntimeError("Aucune actualité collectée à analyser")
    safe_assets = []
    for raw in assets[:100]:
        if isinstance(raw, dict):
            safe_assets.append({key: clean_excerpt(str(raw.get(key, "")), 120) for key in
                                ("id", "label", "vendor", "product", "version", "exposure")})
    evidence = [{
        "id": item["id"], "title": item["title"], "excerpt": item["excerpt"],
        "publishedAt": item["publishedAt"], "categoryRule": item["category"],
        "source": item["source"]["name"], "url": item["url"], "cvesRule": item["cves"],
    } for item in articles]
    prompt = (
        "Analyse uniquement ce JSON et retourne un objet JSON valide avec la clé items. "
        "Un item par article, identifié par id, contient: cluster, classification parmi "
        "menace/vulnerabilite/detection/conformite/autre, resumeFr (2 phrases), vendors, products, "
        "versions, apt, iocs, relevanceAi (0-100), priorityAi (0-100), rationale. "
        "N'invente rien et utilise des tableaux vides si absent. cvesRule et categoryRule sont "
        "des faits immuables. Les actifs servent uniquement à estimer la pertinence.\n" +
        json.dumps({"articles": evidence, "assets": safe_assets}, ensure_ascii=False)
    )
    body = json.dumps({
        "model": OLLAMA_MODEL, "stream": False, "format": "json",
        "messages": [{"role": "system", "content": "Tu es le moteur local de tri cyber d'OpenVigie. Réponds exclusivement en JSON."},
                     {"role": "user", "content": prompt}],
        "options": {"temperature": 0.1},
    }, ensure_ascii=False).encode()
    request = urllib.request.Request(f"{OLLAMA_BASE_URL}/api/chat", data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            outer = json.loads(response.read())
        ai_payload = json.loads(outer.get("message", {}).get("content", "{}"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Ollama indisponible ou réponse invalide : {error}") from error
    ai_by_id = {str(item.get("id")): item for item in ai_payload.get("items", []) if isinstance(item, dict)}
    try:
        kev, kev_status = get_kev(), "online"
    except Exception:
        kev, kev_status = {}, "degraded"
    triage, matrix = [], []
    for article in articles:
        ai = ai_by_id.get(article["id"], {})
        text = normalized_search_text(f"{article['title']} {article['excerpt']}")
        asset_hits = []
        for asset in safe_assets:
            vendor, product = normalized_search_text(asset["vendor"]), normalized_search_text(asset["product"])
            version = normalized_search_text(asset["version"])
            if product and product in text and (not vendor or vendor in text):
                asset_hits.append({**asset, "versionMentioned": bool(version and version in text)})
        cves = article["cves"]
        kev_cves = [cve for cve in cves if cve in kev]
        try:
            ai_priority = min(100, max(0, int(ai.get("priorityAi", 0) or 0)))
        except (TypeError, ValueError):
            ai_priority = 0
        rule_floor = 100 if kev_cves and asset_hits else 92 if kev_cves else 85 if cves and asset_hits else 0
        priority = max(ai_priority, rule_floor)
        reasons = (["CISA KEV : exploitation connue"] if kev_cves else []) + \
                  (["éditeur et produit présents dans le parc"] if asset_hits else []) + \
                  (["CVE extraite par le collecteur"] if cves else [])
        if not reasons:
            reasons = [str(ai.get("rationale", "Priorité proposée par le tri IA local"))[:300]]
        item = {
            "id": article["id"], "title": article["title"], "url": article["url"],
            "source": article["source"], "publishedAt": article["publishedAt"],
            "cluster": str(ai.get("cluster", article["id"]))[:100],
            "classification": str(ai.get("classification", "autre"))[:40],
            "summaryFr": str(ai.get("resumeFr", article["excerpt"]))[:900],
            "entities": {"cves": cves, "vendors": ai.get("vendors", []), "products": ai.get("products", []),
                         "versions": ai.get("versions", []), "apt": ai.get("apt", []), "iocs": ai.get("iocs", [])},
            "assets": asset_hits, "kevCves": kev_cves, "priority": priority,
            "prioritySource": "rules" if rule_floor >= ai_priority and rule_floor else "ai",
            "priorityExplanation": " · ".join(reasons),
        }
        triage.append(item)
        if asset_hits or kev_cves:
            matrix.append(item)
    triage.sort(key=lambda item: item["priority"], reverse=True)
    matrix.sort(key=lambda item: item["priority"], reverse=True)
    alerts = [item for item in matrix if item["priority"] >= 85]
    seen, deduplicated = set(), []
    for item in triage:
        if item["cluster"] not in seen:
            seen.add(item["cluster"])
            deduplicated.append(item)
    return {
        "generatedAt": iso_timestamp(int(time.time())), "cadence": cadence, "model": OLLAMA_MODEL,
        "bulletin": deduplicated, "matrix": matrix, "alerts": alerts,
        "stats": {"analyzed": len(triage), "afterDeduplication": len(deduplicated),
                  "assetMatches": len(matrix), "alerts": len(alerts)},
        "rules": {"precedence": "CVE, parc et CISA KEV priment toujours sur le score IA", "kevStatus": kev_status},
        "sources": bulletin["sources"],
    }


VIGI_SYSTEM = (
    "Tu es Vigi, l'assistant de veille cyber d'OpenVigie. Tu réponds en français, de "
    "façon concise et opérationnelle. Tu ne navigues pas sur le Web : tu t'appuies "
    "uniquement sur le contexte factuel fourni (bulletin OpenVigie, parc déclaré par "
    "l'utilisateur) et sur l'historique de la conversation. N'invente jamais de CVE, "
    "de source, d'URL, de date, d'éditeur ni de version. Quand tu cites un article, "
    "indique le nom de sa source. Les CVE et les catégories fournies sont des faits "
    "immuables : ne les minimise pas. Si le contexte ne permet pas de conclure, dis-le "
    "explicitement et oriente vers la bonne section d'OpenVigie (Le Bulletin, Mon parc, "
    "Plan de veille, Recherche approfondie)."
)

VIGI_CONTEXT_HINTS = (
    "bulletin", "vulnerab", "cve", "faille", "exploit", "kev", "parc", "correctif",
    "patch", "menace", "ransomware", "apt", "avis", "alerte", "editeur", "campagne",
    "0day", "zero day", "zero-day", "actualite", "news", "majeur", "priorite",
)


def _vigi_wants_bulletin(text: str) -> bool:
    """True when the user's question should be grounded on the live bulletin."""
    needle = normalized_search_text(text)
    return any(hint in needle for hint in VIGI_CONTEXT_HINTS)


def build_vigi_reply(messages: list[dict], assets: list[dict], cadence: str = "daily") -> dict:
    """Vigi chatbot: grounded local answers over the OpenVigie bulletin and parc."""
    if cadence not in ("daily", "weekly", "monthly"):
        cadence = "daily"
    history: list[dict] = []
    for entry in messages[-12:]:
        if not isinstance(entry, dict):
            continue
        role = entry.get("role")
        content = re.sub(r"\s+", " ", str(entry.get("content", ""))).strip()[:2000]
        if role in ("user", "assistant") and content:
            history.append({"role": role, "content": content})
    if not history or history[-1]["role"] != "user":
        raise ValueError("Le dernier message doit provenir de l'utilisateur")
    last_user = history[-1]["content"]

    safe_assets = []
    for raw in assets[:60]:
        if isinstance(raw, dict):
            entry = {key: clean_excerpt(str(raw.get(key, "")), 80)
                     for key in ("label", "vendor", "product", "version", "exposure")}
            if entry["product"] or entry["vendor"]:
                safe_assets.append(entry)

    context_blocks: list[str] = []
    used_sources: list[dict] = []
    used_bulletin = False
    if _vigi_wants_bulletin(last_user):
        bulletin = build_bulletin(cadence, 8)
        evidence = []
        for article in bulletin["articles"][:8]:
            evidence.append({
                "titre": article["title"],
                "resume": clean_excerpt(article["excerpt"], 420),
                "categorie": article["category"],
                "cves": article["cves"],
                "source": article["source"]["name"],
                "url": article["url"],
                "publieLe": article["publishedAt"],
            })
            used_sources.append({"name": article["source"]["name"], "url": article["url"]})
        if evidence:
            used_bulletin = True
            context_blocks.append(
                f"Bulletin OpenVigie ({cadence}), articles attribués les plus récents :\n"
                + json.dumps(evidence, ensure_ascii=False)
            )
    if safe_assets:
        context_blocks.append(
            "Parc déclaré par l'utilisateur (marque, produit, version) :\n"
            + json.dumps(safe_assets, ensure_ascii=False)
        )

    system = VIGI_SYSTEM
    if context_blocks:
        system += "\n\nContexte factuel — ne rien affirmer au-delà :\n" + "\n\n".join(context_blocks)
    else:
        system += (
            "\n\nAucun contexte spécifique n'a été chargé pour ce message. Réponds "
            "brièvement et invite l'utilisateur à préciser sa question sur le bulletin "
            "ou sur son parc."
        )

    request_body = json.dumps({
        "model": OLLAMA_MODEL,
        "stream": False,
        "messages": [{"role": "system", "content": system}, *history],
        "options": {"temperature": 0.2, "num_predict": 600},
    }, ensure_ascii=False).encode()
    request = urllib.request.Request(
        f"{OLLAMA_BASE_URL}/api/chat",
        data=request_body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=240) as response:
            result = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Vigi (IA locale) indisponible : {error}") from error
    reply = result.get("message", {}).get("content", "").strip()
    if not reply:
        raise RuntimeError("Vigi a retourné une réponse vide")

    seen: set[str] = set()
    sources = []
    for item in used_sources:
        if item["url"] and item["url"] not in seen:
            seen.add(item["url"])
            sources.append(item)
    return {
        "generatedAt": iso_timestamp(int(time.time())),
        "model": OLLAMA_MODEL,
        "reply": reply,
        "usedContext": {
            "bulletin": used_bulletin,
            "cadence": cadence if used_bulletin else None,
            "assets": len(safe_assets),
        },
        "sources": sources,
        "notice": "Réponse IA locale fondée uniquement sur le bulletin et le parc fournis.",
    }


def search_articles(query: str, limit: int = 30, days: int = 365, source_id: str = "", sort: str = "recent") -> dict:
    """Search the local archive, then complement it with live attributed web news."""
    query = re.sub(r"\s+", " ", query).strip()[:240]
    if len(query) < 2:
        raise ValueError("La recherche doit contenir au moins 2 caractères")
    raw_tokens = [token.lower() for token in re.findall(r"[\wÀ-ÿ.-]{2,}", query, re.UNICODE)][:12]
    cyber_lexicon = (
        "fortipam", "fortinet", "fortigate", "fortios", "fortiweb", "fortimanager", "fortisiem",
        "paloalto", "panos", "globalprotect", "cisco", "anyconnect", "citrix", "netscaler",
        "microsoft", "windows", "exchange", "sharepoint", "ivanti", "sonicwall", "vmware",
        "vcenter", "esxi", "veeam", "juniper", "pulse", "checkpoint", "cloudflare",
        "ransomware", "phishing", "vulnerability", "vulnerabilite", "malware", "spyware",
    )
    corrections = []
    tokens = []
    for token in raw_tokens:
        normalized = normalized_search_text(token).replace("-", "")
        candidate = max(cyber_lexicon, key=lambda item: SequenceMatcher(None, normalized, item).ratio())
        ratio = SequenceMatcher(None, normalized, candidate).ratio()
        corrected = candidate if len(normalized) >= 5 and ratio >= 0.78 and normalized != candidate else token
        if corrected != token:
            corrections.append({"from": token, "to": corrected})
        tokens.append(corrected)
    if not tokens:
        raise ValueError("Aucun mot-clé exploitable")
    normalized_query = " ".join(tokens)
    generic_tokens = {"cve", "cves", "cyber", "cybersecurity", "securite", "vulnerability", "vulnerabilite", "news", "actualite"}
    meaningful_tokens = [token for token in tokens if normalized_search_text(token) not in generic_tokens] or tokens

    cutoff = int(time.time()) - min(3650, max(1, days)) * 86400
    token_clauses = []
    parameters: list[object] = [cutoff]
    for token in meaningful_tokens:
        token_clauses.append("(lower(title) LIKE ? OR lower(summary) LIKE ? OR lower(cves_json) LIKE ?)")
        needle = f"%{token}%"
        parameters.extend([needle, needle, needle])
    clauses = ["published_at >= ?", f"({' OR '.join(token_clauses)})"]
    if source_id:
        clauses.append("source_id = ?")
        parameters.append(source_id[:80])

    with database_lock, connect() as connection:
        rows = connection.execute(
            f"SELECT * FROM articles WHERE {' AND '.join(clauses)} ORDER BY published_at DESC LIMIT 250",
            tuple(parameters),
        ).fetchall()

    now = int(time.time())
    ranked = []
    for row in rows:
        title = row["title"].lower()
        summary = row["summary"].lower()
        cves = json.loads(row["cves_json"] or "[]")
        source = SOURCE_BY_ID.get(row["source_id"], {})
        exact = normalized_query.lower() in f"{title} {summary}"
        title_hits = sum(token in title for token in meaningful_tokens)
        summary_hits = sum(token in summary for token in meaningful_tokens)
        unique_hits = sum(token in f"{title} {summary}" for token in meaningful_tokens)
        freshness = max(0.0, 18.0 * (1 - max(0, now - row["published_at"]) / max(days * 86400, 1)))
        hit_ratio = (title_hits + summary_hits) / max(len(meaningful_tokens), 1)
        score = (35 if exact else 0) + title_hits * 16 + summary_hits * 5 + hit_ratio * 20 + source.get("priority", 5) * 3 + freshness
        ranked.append((score, row, cves))
    ranked.sort(key=lambda item: (item[0], item[1]["published_at"]), reverse=True)

    results = []
    for score, row, cves in ranked[:limit]:
        matched = [token for token in tokens if token in f'{row["title"]} {row["summary"]}'.lower()]
        results.append({
            "id": row["id"], "title": row["title"], "url": row["url"],
            "excerpt": row["summary"], "publishedAt": iso_timestamp(row["published_at"]),
            "category": row["category"], "cves": cves, "score": round(score, 1),
            "matchedTerms": matched,
            "source": {"id": row["source_id"], "name": row["source_name"],
                       "homepage": row["source_home"], "kind": row["source_kind"]},
        })

    # Bing News exposes a public RSS response and works without a private API key.
    # It complements the auditable local archive for topics not yet seen in a feed.
    live_error = ""
    try:
        live_url = "https://www.bing.com/news/search?" + urllib.parse.urlencode({
            "q": normalized_query, "format": "rss", "setlang": "fr-fr", "cc": "fr",
        })
        request = urllib.request.Request(live_url, headers={
            "Accept": "application/rss+xml, application/xml;q=0.9",
            "User-Agent": "OpenVigie/0.5 (+https://github.com/Swapshadow/openvigie)",
        })
        with urllib.request.urlopen(request, timeout=12) as response:
            data = response.read(1_000_000)
        root = ET.fromstring(data)
        known_urls = {item["url"] for item in results}
        for entry in root.findall(".//item")[:40]:
            title = clean_excerpt(entry.findtext("title") or "", 240)
            summary = clean_excerpt(entry.findtext("description") or "", 360)
            bing_link = entry.findtext("link") or ""
            parsed_link = urllib.parse.urlparse(bing_link)
            original = urllib.parse.parse_qs(parsed_link.query).get("url", [bing_link])[0]
            original = canonicalize_url(original, live_url)
            if not title or not original or original in known_urls:
                continue
            published_at = parse_published_at(entry.findtext("pubDate") or "", now)
            if published_at < cutoff:
                continue
            source_name = "Source web"
            for child in entry:
                if element_name(child) == "source" and (child.text or "").strip():
                    source_name = clean_excerpt(child.text or "", 100)
                    break
            category, _ = classify_article(title, summary, "Actualité cyber")
            searchable = normalized_search_text(f"{title} {summary}")
            matched = [token for token in tokens if normalized_search_text(token) in searchable]
            cves = sorted({match.upper() for match in CVE_PATTERN.findall(f"{title} {summary}")})
            results.append({
                "id": hashlib.sha256(original.encode()).hexdigest(), "title": title, "url": original,
                "excerpt": summary, "publishedAt": iso_timestamp(published_at), "category": category,
                "cves": cves, "score": 70 + len(matched) * 25, "matchedTerms": matched,
                "source": {"id": f"web-{normalized_search_text(source_name).replace(' ', '-')[:50]}",
                           "name": source_name, "homepage": urllib.parse.urlunsplit((urllib.parse.urlsplit(original).scheme, urllib.parse.urlsplit(original).netloc, "/", "", "")),
                           "kind": "Recherche web · Bing Actualités"},
            })
            known_urls.add(original)
    except Exception as error:
        live_error = str(error)[:180]

    # A CVE query must also search the authoritative NVD window. This avoids
    # false empty states when a vendor advisory has not reached an RSS feed yet.
    nvd_error = ""
    period_expanded = False
    if "cve" in tokens or not results:
        try:
            nvd_terms = [token for token in tokens if token not in {"cve", "cves", "vulnerability", "vulnerabilite"}]
            if nvd_terms:
                nvd_days = min(days, 120)
                start = datetime.fromtimestamp(now - nvd_days * 86400, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                end = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.999Z")
                nvd_url = NVD_API + "?" + urllib.parse.urlencode({
                    "keywordSearch": " ".join(nvd_terms), "pubStartDate": start,
                    "pubEndDate": end, "resultsPerPage": 50,
                })
                nvd = fetch_json(nvd_url)
                if not nvd.get("vulnerabilities") and days < 3650:
                    nvd_url = NVD_API + "?" + urllib.parse.urlencode({
                        "keywordSearch": " ".join(nvd_terms), "resultsPerPage": 100,
                    })
                    nvd = fetch_json(nvd_url)
                    period_expanded = bool(nvd.get("vulnerabilities"))
                known_ids = {item["id"] for item in results}
                for wrapper in nvd.get("vulnerabilities", []):
                    cve = wrapper.get("cve", {})
                    cve_id = cve.get("id", "")
                    if not cve_id or cve_id in known_ids:
                        continue
                    descriptions = cve.get("descriptions", [])
                    description = next((item.get("value", "") for item in descriptions if item.get("lang") == "fr"), "")
                    if not description:
                        description = next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "")
                    published = cve.get("published", "")
                    published_at = parse_published_at(published, now)
                    title = f"{cve_id} · {clean_excerpt(description, 150)}"
                    searchable = normalized_search_text(f"{cve_id} {description}")
                    matched = [token for token in tokens if normalized_search_text(token) in searchable]
                    results.append({
                        "id": cve_id, "title": title,
                        "url": f"https://nvd.nist.gov/vuln/detail/{urllib.parse.quote(cve_id)}",
                        "excerpt": clean_excerpt(description, 360), "publishedAt": iso_timestamp(published_at),
                        "category": "Vulnérabilités & correctifs", "cves": [cve_id],
                        "score": 95 + len(matched) * 20, "matchedTerms": matched,
                        "outsidePeriod": published_at < cutoff,
                        "source": {"id": "nvd", "name": "NVD / NIST", "homepage": "https://nvd.nist.gov/",
                                   "kind": "Base officielle de vulnérabilités"},
                    })
                    known_ids.add(cve_id)
        except Exception as error:
            nvd_error = str(error)[:180]

    if sort == "relevance":
        results.sort(key=lambda item: (item["score"], item["publishedAt"]), reverse=True)
    else:
        sort = "recent"
        results.sort(key=lambda item: (item["publishedAt"], item["score"]), reverse=True)
    results = results[:limit]
    return {
        "query": query, "normalizedQuery": normalized_query, "corrections": corrections,
        "generatedAt": iso_timestamp(now), "days": days, "sort": sort,
        "results": results, "total": len(results), "sources": feed_statuses(),
        "webSearch": {"active": not bool(live_error), "provider": "Bing Actualités", "error": live_error or None},
        "nvdSearch": {"active": not bool(nvd_error), "error": nvd_error or None},
        "periodExpanded": period_expanded,
        "method": "Recherche tolérante aux fautes, fusion de l’archive OpenVigie, de l’actualité web et du NVD, avec élargissement automatique si la période ne contient aucun résultat CVE.",
    }


def build_leak_watch(days: int = 0) -> dict:
    """Return attributed French breach registries plus major international actors."""
    now = int(time.time())
    days = min(3650, max(0, days))
    if days == 0:
        cutoff = 0
        period_label = "Tout l’historique"
    elif days == 1:
        local_now = datetime.fromtimestamp(now, PARIS)
        cutoff = int(local_now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
        period_label = "Aujourd’hui"
    else:
        cutoff = now - days * 86400
        period_label = f"Les {days} derniers jours"
    french_ids = ("french-breaches", "bonjour-la-fuite")
    actors = ("microsoft", "apple", "openai", "google", "alphabet", "amazon", "aws", "meta", "facebook")
    leak_terms = ("breach", "leak", "stolen data", "exposed data", "fuite", "vol de donnees", "donnees volees")

    with database_lock, connect() as connection:
        french_rows = connection.execute(
            "SELECT * FROM articles WHERE published_at >= ? AND source_id IN (?, ?) ORDER BY published_at DESC",
            (cutoff, *french_ids),
        ).fetchall()
        candidates = connection.execute(
            "SELECT * FROM articles WHERE published_at >= ? AND source_id NOT IN (?, ?) ORDER BY published_at DESC LIMIT 500",
            (cutoff, *french_ids),
        ).fetchall()

    def serialize(row: sqlite3.Row, scope: str, actor: str = "") -> dict:
        return {
            "id": row["id"], "title": row["title"], "url": row["url"],
            "excerpt": row["summary"], "publishedAt": iso_timestamp(row["published_at"]),
            "category": row["category"], "scope": scope, "actor": actor,
            "source": {"id": row["source_id"], "name": row["source_name"],
                       "homepage": row["source_home"], "kind": row["source_kind"]},
        }

    french = [serialize(row, "france") for row in french_rows]
    international = []
    for row in candidates:
        searchable = normalized_search_text(f"{row['title']} {row['summary']}")
        actor = next((name for name in actors if name in searchable), "")
        if actor and any(term in searchable for term in leak_terms):
            international.append(serialize(row, "international", actor.title()))

    items = sorted(french + international, key=lambda item: item["publishedAt"], reverse=True)
    return {
        "generatedAt": iso_timestamp(now), "days": days,
        "period": {"label": period_label, "start": iso_timestamp(cutoff), "end": iso_timestamp(now)},
        "items": items, "counts": {"france": len(french), "international": len(international)},
        "watchlist": ["Microsoft", "Apple", "OpenAI", "Google / Alphabet", "Amazon / AWS", "Meta"],
        "sources": [
            {"name": "FrenchBreaches", "url": "https://frenchbreaches.com/", "status": "online"},
            {"name": "BonjourLaFuite", "url": "https://bonjourlafuite.eu.org/", "status": "online"},
        ],
        "method": "Flux RSS officiels français et veille internationale des grands acteurs, triés du plus récent au plus ancien.",
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


def related_articles(query: dict[str, str], vulnerabilities: list[dict]) -> list[dict]:
    """Correlate the monitored asset with recent attributed bulletin entries."""
    cve_ids = {item["id"] for item in vulnerabilities if item.get("id")}
    raw_terms = " ".join((
        query.get("vendor", ""), query.get("product", ""),
        query.get("cpeVendor", "").replace("_", " "),
        query.get("cpeProduct", "").replace("_", " "),
    ))
    ignored = {"server", "desktop", "linux", "network", "networks", "system", "software", "secure", "manager", "agent"}
    terms = {
        term for term in re.findall(r"[a-z0-9][a-z0-9.+-]{2,}", normalized_search_text(raw_terms))
        if term not in ignored and len(term) >= 4
    }
    with database_lock, connect() as connection:
        rows = connection.execute(
            "SELECT * FROM articles WHERE published_at >= ? ORDER BY published_at DESC LIMIT 600",
            (int(time.time()) - 120 * 86400,),
        ).fetchall()

    matches: list[tuple[int, sqlite3.Row, list[str]]] = []
    for row in rows:
        article_cves = set(json.loads(row["cves_json"] or "[]"))
        shared_cves = sorted(cve_ids.intersection(article_cves))
        searchable = normalized_search_text(f"{row['title']} {row['summary']}")
        matching_terms = sorted(term for term in terms if term in searchable)
        if not shared_cves and not matching_terms:
            continue
        score = len(shared_cves) * 100 + len(matching_terms) * 10
        if row["source_id"] == "cert-fr-alertes":
            score += 35
        elif row["source_id"] == "cert-fr-avis":
            score += 25
        if query.get("version") and query["version"].lower() in searchable:
            score += 8
        reasons = [*shared_cves[:3], *matching_terms[:3]]
        matches.append((score, row, reasons))
    matches.sort(key=lambda item: (item[0], item[1]["published_at"]), reverse=True)
    return [{
        "id": row["id"], "title": row["title"], "url": row["url"],
        "excerpt": row["summary"], "publishedAt": iso_timestamp(row["published_at"]),
        "category": row["category"], "cves": json.loads(row["cves_json"] or "[]"),
        "source": {"id": row["source_id"], "name": row["source_name"], "homepage": row["source_home"]},
        "matchReasons": reasons,
    } for _, row, reasons in matches[:12]]


def attach_related_articles(payload: dict, query: dict[str, str]) -> dict:
    enriched = dict(payload)
    enriched["relatedArticles"] = related_articles(query, payload.get("vulnerabilities", []))
    return enriched


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
        return attach_related_articles(payload, query)

    with lock_for(key):
        row = read_cached(key)
        now = int(time.time())
        if not force and row and row["payload_json"] and (row["last_success"] or 0) + REFRESH_SECONDS > now:
            payload = json.loads(row["payload_json"])
            payload["cached"] = True
            return attach_related_articles(payload, query)
        try:
            payload = collect(query)
            with database_lock, connect() as connection:
                connection.execute(
                    "UPDATE monitored_queries SET payload_json=?, last_attempt=?, last_success=?, next_refresh=?, last_error=NULL WHERE cache_key=?",
                    (json.dumps(payload, separators=(",", ":")), now, now, now + REFRESH_SECONDS, key),
                )
            return attach_related_articles(payload, query)
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
                return attach_related_articles(payload, query)
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
        connection.execute(
            "DELETE FROM articles WHERE published_at < ? AND source_id NOT IN ('french-breaches', 'bonjour-la-fuite')",
            (cutoff,),
        )
        connection.execute("PRAGMA optimize")


def feed_scheduler() -> None:
    last_cleanup = 0
    last_history_refresh = 0
    while True:
        refresh_due_feeds(limit=5)
        now = int(time.time())
        if last_history_refresh < now - 21600:
            try:
                print(f"leak histories refreshed: {refresh_leak_histories()} indexed entries", flush=True)
            except Exception as error:
                print(f"leak history refresh failed: {error}", flush=True)
            last_history_refresh = now
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
                limit = min(100, max(1, limit))
                self.send_json(200, build_bulletin(cadence, limit, category))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            except Exception as error:
                print(f"bulletin error: {error}", flush=True)
                self.send_json(500, {"error": "Erreur interne du bulletin"})
            return
        if parsed.path == "/ai/news-brief":
            try:
                parameters = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                cadence = parameters.get("cadence", ["daily"])[0]
                topic = parameters.get("topic", [""])[0]
                limit = min(20, max(3, int(parameters.get("limit", ["12"])[0])))
                self.send_json(200, build_ai_news_brief(cadence, limit, topic))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            except RuntimeError as error:
                self.send_json(503, {"error": str(error)})
            except Exception as error:
                print(f"AI news brief error: {error}", flush=True)
                self.send_json(500, {"error": "Erreur interne de la synthèse IA"})
            return
        if parsed.path == "/search":
            try:
                parameters = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                query = parameters.get("q", [""])[0]
                source_id = parameters.get("source", [""])[0].strip()
                sort = parameters.get("sort", ["recent"])[0].strip()
                limit = min(60, max(1, int(parameters.get("limit", ["30"])[0])))
                days = min(3650, max(1, int(parameters.get("days", ["365"])[0])))
                self.send_json(200, search_articles(query, limit, days, source_id, sort))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            except Exception as error:
                print(f"search error: {error}", flush=True)
                self.send_json(500, {"error": "Erreur interne de la recherche"})
            return
        if parsed.path == "/leaks":
            try:
                parameters = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                days = int(parameters.get("days", ["0"])[0])
                self.send_json(200, build_leak_watch(days))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            except Exception as error:
                print(f"leak watch error: {error}", flush=True)
                self.send_json(500, {"error": "Erreur interne de la veille fuites"})
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

    def do_POST(self) -> None:  # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        if path == "/ai/chat":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 0 or length > 200_000:
                    raise ValueError("Corps de requête trop volumineux")
                payload = json.loads(self.rfile.read(length) or b"{}")
                messages = payload.get("messages", [])
                if not isinstance(messages, list) or not messages:
                    raise ValueError("messages doit être une liste non vide")
                assets = payload.get("assets", [])
                if not isinstance(assets, list):
                    raise ValueError("assets doit être une liste")
                cadence = str(payload.get("cadence", "daily"))
                self.send_json(200, build_vigi_reply(messages, assets, cadence))
            except (ValueError, json.JSONDecodeError) as error:
                self.send_json(400, {"error": str(error)})
            except RuntimeError as error:
                self.send_json(503, {"error": str(error)})
            except Exception as error:
                print(f"Vigi chat error: {error}", flush=True)
                self.send_json(500, {"error": "Erreur interne de Vigi"})
            return
        if path != "/ai/triage":
            self.send_json(404, {"error": "Route inconnue"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 200_000:
                raise ValueError("Corps de requête trop volumineux")
            payload = json.loads(self.rfile.read(length) or b"{}")
            cadence = str(payload.get("cadence", "daily"))
            limit = min(30, max(3, int(payload.get("limit", 12))))
            assets = payload.get("assets", [])
            if not isinstance(assets, list):
                raise ValueError("assets doit être une liste")
            self.send_json(200, build_ai_triage(cadence, limit, assets))
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error)})
        except RuntimeError as error:
            self.send_json(503, {"error": str(error)})
        except Exception as error:
            print(f"AI triage error: {error}", flush=True)
            self.send_json(500, {"error": "Erreur interne du tri IA"})

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
