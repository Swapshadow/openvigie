from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "output" / "pdf" / "OpenVigie_matrice_de_veille_Qwen3.pdf"
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

PAGE_W, PAGE_H = landscape(A4)
NAVY = colors.HexColor("#0d2333")
ORANGE = colors.HexColor("#ff7417")
CYAN = colors.HexColor("#008da3")
BLUE = colors.HexColor("#315fc7")
GREEN = colors.HexColor("#16834d")
AMBER = colors.HexColor("#a76b00")
RED = colors.HexColor("#bd3e3e")
INK = colors.HexColor("#12212c")
MUTED = colors.HexColor("#526877")
PALE = colors.HexColor("#edf3f6")
PALE_BLUE = colors.HexColor("#eaf0fb")
LINE = colors.HexColor("#b8cbd4")
WHITE = colors.white

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="CoverKicker", fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=ORANGE, tracking=1.5, spaceAfter=9))
styles.add(ParagraphStyle(name="CoverTitle", fontName="Helvetica-Bold", fontSize=31, leading=34, textColor=WHITE, spaceAfter=13))
styles.add(ParagraphStyle(name="CoverLead", fontName="Helvetica", fontSize=12.5, leading=18, textColor=colors.HexColor("#c9d7df"), spaceAfter=16))
styles.add(ParagraphStyle(name="Section", fontName="Helvetica-Bold", fontSize=8.2, leading=10, textColor=ORANGE, tracking=1.0, spaceAfter=6))
styles.add(ParagraphStyle(name="H1", fontName="Helvetica-Bold", fontSize=22, leading=25, textColor=INK, spaceAfter=10))
styles.add(ParagraphStyle(name="H2", fontName="Helvetica-Bold", fontSize=13.5, leading=16, textColor=INK, spaceBefore=8, spaceAfter=5))
styles.add(ParagraphStyle(name="Body", fontName="Helvetica", fontSize=9.1, leading=13.2, textColor=INK, spaceAfter=7))
styles.add(ParagraphStyle(name="Small", fontName="Helvetica", fontSize=7.4, leading=10, textColor=MUTED, spaceAfter=3))
styles.add(ParagraphStyle(name="BulletX", fontName="Helvetica", fontSize=8.8, leading=12.5, textColor=INK, leftIndent=12, firstLineIndent=-7, spaceAfter=4))
styles.add(ParagraphStyle(name="Callout", fontName="Helvetica", fontSize=9.2, leading=13.2, textColor=INK, leftIndent=8, rightIndent=8, borderPadding=8, backColor=colors.HexColor("#e7f5f7"), spaceAfter=8))
styles.add(ParagraphStyle(name="TH", fontName="Helvetica-Bold", fontSize=6.8, leading=8, textColor=WHITE))
styles.add(ParagraphStyle(name="TC", fontName="Helvetica", fontSize=6.5, leading=8.4, textColor=INK))
styles.add(ParagraphStyle(name="TCB", fontName="Helvetica-Bold", fontSize=6.5, leading=8.4, textColor=INK))
styles.add(ParagraphStyle(name="URL", fontName="Helvetica", fontSize=5.8, leading=7.3, textColor=CYAN, wordWrap="CJK"))
styles.add(ParagraphStyle(name="Score", fontName="Helvetica-Bold", fontSize=7.2, leading=8.5, textColor=INK, alignment=1))
styles.add(ParagraphStyle(name="CoverCell", fontName="Helvetica", fontSize=7.4, leading=10, textColor=colors.HexColor("#d8e5ea")))


def P(text, style="Body"):
    return Paragraph(text, styles[style])


def bullet(text):
    return Paragraph(f"• {text}", styles["BulletX"])


SOURCES = [
    {
        "axis": "Vulnérabilités et exploitation", "question": "Une alerte critique concerne-t-elle un produit exposé du parc ?",
        "keywords": "CVE, RCE, zero-day, exploitation active, critique, correctif, SonicWall, Ivanti, Microsoft",
        "source": "CERT-FR - Alertes", "family": "Autorité / CERT", "home": "https://cert.ssi.gouv.fr/alerte/", "feed": "https://cert.ssi.gouv.fr/alerte/feed/", "format": "RSS/XML",
        "freq": "30 min", "criticality": "3 - Immédiate", "scores": (5, 5, 5, 5),
    },
    {
        "axis": "Vulnérabilités et exploitation", "question": "Quels avis et correctifs officiels concernent les versions du parc ?",
        "keywords": "CVE, avis, produit, version, vulnérabilité, mitigation, correctif, patch",
        "source": "CERT-FR - Avis", "family": "Autorité / CERT", "home": "https://cert.ssi.gouv.fr/avis/", "feed": "https://cert.ssi.gouv.fr/avis/feed/", "format": "RSS/XML",
        "freq": "1 h", "criticality": "2 - Haute", "scores": (5, 5, 5, 5),
    },
    {
        "axis": "Vulnérabilités et exploitation", "question": "Une vulnérabilité ou campagne exige-t-elle une action défensive rapide ?",
        "keywords": "advisory, vulnerability, ICS, malware, campaign, mitigation, exploited, CVE",
        "source": "CISA - Cybersecurity Advisories", "family": "Autorité / CERT", "home": "https://www.cisa.gov/news-events/cybersecurity-advisories", "feed": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "format": "RSS/XML",
        "freq": "1 h", "criticality": "2 - Haute", "scores": (5, 5, 5, 5),
    },
    {
        "axis": "Vulnérabilités et exploitation", "question": "Une CVE présente dans le parc est-elle exploitée dans des attaques réelles ?",
        "keywords": "cveID, dateAdded, dueDate, requiredAction, ransomware, known exploited",
        "source": "CISA - Known Exploited Vulnerabilities", "family": "Base officielle", "home": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "feed": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "format": "JSON",
        "freq": "1 h", "criticality": "3 - Immédiate", "scores": (5, 5, 5, 5),
    },
    {
        "axis": "Vulnérabilités et exploitation", "question": "Quelles CVE, sévérités et références correspondent aux produits suivis ?",
        "keywords": "CVE, CVSS, CPE, CWE, vendor, product, version, published, modified",
        "source": "NVD / NIST - CVE API 2.0", "family": "Base officielle", "home": "https://nvd.nist.gov/developers/vulnerabilities", "feed": "https://services.nvd.nist.gov/rest/json/cves/2.0", "format": "API JSON",
        "freq": "6 h", "criticality": "2 - Haute", "scores": (5, 5, 4, 5),
    },
    {
        "axis": "Vulnérabilités et exploitation", "question": "Quels avis affectent les institutions et environnements européens ?",
        "keywords": "security advisory, CVE, critical, EU, exploit, update, vulnerability",
        "source": "CERT-EU - Security Advisories", "family": "Autorité / CERT", "home": "https://cert.europa.eu/publications/security-advisories/", "feed": "https://cert.europa.eu/publications/security-advisories-rss", "format": "RSS/XML",
        "freq": "3 h", "criticality": "2 - Haute", "scores": (5, 4, 5, 5),
    },
    {
        "axis": "Correctifs éditeurs / parc", "question": "Quelles mises à jour Microsoft concernent les produits et versions déclarés ?",
        "keywords": "Microsoft, Windows, Exchange, SharePoint, CVE, security update, KB, exploited",
        "source": "Microsoft Security Response Center", "family": "PSIRT éditeur", "home": "https://msrc.microsoft.com/update-guide/", "feed": "https://api.msrc.microsoft.com/update-guide/rss", "format": "RSS/XML",
        "freq": "3 h", "criticality": "2 - Haute", "scores": (5, 5, 5, 5),
    },
    {
        "axis": "Correctifs éditeurs / parc", "question": "Quels avis Cisco affectent les équipements réseau, VPN ou sécurité suivis ?",
        "keywords": "Cisco, IOS, IOS XE, ASA, Firepower, AnyConnect, CVE, vulnerable, fixed release",
        "source": "Cisco PSIRT", "family": "PSIRT éditeur", "home": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x", "feed": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", "format": "RSS/XML",
        "freq": "3 h", "criticality": "2 - Haute", "scores": (5, 5, 5, 5),
    },
    {
        "axis": "Correctifs éditeurs / parc", "question": "Quels avis Palo Alto touchent les pare-feu et passerelles exposés ?",
        "keywords": "Palo Alto, PAN-OS, GlobalProtect, Prisma, CVE, exploit, severity, fixed version",
        "source": "Palo Alto Networks PSIRT", "family": "PSIRT éditeur", "home": "https://security.paloaltonetworks.com/", "feed": "https://security.paloaltonetworks.com/rss.xml", "format": "RSS/XML",
        "freq": "1 h", "criticality": "3 - Immédiate", "scores": (5, 5, 5, 5),
    },
    {
        "axis": "Menaces et détection", "question": "Quels groupes, outils et techniques d'attaque émergent dans la recherche ?",
        "keywords": "APT, threat actor, malware, ransomware, campaign, IOC, TTP, MITRE ATT&CK",
        "source": "SentinelLabs", "family": "Recherche spécialisée", "home": "https://www.sentinelone.com/labs/", "feed": "https://www.sentinelone.com/labs/feed/", "format": "RSS/XML",
        "freq": "3 h", "criticality": "2 - Haute", "scores": (4, 5, 4, 5),
    },
    {
        "axis": "Menaces et détection", "question": "Quels modes opératoires et IOC sont observés par Cisco Talos ?",
        "keywords": "Talos, threat actor, malware, IOC, phishing, ransomware, vulnerability, campaign",
        "source": "Cisco Talos Intelligence", "family": "Recherche spécialisée", "home": "https://blog.talosintelligence.com/", "feed": "https://blog.talosintelligence.com/rss/", "format": "RSS/XML",
        "freq": "3 h", "criticality": "2 - Haute", "scores": (4, 5, 4, 5),
    },
    {
        "axis": "Menaces et détection", "question": "Quelles campagnes et techniques sont documentées par Unit 42 ?",
        "keywords": "Unit 42, APT, incident response, malware, ransomware, IOC, cloud, campaign",
        "source": "Unit 42", "family": "Recherche spécialisée", "home": "https://unit42.paloaltonetworks.com/", "feed": "https://unit42.paloaltonetworks.com/feed/", "format": "RSS/XML",
        "freq": "3 h", "criticality": "2 - Haute", "scores": (4, 5, 4, 5),
    },
    {
        "axis": "Supply chain logicielle", "question": "Quels risques affectent les dépendances, SBOM et chaînes de construction ?",
        "keywords": "OpenSSF, supply chain, dependency, SBOM, SLSA, Sigstore, package, provenance, CRA",
        "source": "OpenSSF", "family": "Communauté / fondation", "home": "https://openssf.org/blog/", "feed": "https://openssf.org/feed/", "format": "RSS/XML",
        "freq": "12 h", "criticality": "1 - Normale", "scores": (4, 5, 4, 5),
    },
    {
        "axis": "Supply chain logicielle", "question": "Quelles menaces et défenses concernent les dépôts et workflows logiciels ?",
        "keywords": "GitHub, Actions, dependency, malicious package, secret, repository, artifact, supply chain",
        "source": "GitHub - Supply Chain Security", "family": "PSIRT / éditeur", "home": "https://github.blog/security/supply-chain-security/", "feed": "https://github.blog/security/supply-chain-security/feed/", "format": "RSS/XML",
        "freq": "12 h", "criticality": "1 - Normale", "scores": (4, 5, 4, 5),
    },
    {
        "axis": "Stratégie et réglementation", "question": "Quelles orientations françaises modifient les priorités de cybersécurité ?",
        "keywords": "ANSSI, NIS2, réglementation, stratégie, souveraineté, certification, recommandation",
        "source": "ANSSI / cyber.gouv.fr - Actualités", "family": "Autorité nationale", "home": "https://cyber.gouv.fr/actualites/", "feed": "https://cyber.gouv.fr/actualites/rss/", "format": "RSS/XML",
        "freq": "12 h", "criticality": "1 - Normale", "scores": (5, 4, 4, 5),
    },
]


def page_chrome(c: canvas.Canvas, doc):
    if c.getPageNumber() == 1:
        return
    c.saveState()
    c.setStrokeColor(LINE)
    c.setLineWidth(.5)
    c.line(15 * mm, PAGE_H - 12 * mm, PAGE_W - 15 * mm, PAGE_H - 12 * mm)
    c.setFont("Helvetica-Bold", 7)
    c.setFillColor(CYAN)
    c.drawString(15 * mm, PAGE_H - 9 * mm, "OPENVIGIE")
    c.setFont("Helvetica", 7)
    c.setFillColor(MUTED)
    c.drawRightString(PAGE_W - 15 * mm, PAGE_H - 9 * mm, "Matrice hypothétique des flux confrontés par Qwen3")
    c.line(15 * mm, 11 * mm, PAGE_W - 15 * mm, 11 * mm)
    c.drawString(15 * mm, 7 * mm, "Livrable pédagogique - Sources contrôlées le 3 septembre 2026")
    c.drawRightString(PAGE_W - 15 * mm, 7 * mm, str(c.getPageNumber()))
    c.restoreState()


def cover(c: canvas.Canvas, doc):
    c.saveState()
    c.setFillColor(NAVY)
    c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    c.setFillColor(colors.HexColor("#18374c"))
    c.circle(PAGE_W - 15 * mm, PAGE_H - 15 * mm, 70 * mm, fill=1, stroke=0)
    c.setFillColor(ORANGE)
    c.rect(0, 0, 8 * mm, PAGE_H, fill=1, stroke=0)
    c.restoreState()


def matrix_table(rows):
    data = [[P("AXE", "TH"), P("QUESTION DE VEILLE", "TH"), P("MOTS-CLÉS ET VARIANTES", "TH"), P("SOURCE, URL ET FLUX", "TH"), P("FRÉQUENCE", "TH"), P("CRITICITÉ", "TH")]]
    for s in rows:
        source = (
            f"<b>{s['source']}</b><br/>"
            f"Site : <link href='{s['home']}' color='#008da3'>{s['home']}</link><br/>"
            f"Flux : <link href='{s['feed']}' color='#008da3'>{s['feed']}</link><br/>"
            f"Format : {s['format']}"
        )
        data.append([
            P(s["axis"], "TCB"), P(s["question"], "TC"), P(s["keywords"], "TC"),
            P(source, "URL"), P(s["freq"], "TC"), P(s["criticality"], "TCB"),
        ])
    table = Table(data, colWidths=[29 * mm, 49 * mm, 48 * mm, 96 * mm, 22 * mm, 23 * mm], repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
        ("GRID", (0, 0), (-1, -1), .4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    for row_idx, s in enumerate(rows, start=1):
        if s["criticality"].startswith("3"):
            table.setStyle(TableStyle([("BACKGROUND", (5, row_idx), (5, row_idx), colors.HexColor("#fde8e5")), ("TEXTCOLOR", (5, row_idx), (5, row_idx), RED)]))
        elif s["criticality"].startswith("2"):
            table.setStyle(TableStyle([("TEXTCOLOR", (5, row_idx), (5, row_idx), AMBER)]))
    return table


doc = SimpleDocTemplate(
    str(OUTPUT), pagesize=landscape(A4), leftMargin=15 * mm, rightMargin=15 * mm,
    topMargin=18 * mm, bottomMargin=16 * mm,
    title="OpenVigie - Matrice de veille confrontée par Qwen3",
    author="OpenVigie", subject="Matrice hypothétique de 15 sources RSS, XML, API et JSON",
)
story = []

# Cover
story += [
    Spacer(1, 25 * mm),
    P("FIL ROUGE  /  LIVRABLE DE VEILLE", "CoverKicker"),
    P("Matrice hypothétique<br/>des flux confrontés<br/>par Qwen3", "CoverTitle"),
    P("OpenVigie - 15 sources réelles, cinq axes de veille, quatre familles de sources et une priorisation limitée à trois alertes immédiates.", "CoverLead"),
    Spacer(1, 7 * mm),
]
cover_data = [
    [P("PÉRIMÈTRE", "TH"), P("MÉTHODE", "TH"), P("CONTRÔLE", "TH")],
    [P("Vulnérabilités, parc, menaces, supply chain et stratégie", "CoverCell"), P("Matrice à six colonnes et notation sur quatre critères", "CoverCell"), P("15 points d'accès testés en HTTP 200 le 03/09/2026", "CoverCell")],
]
cover_table = Table(cover_data, colWidths=[89 * mm, 89 * mm, 89 * mm])
cover_table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d4359")),
    ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#112c3c")),
    ("TEXTCOLOR", (0, 1), (-1, 1), colors.HexColor("#d8e5ea")),
    ("GRID", (0, 0), (-1, -1), .5, colors.HexColor("#3d6072")),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
]))
story += [cover_table, Spacer(1, 19 * mm), P("Document destiné à l'enseignant - Matrice pédagogique et architecture cible", "CoverKicker"), PageBreak()]

# Methodology
story += [P("01  /  CADRAGE ET MÉTHODE", "Section"), P("Comment lire cette matrice", "H1")]
story += [
    P("La matrice décrit les flux que le système OpenVigie pourra soumettre à Qwen3 après récupération et normalisation. Elle est hypothétique sur le rôle futur de l'IA, mais ses 15 sources et points d'accès sont réels. Les URL ont été contrôlées techniquement le 3 septembre 2026."),
    P("Les six colonnes attendues", "H2"),
]
six = [
    [P("1. Axe", "TCB"), P("Domaine couvert issu du périmètre de veille.", "TC")],
    [P("2. Question", "TCB"), P("Question précise et vérifiable à laquelle la ligne doit répondre.", "TC")],
    [P("3. Mots-clés", "TCB"), P("Termes de recherche, variantes, produits et alias d'acteurs.", "TC")],
    [P("4. Sources", "TCB"), P("Source concrète, page officielle, point d'accès et format technique.", "TC")],
    [P("5. Fréquence", "TCB"), P("Rythme conseillé de consultation ou de relève automatique.", "TC")],
    [P("6. Criticité", "TCB"), P("Poids opérationnel : 1 normale, 2 haute, 3 immédiate.", "TC")],
]
six_table = Table(six, colWidths=[36 * mm, 95 * mm] * 2)
# Reformat to 2-column pairs across 3 rows.
six_table = Table([[*six[i][0:2], *six[i + 3][0:2]] for i in range(3)], colWidths=[34 * mm, 93 * mm, 34 * mm, 93 * mm])
six_table.setStyle(TableStyle([
    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [PALE, colors.white]), ("GRID", (0, 0), (-1, -1), .4, LINE),
    ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 7),
    ("RIGHTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
]))
story += [six_table, Spacer(1, 6 * mm), P("Grille de notation des sources", "H2")]
score_method = [
    [P("CRITÈRE", "TH"), P("QUESTION DE NOTATION", "TH"), P("NOTE 5", "TH")],
    [P("F - Fiabilité", "TCB"), P("La source est-elle officielle, primaire ou reconnue ?", "TC"), P("Source officielle ou équipe de référence", "TC")],
    [P("R - Pertinence", "TCB"), P("Répond-elle directement aux questions OpenVigie ?", "TC"), P("Impact direct sur les axes et le parc", "TC")],
    [P("A - Actualité", "TCB"), P("La publication est-elle régulière et suffisamment rapide ?", "TC"), P("Mise à jour fréquente et datée", "TC")],
    [P("T - Traitabilité", "TCB"), P("Le contenu est-il exploitable automatiquement ?", "TC"), P("RSS, XML, JSON ou API stable", "TC")],
]
score_method_table = Table(score_method, colWidths=[42 * mm, 122 * mm, 103 * mm], repeatRows=1)
score_method_table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), NAVY), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
    ("GRID", (0, 0), (-1, -1), .4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
]))
story += [score_method_table, Spacer(1, 5 * mm), P("Seuil retenu : moyenne minimale de 4,0/5. Toutes les sources ci-dessous atteignent ce seuil. Une vérification éditoriale et technique périodique reste nécessaire.", "Callout"), PageBreak()]

# Matrix pages, five rows each
groups = [
    ("02", "MATRICE 1/3 - Sources officielles et vulnérabilités", SOURCES[:5]),
    ("03", "MATRICE 2/3 - CERT européen, PSIRT et menace", SOURCES[5:10]),
    ("04", "MATRICE 3/3 - Menace, supply chain et stratégie", SOURCES[10:]),
]
for number, title, rows in groups:
    story += [P(f"{number}  /  MATRICE DE VEILLE", "Section"), P(title, "H1"), matrix_table(rows), PageBreak()]

# Scoring
story += [P("05  /  ÉVALUATION DES SOURCES", "Section"), P("Scoring sur quatre critères", "H1")]
score_rows = [[P("SOURCE", "TH"), P("FAMILLE", "TH"), P("F", "TH"), P("R", "TH"), P("A", "TH"), P("T", "TH"), P("MOY.", "TH"), P("DÉCISION", "TH"), P("JUSTIFICATION", "TH")]]
for s in SOURCES:
    avg = sum(s["scores"]) / 4
    score_rows.append([
        P(s["source"], "TCB"), P(s["family"], "TC"), *[P(str(n), "Score") for n in s["scores"]],
        P(f"{avg:.2f}", "Score"), P("Retenue", "TCB"),
        P("Source primaire ou reconnue, pertinente et techniquement automatisable.", "TC"),
    ])
score_table = Table(score_rows, colWidths=[56 * mm, 39 * mm, 10 * mm, 10 * mm, 10 * mm, 10 * mm, 15 * mm, 22 * mm, 95 * mm], repeatRows=1)
score_table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), NAVY), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
    ("GRID", (0, 0), (-1, -1), .38, LINE), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ("TEXTCOLOR", (7, 1), (7, -1), GREEN), ("ALIGN", (2, 1), (7, -1), "CENTER"),
    ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
]))
story += [score_table, Spacer(1, 4 * mm)]
families = sorted(set(s["family"] for s in SOURCES))
story += [P(f"Résultat : 15 sources retenues, {len(families)} familles représentées, cinq axes couverts et exactement trois lignes en criticité immédiate.", "Callout"), PageBreak()]

# Qwen confrontation
story += [P("06  /  CONFRONTATION PAR QWEN3", "Section"), P("Ce que Qwen3 devra comparer", "H1")]
story += [
    P("Qwen3 ne reçoit pas un flux unique. Il confronte plusieurs descriptions d'un même fait afin de produire une vue cohérente, tout en conservant l'origine de chaque information."),
]
compare = [
    [P("SIGNAL", "TH"), P("SOURCES CONFRONTÉES", "TH"), P("TRAITEMENT ATTENDU", "TH"), P("RÈGLE PRIORITAIRE", "TH")],
    [P("Nouvelle CVE", "TCB"), P("NVD + CERT-FR Avis + PSIRT éditeur", "TC"), P("Fusionner l'identifiant, la description, le produit et les versions ; supprimer les doublons.", "TC"), P("La version affectée doit être confirmée par l'avis éditeur.", "TC")],
    [P("Exploitation active", "TCB"), P("CISA KEV + CERT-FR Alertes + CISA Advisories", "TC"), P("Identifier l'exploitation réelle, résumer l'urgence et produire une alerte.", "TC"), P("La présence dans KEV impose un plancher de priorité élevé.", "TC")],
    [P("Campagne de menace", "TCB"), P("SentinelLabs + Talos + Unit 42", "TC"), P("Regrouper les alias d'acteurs, TTP, logiciels malveillants et IOC communs.", "TC"), P("Les IOC restent attribués et datés ; aucune invention n'est admise.", "TC")],
    [P("Risque supply chain", "TCB"), P("OpenSSF + GitHub Supply Chain", "TC"), P("Classer dépendances, paquets, SBOM, provenance et sécurité des workflows.", "TC"), P("La pertinence dépend des technologies réellement déclarées dans le parc.", "TC")],
    [P("Contexte français", "TCB"), P("ANSSI + CERT-FR", "TC"), P("Relier orientations nationales, alertes techniques et recommandations.", "TC"), P("Une actualité institutionnelle ne remplace pas un avis technique.", "TC")],
]
compare_table = Table(compare, colWidths=[42 * mm, 62 * mm, 96 * mm, 67 * mm], repeatRows=1)
compare_table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), NAVY), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE_BLUE]),
    ("GRID", (0, 0), (-1, -1), .4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
]))
story += [compare_table, Spacer(1, 6 * mm), P("Sortie structurée attendue", "H2")]
story += [
    bullet("Déduplication et identifiant de groupe pour les publications décrivant le même événement."),
    bullet("Classification : vulnérabilité, menace, détection, conformité, supply chain ou autre."),
    bullet("Résumé français, niveau d'incertitude et liens vers toutes les sources utilisées."),
    bullet("Entités : CVE, éditeur, produit, version, APT, malware, technique et IOC."),
    bullet("Pertinence pour le parc et justification de la priorité proposée."),
    P("Hiérarchie obligatoire : avis éditeur, NVD, CISA KEV et correspondance exacte avec le parc priment toujours sur le score produit par Qwen3.", "Callout"),
    PageBreak(),
]

# Operational rule and references
story += [P("07  /  EXPLOITATION ET TRAÇABILITÉ", "Section"), P("Du flux à l'alerte OpenVigie", "H1")]
pipeline = [
    [P("1. RELÈVE", "TH"), P("2. NORMALISATION", "TH"), P("3. CONFRONTATION IA", "TH"), P("4. RÈGLES", "TH"), P("5. DIFFUSION", "TH")],
    [P("Lecture RSS, XML, JSON ou API selon la fréquence définie.", "TC"), P("Titre, date, source, URL, résumé et CVE sont harmonisés.", "TC"), P("Qwen3 déduplique, classe, résume et extrait les entités.", "TC"), P("CVE, versions, parc et KEV imposent la priorité finale.", "TC"), P("Bulletin, matrice du parc et alertes expliquées.", "TC")],
]
pipeline_table = Table(pipeline, colWidths=[53.4 * mm] * 5)
pipeline_table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), NAVY), ("BACKGROUND", (0, 1), (-1, 1), PALE),
    ("GRID", (0, 0), (-1, -1), .4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
]))
story += [pipeline_table, Spacer(1, 6 * mm), P("Règles d'exploitation", "H2")]
story += [
    bullet("Conserver le nom de la source, l'URL d'origine, la date de publication et la date de collecte."),
    bullet("Réévaluer périodiquement le scoring et retirer un flux devenu instable ou hors périmètre."),
    bullet("Ne pas déclencher plus de trois alertes immédiates sans requalification humaine de la matrice."),
    bullet("Afficher un état dégradé si une source est indisponible et servir la dernière donnée connue avec sa date."),
    bullet("Ne jamais présenter une synthèse Qwen3 comme une preuve autonome."),
    P("Contrôle des points d'accès", "H2"),
    P("Les 15 points d'accès listés dans cette matrice ont répondu en HTTP 200 lors du contrôle du 3 septembre 2026. Ce contrôle confirme leur accessibilité à cette date ; il ne garantit pas leur disponibilité future. Les sources doivent rester supervisées par le collecteur.", "Callout"),
    P("Références institutionnelles", "H2"),
    P("CERT-FR : <link href='https://cert.ssi.gouv.fr/' color='#008da3'>https://cert.ssi.gouv.fr/</link> - alertes, avis, rapports de menace et flux RSS officiels.<br/>CISA KEV : <link href='https://www.cisa.gov/known-exploited-vulnerabilities-catalog' color='#008da3'>catalogue des vulnérabilités exploitées</link>.<br/>NVD : <link href='https://nvd.nist.gov/developers/vulnerabilities' color='#008da3'>documentation de l'API CVE 2.0</link>.<br/>OpenSSF : <link href='https://openssf.org/blog/' color='#008da3'>actualité de la sécurité open source</link>.", "Small"),
]

doc.build(story, onFirstPage=cover, onLaterPages=page_chrome)
print(OUTPUT)
