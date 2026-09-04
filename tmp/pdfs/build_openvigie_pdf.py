from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    Flowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "output" / "pdf" / "OpenVigie_dossier_technique_flux_Qwen3.pdf"
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

PAGE_W, PAGE_H = A4
INK = colors.HexColor("#12212c")
MUTED = colors.HexColor("#536775")
NAVY = colors.HexColor("#071722")
PANEL = colors.HexColor("#edf4f6")
CYAN = colors.HexColor("#008ba0")
GREEN = colors.HexColor("#16834d")
BLUE = colors.HexColor("#365fc4")
AMBER = colors.HexColor("#9a6500")
LINE = colors.HexColor("#b9cbd3")
WHITE = colors.white


styles = getSampleStyleSheet()
styles.add(ParagraphStyle(
    name="CoverKicker", fontName="Helvetica-Bold", fontSize=9, leading=12,
    textColor=colors.HexColor("#69dce7"), spaceAfter=12, tracking=1.5,
))
styles.add(ParagraphStyle(
    name="CoverTitle", fontName="Helvetica-Bold", fontSize=32, leading=35,
    textColor=WHITE, spaceAfter=18,
))
styles.add(ParagraphStyle(
    name="CoverLead", fontName="Helvetica", fontSize=13, leading=19,
    textColor=colors.HexColor("#c9d7df"), spaceAfter=18,
))
styles.add(ParagraphStyle(
    name="H1x", fontName="Helvetica-Bold", fontSize=22, leading=26,
    textColor=INK, spaceBefore=2, spaceAfter=13,
))
styles.add(ParagraphStyle(
    name="H2x", fontName="Helvetica-Bold", fontSize=14, leading=18,
    textColor=INK, spaceBefore=12, spaceAfter=7,
))
styles.add(ParagraphStyle(
    name="H3x", fontName="Helvetica-Bold", fontSize=10.5, leading=14,
    textColor=CYAN, spaceBefore=4, spaceAfter=4,
))
styles.add(ParagraphStyle(
    name="BodyX", fontName="Helvetica", fontSize=9.6, leading=14.2,
    textColor=INK, spaceAfter=8,
))
styles.add(ParagraphStyle(
    name="BodySmall", fontName="Helvetica", fontSize=8.4, leading=12.1,
    textColor=MUTED, spaceAfter=5,
))
styles.add(ParagraphStyle(
    name="BulletX", fontName="Helvetica", fontSize=9.3, leading=13.4,
    textColor=INK, leftIndent=13, firstLineIndent=-7, bulletIndent=2, spaceAfter=5,
))
styles.add(ParagraphStyle(
    name="Callout", fontName="Helvetica", fontSize=10.2, leading=15,
    textColor=INK, leftIndent=10, rightIndent=8, borderColor=CYAN,
    borderWidth=0, borderPadding=8, backColor=colors.HexColor("#e8f6f8"),
    spaceBefore=5, spaceAfter=10,
))
styles.add(ParagraphStyle(
    name="Quote", fontName="Helvetica-Oblique", fontSize=10.2, leading=15.2,
    textColor=INK, leftIndent=14, rightIndent=10, borderColor=BLUE,
    borderWidth=0, borderPadding=10, backColor=colors.HexColor("#eef1fb"),
    spaceBefore=5, spaceAfter=12,
))
styles.add(ParagraphStyle(
    name="TableHead", fontName="Helvetica-Bold", fontSize=8, leading=10,
    textColor=WHITE,
))
styles.add(ParagraphStyle(
    name="TableCell", fontName="Helvetica", fontSize=7.8, leading=10.5,
    textColor=INK,
))
styles.add(ParagraphStyle(
    name="TableCellBold", fontName="Helvetica-Bold", fontSize=7.8, leading=10.5,
    textColor=INK,
))
styles.add(ParagraphStyle(
    name="CoverCell", fontName="Helvetica", fontSize=8.2, leading=11,
    textColor=colors.HexColor("#dce7ec"),
))


def P(text, style="BodyX"):
    return Paragraph(text, styles[style])


def bullet(text):
    return Paragraph(f"• {text}", styles["BulletX"])


def section_label(number, title):
    return [
        Paragraph(f"{number}  /  {title.upper()}", ParagraphStyle(
            name=f"Label{number}", parent=styles["H3x"], fontSize=8.2,
            leading=10, tracking=1.1, spaceAfter=7,
        )),
    ]


class ArchitectureFlow(Flowable):
    def __init__(self):
        super().__init__()
        self.width = 174 * mm
        self.height = 41 * mm

    def draw(self):
        c = self.canv
        labels = [
            ("SOURCES", "Flux choisis", CYAN),
            ("GOUVERNANCE", "Matrice de flux", GREEN),
            ("ANALYSE", "Qwen3 local", BLUE),
            ("METIER", "Collecteur", AMBER),
        ]
        gap = 5 * mm
        box_w = (self.width - 3 * gap) / 4
        box_h = 31 * mm
        y = 6 * mm
        for index, (kicker, title, accent) in enumerate(labels):
            x = index * (box_w + gap)
            c.setFillColor(colors.HexColor("#f5f8fa"))
            c.setStrokeColor(accent)
            c.setLineWidth(1.2)
            c.roundRect(x, y, box_w, box_h, 3 * mm, fill=1, stroke=1)
            c.setFillColor(accent)
            c.setFont("Helvetica-Bold", 6.2)
            c.drawString(x + 4 * mm, y + 21 * mm, kicker)
            c.setFillColor(INK)
            c.setFont("Helvetica-Bold", 9.2)
            title_width = stringWidth(title, "Helvetica-Bold", 9.2)
            if title_width > box_w - 8 * mm:
                c.setFont("Helvetica-Bold", 8.1)
            c.drawString(x + 4 * mm, y + 12 * mm, title)
            if index < 3:
                c.setStrokeColor(CYAN)
                c.setFillColor(CYAN)
                ax = x + box_w + 1.2 * mm
                ay = y + box_h / 2
                c.line(ax, ay, ax + 2.8 * mm, ay)
                c.line(ax + 2.8 * mm, ay, ax + 1.6 * mm, ay + 1.2 * mm)
                c.line(ax + 2.8 * mm, ay, ax + 1.6 * mm, ay - 1.2 * mm)


def info_cards(left_title, left_body, right_title, right_body):
    data = [[
        P(f"<font color='{GREEN.hexval()}'><b>{left_title}</b></font><br/>{left_body}", "BodyX"),
        P(f"<font color='{BLUE.hexval()}'><b>{right_title}</b></font><br/>{right_body}", "BodyX"),
    ]]
    table = Table(data, colWidths=[84.5 * mm, 84.5 * mm], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PANEL),
        ("BOX", (0, 0), (-1, -1), .6, LINE),
        ("INNERGRID", (0, 0), (-1, -1), .6, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 11),
        ("RIGHTPADDING", (0, 0), (-1, -1), 11),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return table


def page_chrome(c: canvas.Canvas, doc):
    page = c.getPageNumber()
    if page == 1:
        return
    c.saveState()
    c.setStrokeColor(LINE)
    c.setLineWidth(.5)
    c.line(20 * mm, PAGE_H - 15 * mm, PAGE_W - 20 * mm, PAGE_H - 15 * mm)
    c.setFont("Helvetica-Bold", 7.5)
    c.setFillColor(CYAN)
    c.drawString(20 * mm, PAGE_H - 11.5 * mm, "OPENVIGIE")
    c.setFont("Helvetica", 7.5)
    c.setFillColor(MUTED)
    c.drawRightString(PAGE_W - 20 * mm, PAGE_H - 11.5 * mm, "Dossier technique - Flux et IA locale")
    c.line(20 * mm, 14 * mm, PAGE_W - 20 * mm, 14 * mm)
    c.drawString(20 * mm, 9.5 * mm, "Document informationnel - Fonctionnement actuel et architecture cible")
    c.drawRightString(PAGE_W - 20 * mm, 9.5 * mm, str(page))
    c.restoreState()


def cover(c: canvas.Canvas, doc):
    c.saveState()
    c.setFillColor(NAVY)
    c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    c.setFillColor(colors.HexColor("#0c2937"))
    c.circle(PAGE_W - 18 * mm, PAGE_H - 30 * mm, 54 * mm, fill=1, stroke=0)
    c.setFillColor(colors.HexColor("#103a47"))
    c.circle(12 * mm, 10 * mm, 62 * mm, fill=1, stroke=0)
    c.restoreState()


doc = SimpleDocTemplate(
    str(OUTPUT), pagesize=A4,
    rightMargin=20 * mm, leftMargin=20 * mm,
    topMargin=23 * mm, bottomMargin=20 * mm,
    title="OpenVigie - Dossier technique des flux et de Qwen3",
    author="OpenVigie",
    subject="CyberFeed, veille cyber automatisée et intégration locale de Qwen3",
)

story = []

# Cover
story += [
    Spacer(1, 33 * mm),
    P("DOSSIER TECHNIQUE INFORMATIONNEL", "CoverKicker"),
    P("OpenVigie,<br/>des flux choisis à<br/>une veille assistée par IA", "CoverTitle"),
    P("Présentation de CyberFeed, de la matrice de flux et de l'intégration cible de Qwen3 dans le projet fil rouge OpenVigie.", "CoverLead"),
    Spacer(1, 12 * mm),
]
cover_meta = Table([
    [P("PÉRIMÈTRE", "TableHead"), P("STATUT", "TableHead")],
    [P("Veille cyber, collecte, parc et IA locale", "CoverCell"), P("Fonctions actuelles et architecture cible", "CoverCell")],
], colWidths=[84.5 * mm, 84.5 * mm])
cover_meta.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123342")),
    ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#0a202c")),
    ("BOX", (0, 0), (-1, -1), .6, colors.HexColor("#315466")),
    ("INNERGRID", (0, 0), (-1, -1), .6, colors.HexColor("#315466")),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ("TOPPADDING", (0, 0), (-1, -1), 8),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
]))
story += [cover_meta, Spacer(1, 44 * mm), P("Projet fil rouge - Support de présentation destiné à l'enseignant", "CoverKicker"), PageBreak()]

# Context
story += section_label("01", "Contexte du projet")
story += [
    P("De CyberFeed à OpenVigie", "H1x"),
    P("Ce dossier accompagne la présentation de deux étapes complémentaires d'un même travail de veille : une première matrice de flux déjà automatisée et un projet plus avancé, centré sur la pertinence des informations pour un parc informatique réel."),
    P("Message de présentation", "H2x"),
    P("J'avais déjà réalisé une matrice de flux automatisée intitulée <b>CyberFeed</b>, accessible 24 h/24 depuis mon portfolio GitHub Pages : <link href='https://swapshadow.github.io/portfolio/veille.html' color='#008ba0'>swapshadow.github.io/portfolio/veille.html</link>.<br/><br/>Dans le cadre du projet fil rouge, je travaille actuellement sur l'intégration locale de l'IA <b>Qwen3</b> à OpenVigie. L'objectif est d'obtenir une veille plus ciblée, notamment en fonction des équipements et logiciels renseignés dans le parc de l'utilisateur. Cette intégration nécessite toutefois un peu plus de temps que prévu.<br/><br/>Le présent document explique le fonctionnement envisagé de cette fonctionnalité.", "Quote"),
    P("Ce que ce message met en évidence", "H2x"),
    bullet("<b>CyberFeed constitue l'acquis initial :</b> une matrice automatisée, publiée en continu et consultable en ligne."),
    bullet("<b>OpenVigie constitue l'étape d'approfondissement :</b> la veille n'est plus seulement organisée par thèmes, elle doit aussi être rapprochée du parc de l'utilisateur."),
    bullet("<b>Qwen3 constitue une évolution locale :</b> l'IA doit améliorer le tri et l'explication sans envoyer les données du parc vers un service d'IA distant."),
    bullet("<b>Le délai supplémentaire est lié à l'intégration :</b> téléchargement du modèle, ressources matérielles, orchestration Docker, règles de priorité et validation des résultats."),
    Spacer(1, 4 * mm),
    info_cards(
        "RÉALISATION DISPONIBLE", "CyberFeed démontre une chaîne de veille automatisée accessible depuis le portfolio.",
        "PROJET EN COURS", "OpenVigie vise une veille contextualisée, locale et directement utile au parc déclaré.",
    ),
]

story += [PageBreak()]

# Vision and sources
story += section_label("02", "Vision et choix des flux")
story += [
    P("Une veille fondée sur des sources choisies", "H1x"),
    P("OpenVigie ne cherche pas à aspirer tout le Web. Les flux sont sélectionnés parce qu'ils répondent à un besoin de la matrice : vulnérabilités, menaces, détection, conformité, incidents, fuites de données ou contexte stratégique. Cette sélection réduit le bruit et conserve une provenance vérifiable."),
    P("Critères de sélection", "H2x"),
]

criteria = [
    [P("CRITÈRE", "TableHead"), P("OBJECTIF", "TableHead"), P("APPLICATION", "TableHead")],
    [P("Autorité", "TableCellBold"), P("Favoriser les sources compétentes.", "TableCell"), P("CERT, autorités, NVD, CISA, PSIRT et recherche reconnue.", "TableCell")],
    [P("Pertinence", "TableCellBold"), P("Répondre à un thème cyber utile.", "TableCell"), P("Vulnérabilité, menace, défense, conformité ou incident.", "TableCell")],
    [P("Attribution", "TableCellBold"), P("Permettre la vérification.", "TableCell"), P("Nom, date, court extrait et lien d'origine sont conservés.", "TableCell")],
    [P("Qualité technique", "TableCellBold"), P("Automatiser de façon stable.", "TableCell"), P("Flux lisible, correctement daté et normalisable.", "TableCell")],
    [P("Diversité", "TableCellBold"), P("Limiter les angles morts.", "TableCell"), P("Sources primaires et analyses spécialisées sont combinées.", "TableCell")],
    [P("Résilience", "TableCellBold"), P("Rester transparent en cas d'erreur.", "TableCell"), P("Une source indisponible est signalée comme dégradée.", "TableCell")],
]
criteria_table = Table(criteria, colWidths=[35 * mm, 56 * mm, 78 * mm], repeatRows=1)
criteria_table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), NAVY),
    ("BACKGROUND", (0, 1), (-1, -1), colors.white),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]),
    ("GRID", (0, 0), (-1, -1), .45, LINE),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("LEFTPADDING", (0, 0), (-1, -1), 7),
    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ("TOPPADDING", (0, 0), (-1, -1), 7),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
]))
story += [criteria_table, Spacer(1, 7 * mm), P("La matrice de flux", "H2x")]
story += [
    P("La matrice formalise la gouvernance de chaque source. Elle enregistre sa nature, son thème, son niveau de priorité, sa cadence de relève, ses conditions d'attribution et son état de collecte. Elle détermine donc ce qui entre dans le système et où l'information doit être dirigée."),
    P("Une alerte CERT, un avis d'éditeur et un article de presse ne sont pas traités comme des preuves équivalentes. Leur origine reste visible et leur poids initial est défini par des règles OpenVigie, avant toute intervention de l'IA.", "Callout"),
]

story += [PageBreak()]

# Architecture
story += section_label("03", "Architecture fonctionnelle")
story += [
    P("Le positionnement cible de Qwen3", "H1x"),
    P("Dans l'architecture cible, Qwen3 intervient logiquement entre la matrice de flux et les traitements métier du collecteur. Il n'est ni une source ni l'arbitre final. Il interprète les éléments déjà sélectionnés et attribués."),
    Spacer(1, 4 * mm),
    ArchitectureFlow(),
    P("Sorties : bulletin de veille, matrice de risques du parc, alertes prioritaires et futures fonctions spécialisées.", "BodySmall"),
    P("Responsabilités de chaque couche", "H2x"),
]

layers = [
    ("1. Matrice de flux", "Choisit et qualifie les flux : source, catégorie, priorité, cadence et attribution.", "Règles OpenVigie"),
    ("2. Qwen3", "Déduplique, classe, résume et extrait les entités utiles à la veille.", "IA locale"),
    ("3. Collecteur", "Normalise, stocke, rapproche le parc et applique les règles CVE et CISA KEV.", "Code déterministe"),
    ("4. Interfaces", "Présentent le bulletin, la matrice et les alertes avec les références d'origine.", "OpenVigie"),
]
layer_data = [[P("COUCHE", "TableHead"), P("RÔLE", "TableHead"), P("AUTORITÉ", "TableHead")]]
for title, role, authority in layers:
    layer_data.append([P(title, "TableCellBold"), P(role, "TableCell"), P(authority, "TableCell")])
layer_table = Table(layer_data, colWidths=[40 * mm, 94 * mm, 35 * mm], repeatRows=1)
layer_table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), NAVY),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]),
    ("GRID", (0, 0), (-1, -1), .45, LINE),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("LEFTPADDING", (0, 0), (-1, -1), 7),
    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ("TOPPADDING", (0, 0), (-1, -1), 7),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
]))
story += [layer_table, Spacer(1, 6 * mm), P("Fonctions confiées à l'IA", "H2x")]
story += [
    bullet("Regrouper plusieurs publications décrivant le même événement."),
    bullet("Classer les informations : menace, vulnérabilité, détection, conformité ou autre."),
    bullet("Produire une synthèse courte en français, liée aux sources d'origine."),
    bullet("Extraire les CVE, éditeurs, produits, versions, groupes APT et indicateurs de compromission mentionnés."),
    bullet("Estimer la pertinence d'un signal pour le parc déclaré et expliquer la priorité proposée."),
]

story += [PageBreak()]

# Rules and local deployment
story += section_label("04", "Règles, limites et exécution locale")
story += [
    P("L'IA assiste, les faits décident", "H1x"),
    P("La priorité finale ne doit pas dépendre uniquement du modèle. Les éléments vérifiables restent dominants : identifiant CVE, plage de versions affectées, correspondance avec le parc, score technique, avis de l'éditeur et présence dans le catalogue CISA Known Exploited Vulnerabilities."),
    P("Principe de priorité", "H2x"),
    P("Une correspondance de version, une CVE officielle ou un signal CISA KEV prime toujours sur l'appréciation de Qwen3. Le modèle peut augmenter la lisibilité et attirer l'attention sur un contexte, mais il ne peut pas diminuer une priorité imposée par une règle factuelle.", "Callout"),
    P("Garde-fous", "H2x"),
    bullet("Qwen3 ne doit pas inventer une vulnérabilité, une date, une source ou une URL."),
    bullet("Chaque résumé reste rattaché aux articles et références ayant servi d'éléments de preuve."),
    bullet("Les informations incertaines ou contradictoires doivent être signalées comme telles."),
    bullet("Aucune remédiation de production ne doit être lancée automatiquement sur la seule recommandation du modèle."),
    bullet("Les plages de versions affectées et corrigées doivent être confirmées dans l'avis primaire de l'éditeur."),
    P("Pourquoi une IA locale ?", "H2x"),
    P("L'exécution locale permet à OpenVigie de garder le traitement dans l'environnement de l'utilisateur. Le parc, les requêtes et les contenus de veille n'ont pas besoin d'être envoyés à une API d'IA distante. Le modèle peut être distribué avec l'application au moyen de Docker et d'Ollama."),
    info_cards(
        "AVANTAGE", "Confidentialité accrue, indépendance d'un service cloud et fonctionnement cohérent sur Windows, Linux et macOS via Docker.",
        "CONTRAINTE", "Le modèle demande de la mémoire, du stockage et un temps d'inférence adaptés à la machine de l'utilisateur.",
    ),
]

story += [PageBreak()]

# Bulletin
story += section_label("05", "Bulletin de veille")
story += [
    P("Le service disponible aujourd'hui", "H1x"),
    P("Pour le moment, le bulletin OpenVigie fait office de vue automatique des dernières nouvelles cyber. Il récupère les flux sélectionnés, conserve les titres, courts extraits, dates et liens d'origine, puis classe les éléments selon la fraîcheur, l'autorité de la source, les signaux CVE et la diversité des provenances."),
    P("Le collecteur fonctionne dans les conteneurs OpenVigie. Il peut continuer à relever les flux et à alimenter la base lorsque l'interface Web est fermée, tant que Docker et les conteneurs restent actifs.", "Callout"),
    P("Évolution prévue avec Qwen3", "H2x"),
]

bulletin_steps = [
    [P("ÉTAPE", "TableHead"), P("FONCTION", "TableHead"), P("STATUT", "TableHead")],
    [P("Collecte", "TableCellBold"), P("Lecture RSS/Atom, normalisation, attribution et détection de CVE.", "TableCell"), P("Disponible", "TableCell")],
    [P("Bulletin", "TableCellBold"), P("Présentation automatique des actualités cyber les plus récentes.", "TableCell"), P("Disponible", "TableCell")],
    [P("Tri sémantique", "TableCellBold"), P("Déduplication, classification et extraction d'entités par Qwen3.", "TableCell"), P("Cible", "TableCell")],
    [P("Synthèse IA", "TableCellBold"), P("Résumé français et explication de la pertinence pour le parc.", "TableCell"), P("Cible", "TableCell")],
    [P("Mise à jour assistée", "TableCellBold"), P("Regroupement d'événements et propositions de priorité éditoriale.", "TableCell"), P("Évolution", "TableCell")],
]
bulletin_table = Table(bulletin_steps, colWidths=[38 * mm, 96 * mm, 35 * mm], repeatRows=1)
bulletin_table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), NAVY),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]),
    ("GRID", (0, 0), (-1, -1), .45, LINE),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("TEXTCOLOR", (2, 1), (2, 2), GREEN),
    ("TEXTCOLOR", (2, 3), (2, -1), BLUE),
    ("LEFTPADDING", (0, 0), (-1, -1), 7),
    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ("TOPPADDING", (0, 0), (-1, -1), 7),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
]))
story += [bulletin_table, Spacer(1, 7 * mm)]
story += [
    P("Le bulletin est un point d'entrée de veille, pas une preuve autonome. Toute décision technique importante doit revenir aux sources primaires, aux avis des éditeurs et à la validation humaine."),
    P("Autres implantations possibles de Qwen3", "H2x"),
    bullet("<b>Matrice du parc :</b> expliquer pourquoi un signal concerne un équipement."),
    bullet("<b>Alertes :</b> synthétiser la cause, le niveau d'urgence et les actions à examiner."),
    bullet("<b>Recherche :</b> accepter des questions en langage naturel et regrouper les résultats."),
    bullet("<b>Dossiers :</b> préparer chronologies, acteurs cités et points de contradiction."),
    bullet("<b>Assistance éditoriale :</b> proposer catégories et mots-clés avec un niveau de confiance."),
]

story += [PageBreak()]

# Summary
story += section_label("06", "Synthèse et trajectoire")
story += [
    P("Une progression cohérente du projet", "H1x"),
    P("CyberFeed a permis d'établir et de publier une première matrice de veille automatisée. OpenVigie réutilise cette logique en l'étendant à la collecte normalisée, aux vulnérabilités et à la connaissance du parc. Qwen3 doit ensuite ajouter une couche d'analyse locale, explicable et réutilisable."),
    P("Chaîne cible", "H2x"),
    ArchitectureFlow(),
    Spacer(1, 5 * mm),
    P("Le principe directeur peut être résumé ainsi : <b>la matrice choisit, Qwen3 interprète, les règles factuelles arbitrent et OpenVigie informe.</b>", "Callout"),
    P("Trajectoire de mise en oeuvre", "H2x"),
]

roadmap = [
    [P("PHASE", "TableHead"), P("RÉSULTAT ATTENDU", "TableHead")],
    [P("1. Sources", "TableCellBold"), P("Maintenir une liste de flux pertinents, attribués et techniquement suivis.", "TableCell")],
    [P("2. Collecte", "TableCellBold"), P("Normaliser, conserver et distribuer les éléments de veille avec leurs preuves.", "TableCell")],
    [P("3. IA locale", "TableCellBold"), P("Valider Qwen3 dans Docker, sa consommation de ressources et la structure de ses réponses.", "TableCell")],
    [P("4. Corrélation", "TableCellBold"), P("Rapprocher les résultats IA du parc sans affaiblir les règles CVE et CISA KEV.", "TableCell")],
    [P("5. Interfaces", "TableCellBold"), P("Mettre à jour le bulletin puis étendre l'IA à la matrice, aux alertes et à la recherche.", "TableCell")],
]
roadmap_table = Table(roadmap, colWidths=[43 * mm, 126 * mm], repeatRows=1)
roadmap_table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), NAVY),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]),
    ("GRID", (0, 0), (-1, -1), .45, LINE),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("LEFTPADDING", (0, 0), (-1, -1), 7),
    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ("TOPPADDING", (0, 0), (-1, -1), 7),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
]))
story += [roadmap_table, Spacer(1, 10 * mm)]
story += [
    P("Référence", "H2x"),
    P("CyberFeed : <link href='https://swapshadow.github.io/portfolio/veille.html' color='#008ba0'>https://swapshadow.github.io/portfolio/veille.html</link>"),
    P("Document source : dossier HTML OpenVigie sur les flux et l'IA locale.", "BodySmall"),
]

doc.build(story, onFirstPage=cover, onLaterPages=page_chrome)
print(OUTPUT)
