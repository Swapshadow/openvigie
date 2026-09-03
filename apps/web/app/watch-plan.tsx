'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import WatchAlerts from './watch-alerts';

const STORAGE_KEY = 'openvigie.watch-plan.v2';
const LEGACY_STORAGE_KEY = 'openvigie.watch-plan.v1';
const MAX_IMMEDIATE_ALERTS = 3;

const AXES = ['Menaces', 'Vulnérabilités et correctifs', 'Détection / techniques MITRE ATT&CK', 'Conformité et réglementation'] as const;
type Axis = typeof AXES[number];
type Frequency = 'Immédiat' | 'Quotidien' | 'Hebdomadaire' | 'Mensuel';
type WatchLine = { id: string; axis: Axis; question: string; keywords: string; sourceIds: string[]; frequency: Frequency; criticality: 1 | 2 | 3 };
type Source = {
  id: string; collectorId?: string; name: string; family: string; url: string; feed: string;
  reliability: 1 | 2 | 3; freshness: 1 | 2 | 3; noise: 1 | 2 | 3; usability: 1 | 2 | 3;
};
type SourceCheck = { id: string; status: 'online' | 'degraded' | 'pending'; httpStatus: number | null; checkedAt: string | null; lastSuccess: string | null; nextRefresh: string | null; error: string | null; watchFrequency: string | null; watchRefreshSeconds: number | null };
type SourceStatusResponse = { checkedAt: string; sources: SourceCheck[]; collectorAvailable: boolean };
type View = 'matrix' | 'alerts' | 'sources' | 'documentation';
type ScheduleStatus = 'pending' | 'synced' | 'error';

const SOURCES: Source[] = [
  { id: 'cert-fr-alertes', collectorId: 'cert-fr-alertes', name: 'CERT-FR · Alertes', family: 'Officielle', url: 'https://cert.ssi.gouv.fr/alerte/', feed: 'https://cert.ssi.gouv.fr/alerte/feed/', reliability: 3, freshness: 3, noise: 3, usability: 3 },
  { id: 'anssi-actualites', collectorId: 'anssi-actualites', name: 'ANSSI · Actualités', family: 'Officielle', url: 'https://cyber.gouv.fr/actualites/', feed: 'https://cyber.gouv.fr/actualites/rss/', reliability: 3, freshness: 2, noise: 2, usability: 3 },
  { id: 'cisa-advisories', collectorId: 'cisa-advisories', name: 'CISA · Advisories', family: 'Officielle', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories', feed: 'https://www.cisa.gov/cybersecurity-advisories/all.xml', reliability: 3, freshness: 3, noise: 3, usability: 3 },
  { id: 'enisa', name: 'ENISA · Actualités', family: 'Officielle', url: 'https://www.enisa.europa.eu/news', feed: '', reliability: 3, freshness: 2, noise: 2, usability: 1 },
  { id: 'nvd', name: 'NVD / NIST', family: 'Base de vulnérabilités', url: 'https://nvd.nist.gov/', feed: 'https://services.nvd.nist.gov/rest/json/cves/2.0', reliability: 3, freshness: 3, noise: 3, usability: 3 },
  { id: 'cisa-kev', name: 'CISA KEV', family: 'Base de vulnérabilités', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', feed: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', reliability: 3, freshness: 3, noise: 3, usability: 3 },
  { id: 'cve-program', name: 'CVE Program', family: 'Base de vulnérabilités', url: 'https://www.cve.org/', feed: 'https://cveawg.mitre.org/api/cve/CVE-2024-3094', reliability: 3, freshness: 3, noise: 3, usability: 3 },
  { id: 'epss', name: 'FIRST EPSS', family: 'Base de vulnérabilités', url: 'https://www.first.org/epss/', feed: 'https://api.first.org/data/v1/epss?cve=CVE-2024-3094', reliability: 3, freshness: 3, noise: 3, usability: 3 },
  { id: 'cisco-psirt', collectorId: 'cisco-psirt', name: 'Cisco PSIRT', family: 'Éditeur', url: 'https://sec.cloudapps.cisco.com/security/center/publicationListing.x', feed: 'https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml', reliability: 3, freshness: 3, noise: 3, usability: 3 },
  { id: 'msrc', collectorId: 'msrc', name: 'Microsoft MSRC', family: 'Éditeur', url: 'https://msrc.microsoft.com/update-guide/', feed: 'https://api.msrc.microsoft.com/update-guide/rss', reliability: 3, freshness: 3, noise: 3, usability: 3 },
  { id: 'fortinet-psirt', name: 'Fortinet PSIRT', family: 'Éditeur', url: 'https://www.fortiguard.com/psirt', feed: '', reliability: 3, freshness: 3, noise: 3, usability: 1 },
  { id: 'palo-alto-psirt', collectorId: 'palo-alto-psirt', name: 'Palo Alto PSIRT', family: 'Éditeur', url: 'https://security.paloaltonetworks.com/', feed: 'https://security.paloaltonetworks.com/rss.xml', reliability: 3, freshness: 3, noise: 3, usability: 3 },
  { id: 'citizen-lab', collectorId: 'citizen-lab', name: 'Citizen Lab', family: 'Labs et chercheurs', url: 'https://citizenlab.ca/', feed: 'https://citizenlab.ca/feed/', reliability: 3, freshness: 2, noise: 2, usability: 3 },
  { id: 'amnesty-security-lab', collectorId: 'amnesty-security-lab', name: 'Amnesty Security Lab', family: 'Labs et chercheurs', url: 'https://securitylab.amnesty.org/', feed: 'https://securitylab.amnesty.org/latest/feed/', reliability: 3, freshness: 2, noise: 2, usability: 3 },
  { id: 'unit-42', collectorId: 'unit-42', name: 'Unit 42', family: 'Labs et chercheurs', url: 'https://unit42.paloaltonetworks.com/', feed: 'https://unit42.paloaltonetworks.com/feed/', reliability: 2, freshness: 3, noise: 2, usability: 3 },
];

const DEFAULT_LINES: WatchLine[] = [
  { id: 'w1', axis: 'Menaces', question: 'Quels groupes ont revendiqué des victimes françaises ou européennes cette semaine ?', keywords: 'APT; threat actor; intrusion set; ransomware; France; Europe; alias; revendication', sourceIds: ['cert-fr-alertes', 'cisa-advisories', 'unit-42'], frequency: 'Hebdomadaire', criticality: 2 },
  { id: 'w2', axis: 'Menaces', question: 'Une campagne d’espionnage ou de rançongiciel cible-t-elle actuellement notre secteur ?', keywords: 'espionage; ransomware; campaign; state-backed; secteur; infrastructure critique', sourceIds: ['cisa-advisories', 'citizen-lab', 'amnesty-security-lab'], frequency: 'Quotidien', criticality: 2 },
  { id: 'w3', axis: 'Vulnérabilités et correctifs', question: 'Une CVE entrée dans CISA KEV affecte-t-elle une version présente dans notre parc ?', keywords: 'CVE; CISA KEV; known exploited; active exploitation; version; vendor; product', sourceIds: ['cisa-kev', 'nvd', 'cert-fr-alertes'], frequency: 'Immédiat', criticality: 3 },
  { id: 'w4', axis: 'Vulnérabilités et correctifs', question: 'Un éditeur du parc a-t-il publié une version corrigée ou un contournement ?', keywords: 'security advisory; fixed version; patch; mitigation; workaround; PSIRT', sourceIds: ['cisco-psirt', 'msrc', 'fortinet-psirt', 'palo-alto-psirt'], frequency: 'Quotidien', criticality: 3 },
  { id: 'w5', axis: 'Vulnérabilités et correctifs', question: 'Une dépendance, un VPN ou une passerelle exposée présente-t-il un risque critique ?', keywords: 'supply chain; dependency; VPN; SSL-VPN; gateway; firewall; package; backdoor', sourceIds: ['cert-fr-alertes', 'nvd', 'epss'], frequency: 'Quotidien', criticality: 2 },
  { id: 'w6', axis: 'Détection / techniques MITRE ATT&CK', question: 'Quelles techniques ATT&CK sont associées aux campagnes actives suivies ?', keywords: 'MITRE ATT&CK; technique; sub-technique; TTP; initial access; persistence', sourceIds: ['cisa-advisories', 'unit-42'], frequency: 'Hebdomadaire', criticality: 2 },
  { id: 'w7', axis: 'Détection / techniques MITRE ATT&CK', question: 'De nouveaux IOC permettent-ils de détecter une exploitation visant le parc ?', keywords: 'IOC; indicator; IP; domain; hash; detection rule; Sigma; YARA; exploitation', sourceIds: ['cisa-advisories', 'cert-fr-alertes', 'unit-42'], frequency: 'Immédiat', criticality: 3 },
  { id: 'w8', axis: 'Conformité et réglementation', question: 'Une nouvelle obligation NIS2, DORA, CRA ou CNIL modifie-t-elle nos exigences ?', keywords: 'NIS2; DORA; CRA; RGPD; CNIL; notification; conformité; règlement', sourceIds: ['anssi-actualites', 'enisa'], frequency: 'Mensuel', criticality: 1 },
  { id: 'w9', axis: 'Conformité et réglementation', question: 'Une évolution réglementaire affecte-t-elle le chiffrement ou la protection des données ?', keywords: 'chiffrement; encryption; lawful access; ePrivacy; DSA; DMA; données personnelles', sourceIds: ['anssi-actualites', 'enisa', 'amnesty-security-lab'], frequency: 'Mensuel', criticality: 1 },
];

const uid = () => `watch-${Date.now()}-${Math.random().toString(16).slice(2)}`;
const score = (source: Source) => source.reliability + source.freshness + source.noise + source.usability;
const qualification = (source: Source) => score(source) < 4 ? 'Écartée' : score(source) < 6 ? 'Observation' : 'Qualifiée';
const formatDate = (value: string | null) => value ? new Intl.DateTimeFormat('fr-FR', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value)) : 'Jamais contrôlé';

function normalizeAxis(value: string): Axis {
  const normalized = value.toLowerCase();
  if (normalized.includes('vuln') || normalized.includes('supply') || normalized.includes('vpn')) return AXES[1];
  if (normalized.includes('détection') || normalized.includes('detection') || normalized.includes('att&ck')) return AXES[2];
  if (normalized.includes('conform') || normalized.includes('réglement') || normalized.includes('reglement')) return AXES[3];
  return AXES[0];
}

function normalizeFrequency(value: string): Frequency {
  if (/temps réel|immediat|immédiat/i.test(value)) return 'Immédiat';
  if (/quotid/i.test(value)) return 'Quotidien';
  if (/mensu/i.test(value)) return 'Mensuel';
  return 'Hebdomadaire';
}

function migrateLines(value: unknown): WatchLine[] {
  if (!Array.isArray(value)) return DEFAULT_LINES;
  const migrated = value.filter((line) => line && typeof line === 'object').map((line, index) => {
    const item = line as Record<string, unknown>;
    return {
      id: typeof item.id === 'string' ? item.id : `legacy-${index}`,
      axis: normalizeAxis(String(item.axis ?? 'Menaces')),
      question: String(item.question ?? ''),
      keywords: String(item.keywords ?? ''),
      sourceIds: Array.isArray(item.sourceIds) ? item.sourceIds.filter((id): id is string => typeof id === 'string' && SOURCES.some((source) => source.id === id)) : [],
      frequency: normalizeFrequency(String(item.frequency ?? 'Hebdomadaire')),
      criticality: ([1, 2, 3].includes(Number(item.criticality)) ? Number(item.criticality) : 1) as 1 | 2 | 3,
    };
  });
  const missingAxes = AXES.filter((axis) => !migrated.some((line) => line.axis === axis));
  let immediateCount = 0;
  return [...migrated, ...DEFAULT_LINES.filter((line) => missingAxes.includes(line.axis))].map((line) => {
    if (line.criticality !== 3) return line;
    immediateCount += 1;
    return immediateCount <= MAX_IMMEDIATE_ALERTS ? line : { ...line, criticality: 2 };
  });
}

function download(name: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = name;
  link.click();
  URL.revokeObjectURL(link.href);
}

export default function WatchPlan() {
  const [lines, setLines] = useState<WatchLine[]>(DEFAULT_LINES);
  const [view, setView] = useState<View>('matrix');
  const [selectedId, setSelectedId] = useState(DEFAULT_LINES[0].id);
  const [checks, setChecks] = useState<Record<string, SourceCheck>>({});
  const [checksLoading, setChecksLoading] = useState(true);
  const [notice, setNotice] = useState('');
  const [scheduleStatus, setScheduleStatus] = useState<ScheduleStatus>('pending');

  useEffect(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? localStorage.getItem(LEGACY_STORAGE_KEY) ?? 'null');
      const migrated = migrateLines(saved);
      queueMicrotask(() => { setLines(migrated); setSelectedId(migrated[0]?.id ?? ''); });
    } catch { /* conserver la matrice démonstrative */ }
  }, []);
  useEffect(() => { localStorage.setItem(STORAGE_KEY, JSON.stringify(lines)); }, [lines]);

  const refreshChecks = useCallback(async () => {
    setChecksLoading(true);
    try {
      const response = await fetch('/api/watch-sources', { cache: 'no-store' });
      const payload = await response.json() as SourceStatusResponse & { error?: string };
      if (!response.ok) throw new Error(payload.error ?? 'Contrôle indisponible');
      setChecks(Object.fromEntries(payload.sources.map((item) => [item.id, item])));
      setNotice(`Contrôle terminé : ${payload.sources.filter((item) => item.status === 'online').length}/${SOURCES.length} sources joignables.`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : 'Le contrôle réseau est indisponible.');
    } finally { setChecksLoading(false); }
  }, []);

  useEffect(() => {
    const initialCheck = window.setTimeout(() => void refreshChecks(), 0);
    return () => window.clearTimeout(initialCheck);
  }, [refreshChecks]);

  useEffect(() => {
    const timer = window.setTimeout(async () => {
      const order: Record<Frequency, number> = { 'Immédiat': 0, 'Quotidien': 1, 'Hebdomadaire': 2, 'Mensuel': 3 };
      const schedules = new Map<string, Frequency>();
      for (const line of lines) {
        for (const sourceId of line.sourceIds) {
          const collectorId = SOURCES.find((source) => source.id === sourceId)?.collectorId;
          if (!collectorId) continue;
          const current = schedules.get(collectorId);
          if (!current || order[line.frequency] < order[current]) schedules.set(collectorId, line.frequency);
        }
      }
      try {
        const response = await fetch('/api/watch-sources', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sources: [...schedules].map(([sourceId, frequency]) => ({ sourceId, frequency })) }),
        });
        setScheduleStatus(response.ok ? 'synced' : 'error');
      } catch { setScheduleStatus('error'); }
    }, 450);
    return () => window.clearTimeout(timer);
  }, [lines]);

  const immediate = lines.filter((line) => line.criticality === 3).length;
  const coveredAxes = new Set(lines.map((line) => line.axis)).size;
  const qualifiedSources = SOURCES.filter((source) => qualification(source) === 'Qualifiée').length;
  const operationalSources = SOURCES.filter((source) => checks[source.id]?.status === 'online').length;
  const representedSources = useMemo(() => new Set(lines.flatMap((line) => line.sourceIds)).size, [lines]);
  const families = new Set(SOURCES.map((source) => source.family)).size;
  const selected = lines.find((line) => line.id === selectedId) ?? null;

  const update = (id: string, patch: Partial<WatchLine>) => setLines((current) => current.map((line) => line.id === id ? { ...line, ...patch } : line));
  const setCriticality = (line: WatchLine, value: 1 | 2 | 3) => {
    if (value === 3 && line.criticality !== 3 && immediate >= MAX_IMMEDIATE_ALERTS) {
      setNotice('Limite atteinte : rétrogradez une autre ligne avant de créer une quatrième alerte immédiate.');
      return;
    }
    update(line.id, { criticality: value });
  };
  const toggleSource = (line: WatchLine, sourceId: string) => update(line.id, { sourceIds: line.sourceIds.includes(sourceId) ? line.sourceIds.filter((id) => id !== sourceId) : [...line.sourceIds, sourceId] });
  const addLine = () => {
    const line: WatchLine = { id: uid(), axis: 'Menaces', question: 'Nouvelle question précise et vérifiable', keywords: '', sourceIds: [], frequency: 'Hebdomadaire', criticality: 1 };
    setLines((current) => [...current, line]);
    setSelectedId(line.id);
    setView('matrix');
  };

  const exportCsv = () => {
    const quote = (value: string | number) => `"${String(value).replaceAll('"', '""')}"`;
    const rows = [['Axe', 'Question', 'Mots-clés et alias', 'Sources (URL et flux/API)', 'Fréquence', 'Criticité'], ...lines.map((line) => [line.axis, line.question, line.keywords, line.sourceIds.map((id) => { const source = SOURCES.find((item) => item.id === id); return source ? `${source.name} | ${source.url} | ${source.feed || 'Sans flux public'}` : id; }).join(' ; '), line.frequency, line.criticality])];
    download('openvigie-matrice-de-veille.csv', `\uFEFF${rows.map((row) => row.map(quote).join(';')).join('\n')}`, 'text/csv;charset=utf-8');
  };

  const documentation = useMemo(() => {
    const sourceRows = SOURCES.map((source) => `| ${source.name} | ${source.family} | ${source.url} | ${source.feed || 'Consultation manuelle'} | ${score(source)}/12 | ${qualification(source)} |`).join('\n');
    return `# OpenVigie — documentation du dispositif de veille\n\n## Schéma de collecte\n\nSources officielles / bases / éditeurs / chercheurs → contrôle réseau → collecteur Docker → SQLite → filtrage CVE/produit/version → matrice du parc et bulletin → notification locale.\n\n## Sources qualifiées\n\n| Source | Famille | URL | Flux ou API | Score | Statut |\n|---|---|---|---|---:|---|\n${sourceRows}\n\n## Scoring\n\nChaque source est notée de 1 à 3 sur la fiabilité, la fraîcheur, le niveau de bruit utile et l’exploitabilité technique. Total sur 12 : moins de 4 = Écartée ; moins de 6 = Observation ; 6 ou plus = Qualifiée.\n\n## Filtrage et alerte\n\nUne CVE est prioritaire si elle correspond au produit et à la version du parc et si elle est critique, exploitée activement ou inscrite au catalogue CISA KEV. Une correspondance parc + CISA KEV déclenche une alerte visible dans la matrice de risques et dans le bulletin. Trois lignes au maximum peuvent être classées en alerte immédiate.\n\n## Reprise et preuve\n\nLe collecteur conserve les articles et requêtes CVE dans SQLite. L’interface affiche la date, le code HTTP et l’erreur du dernier contrôle réel. Les échecs restent visibles et ne sont jamais présentés comme des succès. Les données de cadrage restent dans le stockage local du navigateur.\n`;
  }, []);

  return <div className="watch-plan">
    <header className="watch-plan-hero glass-panel"><div><p className="eyebrow neon">Matrice de veille qualifiée</p><h1>Plan de veille</h1><p>Quatre axes, des questions vérifiables, quinze sources documentées et une chaîne de collecte démontrable.</p></div><div className="watch-plan-actions"><button type="button" onClick={addLine}>+ Ajouter une ligne</button><button type="button" onClick={exportCsv}>Exporter CSV</button><button type="button" onClick={() => download('openvigie-dispositif-de-veille.md', documentation, 'text/markdown;charset=utf-8')}>Exporter la documentation</button></div></header>

    <section className="watch-plan-stats" aria-label="Contrôles du livrable"><article data-valid={coveredAxes === 4}><span>Axes couverts</span><strong>{coveredAxes}/4</strong><p>Menaces · vulnérabilités · détection · conformité</p></article><article data-valid={qualifiedSources >= 10 && qualifiedSources <= 15}><span>Sources qualifiées</span><strong>{qualifiedSources}/15</strong><p>{representedSources} utilisées · {families} familles</p></article><article data-valid={operationalSources > 0 && scheduleStatus === 'synced'}><span>Sources joignables</span><strong>{checksLoading ? '···' : `${operationalSources}/15`}</strong><p>{scheduleStatus === 'synced' ? 'Planning transmis au collecteur' : scheduleStatus === 'error' ? 'Planning non synchronisé' : 'Synchronisation du planning…'}</p></article><article data-alert={immediate >= 3}><span>Alertes immédiates</span><strong>{immediate}/3</strong><p>La quatrième alerte est bloquée</p></article></section>

    {notice ? <div className="watch-notice" role="status"><span>◎</span><p>{notice}</p><button type="button" onClick={() => setNotice('')}>Fermer</button></div> : null}

    <section className="watch-plan-panel glass-panel"><header><div><span>LIVRABLE OPÉRATIONNEL</span><h2>{view === 'matrix' ? 'Matrice à six colonnes' : view === 'alerts' ? 'Alertes par sévérité' : view === 'sources' ? 'Sources et qualification' : 'Documentation du dispositif'}</h2></div><nav aria-label="Sections du plan de veille"><button type="button" aria-pressed={view === 'matrix'} onClick={() => setView('matrix')}>Matrice</button><button type="button" aria-pressed={view === 'alerts'} onClick={() => setView('alerts')}>Alertes</button><button type="button" aria-pressed={view === 'sources'} onClick={() => setView('sources')}>Sources et qualification</button><button type="button" aria-pressed={view === 'documentation'} onClick={() => setView('documentation')}>Documentation</button></nav></header>

      {view === 'matrix' ? <>
        <div className="watch-matrix-wrap"><table className="watch-matrix"><thead><tr><th>Axe</th><th>Question précise et vérifiable</th><th>Mots-clés, variantes et alias</th><th>Sources · URL · flux/API</th><th>Fréquence</th><th>Criticité</th></tr></thead><tbody>{lines.map((line) => <tr key={line.id} data-selected={selectedId === line.id} onClick={() => setSelectedId(line.id)}><td><b>{line.axis}</b></td><td><button type="button" onClick={() => setSelectedId(line.id)}>{line.question}</button></td><td><span>{line.keywords || 'À documenter'}</span></td><td><div>{line.sourceIds.map((id) => { const source = SOURCES.find((item) => item.id === id); return source ? <span className="matrix-source" key={id}><a href={source.url} target="_blank" rel="noreferrer">{source.name}</a>{source.feed ? <a href={source.feed} target="_blank" rel="noreferrer" aria-label={`Flux de ${source.name}`}>RSS/API</a> : <em>manuel</em>}</span> : null; })}</div></td><td><span className="frequency-chip">{line.frequency}</span></td><td><strong className="criticality-chip" data-level={line.criticality}>{line.criticality}</strong><small>{line.criticality === 3 ? 'Alerte immédiate' : line.criticality === 2 ? 'Prioritaire' : 'Information'}</small></td></tr>)}</tbody></table></div>
        {selected ? <section className="watch-line-editor" aria-labelledby="watch-editor-title"><header><span>MODIFIER LA LIGNE</span><h3 id="watch-editor-title">{selected.question}</h3></header><div><label><span>Axe</span><select value={selected.axis} onChange={(event) => update(selected.id, { axis: event.target.value as Axis })}>{AXES.map((axis) => <option key={axis}>{axis}</option>)}</select></label><label className="wide"><span>Question précise et vérifiable</span><textarea value={selected.question} onChange={(event) => update(selected.id, { question: event.target.value })} /></label><label className="wide"><span>Mots-clés, variantes et alias</span><textarea value={selected.keywords} onChange={(event) => update(selected.id, { keywords: event.target.value })} /></label><label><span>Fréquence</span><select value={selected.frequency} onChange={(event) => update(selected.id, { frequency: event.target.value as Frequency })}><option>Immédiat</option><option>Quotidien</option><option>Hebdomadaire</option><option>Mensuel</option></select></label><label><span>Criticité</span><select value={selected.criticality} onChange={(event) => setCriticality(selected, Number(event.target.value) as 1 | 2 | 3)}><option value="1">1 · Information</option><option value="2">2 · Prioritaire</option><option value="3" disabled={selected.criticality !== 3 && immediate >= MAX_IMMEDIATE_ALERTS}>3 · Alerte immédiate</option></select></label><fieldset className="wide"><legend>Sources associées</legend><div>{SOURCES.map((source) => <label key={source.id}><input type="checkbox" checked={selected.sourceIds.includes(source.id)} onChange={() => toggleSource(selected, source.id)} /><span>{source.name}</span></label>)}</div></fieldset><button className="watch-delete" type="button" onClick={() => { setLines((current) => current.filter((item) => item.id !== selected.id)); setSelectedId(lines.find((item) => item.id !== selected.id)?.id ?? ''); }}>Supprimer cette ligne</button></div></section> : null}
      </> : null}

      {view === 'alerts' ? <WatchAlerts /> : null}
      {view === 'sources' ? <div className="source-score-table"><div className="source-check-toolbar"><p><strong>Contrôles vérifiables</strong><span>Une source n’est « joignable » qu’après une réponse réseau réelle. Les codes HTTP et erreurs restent visibles.</span></p><button type="button" onClick={() => void refreshChecks()} disabled={checksLoading}>{checksLoading ? 'Contrôle en cours…' : 'Tester les 15 sources'}</button></div><table><thead><tr><th>Source et famille</th><th>Fiabilité</th><th>Fraîcheur</th><th>Bruit</th><th>Exploitabilité</th><th>Total / statut</th><th>Dernier contrôle réel</th></tr></thead><tbody>{SOURCES.map((source) => { const total = score(source); const check = checks[source.id]; return <tr key={source.id}><td><strong>{source.name}</strong><span>{source.family}</span><a href={source.url} target="_blank" rel="noreferrer">Site ↗</a>{source.feed ? <a href={source.feed} target="_blank" rel="noreferrer">Flux/API ↗</a> : <em>Consultation manuelle</em>}</td><td>{source.reliability}/3</td><td>{source.freshness}/3</td><td>{source.noise}/3</td><td>{source.usability}/3</td><td><b data-pass={total >= 6}>{total}/12</b><span className="qualification" data-state={qualification(source)}>{qualification(source)}</span></td><td><span className="source-check-state" data-state={check?.status ?? 'pending'}>{check?.status === 'online' ? 'Joignable' : check?.status === 'degraded' ? 'Échec' : 'Non testé'}</span><strong>{check?.httpStatus ? `HTTP ${check.httpStatus}` : 'HTTP —'}</strong><small>{formatDate(check?.checkedAt ?? null)}</small>{check?.watchFrequency ? <small>Collecte : {check.watchFrequency}</small> : null}{check?.error ? <em title={check.error}>{check.error}</em> : null}</td></tr>; })}</tbody></table><footer><strong>Règle de qualification</strong><span>Chaque critère est noté de 1 à 3. Total sur 12 : moins de 4 = Écartée ; moins de 6 = Observation ; à partir de 6 = Qualifiée. Le critère « bruit » mesure la part de contenu utile dans le périmètre : une note élevée signifie peu de bruit.</span></footer></div> : null}

      {view === 'documentation' ? <section className="watch-documentation"><div className="collection-flow" aria-label="Schéma de collecte"><article><span>01</span><strong>15 sources</strong><small>Officielles, bases, éditeurs, chercheurs</small></article><i>→</i><article><span>02</span><strong>Contrôle réseau</strong><small>Code HTTP, date et erreur conservés</small></article><i>→</i><article><span>03</span><strong>Collecteur Docker</strong><small>RSS/API vers SQLite selon le rythme</small></article><i>→</i><article><span>04</span><strong>Filtrage</strong><small>Produit + version + criticité ou KEV</small></article><i>→</i><article><span>05</span><strong>Décision</strong><small>Bulletin, parc, preuve et remédiation</small></article></div><div className="documentation-grid"><article><span>RÈGLE OBJECTIVE</span><h3>Priorité CVE</h3><p>Une CVE remonte si elle correspond à un produit et une version du parc. Elle devient prioritaire lorsqu’elle est critique, exploitée activement ou inscrite au catalogue CISA KEV.</p></article><article><span>ALERTE DÉMONTRABLE</span><h3>Parc + CISA KEV</h3><p>Une correspondance avec CISA KEV est visible dans « Risques du parc » et dans le Bulletin. La notification de test ci-dessous reste locale et ne contacte personne.</p><button type="button" onClick={() => setNotice(`Notification de test · ${new Intl.DateTimeFormat('fr-FR', { dateStyle: 'short', timeStyle: 'short' }).format(new Date())} · Simulation CISA KEV pour un produit suivi · aucun message externe envoyé.`)}>Déclencher la notification de test</button></article><article><span>REPRISE</span><h3>Éléments de preuve</h3><p>Les articles et instantanés CVE sont conservés dans SQLite. Le cadrage reste dans le navigateur. Les exports CSV et Markdown permettent à un tiers de reprendre le dispositif.</p></article></div><div className="documentation-preview"><header><div><span>DOCUMENT EXPORTABLE</span><h3>Procédure complète</h3></div><button type="button" onClick={() => download('openvigie-dispositif-de-veille.md', documentation, 'text/markdown;charset=utf-8')}>Télécharger Markdown</button></header><pre>{documentation}</pre></div></section> : null}
    </section>
  </div>;
}
