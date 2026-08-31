'use client';

import { useState } from 'react';
import { issues, stories, type Cadence } from './bulletin-data';

type Tab = 'summary' | 'attack' | 'evidence';
type View = 'bulletin' | 'assets';

const assets = [
  { id: 'fortinet', short: 'FG', vendor: 'Fortinet', name: 'FortiGate 100F', version: 'FortiOS 7.4.2', context: 'SSL-VPN exposé', alerts: 3 },
  { id: 'cisco', short: 'CX', vendor: 'Cisco', name: 'Catalyst 9300', version: 'IOS XE 17.9.4a', context: 'Cœur de réseau', alerts: 1 },
  { id: 'aruba', short: 'AR', vendor: 'HPE Aruba', name: 'Aruba CX 6300', version: 'AOS-CX 10.13', context: 'Distribution réseau', alerts: 1 },
  { id: 'sentinelone', short: 'S1', vendor: 'SentinelOne', name: 'Singularity Agent', version: 'Agent 24.1', context: 'Parc postes', alerts: 2 },
];

const attackSteps = [
  ['01', 'Surface', 'L’interface SSL-VPN HTTPS est accessible depuis Internet.'],
  ['02', 'Prérequis', 'Aucun compte requis : le service doit seulement être joignable.'],
  ['03', 'Mécanique', 'Une entrée anormale déclenche une écriture mémoire hors limites.'],
  ['04', 'Effet', 'Le service peut planter ou exécuter du code contrôlé à distance.'],
  ['05', 'Suite', 'L’équipement compromis peut devenir un point de pivot réseau.'],
];

const evidence = [
  ['Fortinet PSIRT', 'Versions affectées, correctifs et contournements', 'Primaire'],
  ['CISA KEV', 'Exploitation observée dans des attaques réelles', 'Confirmée'],
  ['Exploit-DB', 'Recherche par CVE et produit', 'À corréler'],
  ['Metasploit', 'Module, rang, cibles et effets secondaires', 'Lecture seule'],
  ['Nuclei', 'Gabarit de détection et niveau d’intrusion', 'À vérifier'],
];

export default function Home() {
  const [assetId, setAssetId] = useState('fortinet');
  const [tab, setTab] = useState<Tab>('attack');
  const [view, setView] = useState<View>('bulletin');
  const [cadence, setCadence] = useState<Cadence>('daily');
  const [selectedStoryId, setSelectedStoryId] = useState(issues.daily.lead);
  const asset = assets.find((item) => item.id === assetId) ?? assets[0];
  const issue = issues[cadence];
  const leadStory = stories[issue.lead];
  const selectedStory = stories[selectedStoryId] ?? leadStory;

  const selectCadence = (nextCadence: Cadence) => {
    setCadence(nextCadence);
    setSelectedStoryId(issues[nextCadence].lead);
  };

  return (
    <main className="app-shell">
      <div className="sun" aria-hidden="true"><span /></div>
      <div className="horizon-grid" aria-hidden="true" />

      <header className="topbar glass-panel">
        <a className="brand" href="#main-content" aria-label="OpenVigie, aller au contenu">
          <span className="brand-mark" aria-hidden="true">◉</span>
          <span><b>OPEN</b>VIGIE</span>
        </a>
        <div className="sync-state"><span aria-hidden="true" />6 sources synchronisées</div>
        <div className="top-actions">
          <button type="button" className="icon-button" aria-label="Rechercher">⌕</button>
          <button type="button" className="icon-button" aria-label="Notifications">♢</button>
        </div>
      </header>

      <div className="workspace">
        <aside className="sidebar glass-panel" aria-label="Navigation principale">
          <p className="eyebrow">Navigation</p>
          <nav className="nav-list">
            {[
              ['bulletin', '▤', 'Le Bulletin'],
              ['assets', '◫', 'Mon parc'],
              ['veille', '⌁', 'Veille'],
              ['cve', '◇', 'Dossiers CVE'],
              ['preuves', '△', 'Preuves'],
              ['sources', '≋', 'Sources'],
            ].map(([id, icon, label]) => (
              <button
                className="nav-item"
                type="button"
                aria-current={view === id ? 'page' : undefined}
                key={id}
                onClick={() => id === 'bulletin' || id === 'assets' ? setView(id) : undefined}
              >
                <span aria-hidden="true">{icon}</span><span>{label}</span>
              </button>
            ))}
          </nav>
          <div className="open-source-note">
            <strong>100 % open source</strong>
            <span>Pipeline auditable</span>
            <span>Sources traçables</span>
            <span>Contributions ouvertes</span>
          </div>
        </aside>

        {view === 'bulletin' ? (
          <section className="content bulletin" id="main-content">
            <header className="bulletin-masthead glass-panel">
              <div className="bulletin-kicker">{issue.kicker}</div>
              <div className="bulletin-title-row">
                <span>{issue.label}</span>
                <h1>OPENVIGIE <em>LE BULLETIN</em></h1>
                <span>{issue.date}</span>
              </div>
              <div className="bulletin-cadence" role="tablist" aria-label="Période du bulletin">
                {([
                  ['daily', 'Journalier'],
                  ['weekly', 'Hebdomadaire'],
                  ['monthly', 'Mensuel'],
                ] as const).map(([id, label]) => (
                  <button type="button" role="tab" aria-selected={cadence === id} onClick={() => selectCadence(id)} key={id}>{label}</button>
                ))}
              </div>
              <div className="edition-note"><span>Édition de démonstration</span><p>{issue.note}</p></div>
            </header>

            <article className="bulletin-lead glass-panel">
              <div className="lead-index">{leadStory.index}</div>
              <div>
                <div className="story-meta"><span>{leadStory.section}</span><strong data-tone={leadStory.tone}>{leadStory.status}</strong></div>
                <h2>{leadStory.title}</h2>
                <p>{leadStory.deck}</p>
                <div className="source-links" aria-label="Sources de l’article">
                  {leadStory.sources.map((source) => <a href={source.url} target="_blank" rel="noreferrer" key={source.label}>{source.label} ↗</a>)}
                </div>
                <button className="read-dossier" type="button" onClick={() => setSelectedStoryId(leadStory.id)}>Lire le dossier</button>
              </div>
              <aside>
                <span>Pourquoi c’est important</span>
                <p>{leadStory.why}</p>
              </aside>
            </article>

            <div className="bulletin-columns">
              {issue.sides.map((storyId) => {
                const story = stories[storyId];
                return (
                  <button className="story-card glass-panel" type="button" aria-pressed={selectedStoryId === story.id} onClick={() => setSelectedStoryId(story.id)} key={story.id}>
                    <span className="story-number">{story.index}</span>
                    <span className="story-section">{story.section}</span>
                    <strong>{story.title}</strong>
                    <span className="story-deck">{story.deck}</span>
                    <em data-tone={story.tone}>{story.status}</em>
                  </button>
                );
              })}
            </div>

            <div className="briefing-strip glass-panel" aria-label="À suivre également">
              <div className="briefing-label">À suivre</div>
              {issue.briefs.map((storyId) => {
                const story = stories[storyId];
                return (
                  <button type="button" onClick={() => setSelectedStoryId(story.id)} key={story.id}>
                    <span>{story.section}</span><strong>{story.title}</strong>
                  </button>
                );
              })}
            </div>

            <article className="story-dossier glass-panel" aria-live="polite">
              <header>
                <div>
                  <p>{selectedStory.section} · {selectedStory.index}</p>
                  <h2>{selectedStory.title}</h2>
                </div>
                <span className="verification-status" data-tone={selectedStory.tone}>{selectedStory.status}</span>
              </header>
              <div className="story-dossier-grid">
                <section>
                  <h3>Ce qui est établi</h3>
                  <ul>{selectedStory.facts.map((fact) => <li key={fact}>{fact}</li>)}</ul>
                </section>
                <section>
                  <h3>Ce que l’on surveille</h3>
                  <ul>{selectedStory.watch.map((signal) => <li key={signal}>{signal}</li>)}</ul>
                </section>
                <aside>
                  <h3>Sources & nature</h3>
                  {selectedStory.sources.map((source) => (
                    <a href={source.url} target="_blank" rel="noreferrer" key={source.label}>
                      <span>{source.kind}</span><strong>{source.label} ↗</strong>
                    </a>
                  ))}
                </aside>
              </div>
            </article>

            <footer className="editorial-standard glass-panel">
              <strong>Le pacte éditorial OpenVigie</strong>
              <span><i className="dot verified" /> Confirmé : sources identifiées et concordantes</span>
              <span><i className="dot contested" /> Contesté : positions attribuées, désaccord visible</span>
              <span><i className="dot analysis" /> Analyse : interprétation explicitement séparée des faits</span>
            </footer>
          </section>
        ) : (
        <section className="content" id="main-content">
          <div className="page-heading">
            <div>
              <p className="eyebrow neon">Infrastructure intelligence</p>
              <h1>Mon parc</h1>
              <p>Les vulnérabilités qui concernent réellement votre infrastructure.</p>
            </div>
            <div className="last-sync">Dernière veille<br /><strong>il y a 12 min</strong></div>
          </div>

          <div className="asset-grid" aria-label="Équipements surveillés">
            {assets.map((item) => (
              <button
                className="asset-card glass-panel"
                type="button"
                aria-pressed={assetId === item.id}
                key={item.id}
                onClick={() => setAssetId(item.id)}
              >
                <span className="asset-monogram" aria-hidden="true">{item.short}</span>
                <span className="asset-copy"><strong>{item.name}</strong><small>{item.version}</small></span>
                <span className="alert-count">{String(item.alerts).padStart(2, '0')}</span>
              </button>
            ))}
          </div>

          <article className="dossier glass-panel" aria-live="polite">
            <header className="dossier-heading">
              <div>
                <p className="cve-id">CVE-2024-21762</p>
                <h2>{asset.vendor} · {asset.name}</h2>
                <p>{asset.version} · {asset.context}</p>
              </div>
              <div className="badges" aria-label="Caractéristiques principales">
                <span className="badge critical">Critique 9.6</span>
                <span className="badge critical">CISA KEV</span>
                <span className="badge cyan">RCE / DoS</span>
              </div>
            </header>

            <div className="tabs" role="tablist" aria-label="Détails de la vulnérabilité">
              <button type="button" role="tab" aria-selected={tab === 'summary'} onClick={() => setTab('summary')}>Fiche technique</button>
              <button type="button" role="tab" aria-selected={tab === 'attack'} onClick={() => setTab('attack')}>Comprendre l’attaque</button>
              <button type="button" role="tab" aria-selected={tab === 'evidence'} onClick={() => setTab('evidence')}>Preuves publiques</button>
            </div>

            {tab === 'attack' && (
              <section className="tab-panel" aria-label="Comprendre l’attaque">
                <p className="section-label">Anatomie de l’attaque</p>
                <div className="attack-chain">
                  {attackSteps.map(([number, title, description]) => (
                    <div className="attack-step" key={number}>
                      <span>{number}</span><h3>{title}</h3><p>{description}</p>
                    </div>
                  ))}
                </div>
                <div className="impact-grid">
                  {[
                    ['Confidentialité', 'Élevée'],
                    ['Intégrité', 'Élevée'],
                    ['Disponibilité', 'Élevée'],
                    ['Zero-day aujourd’hui', 'Non'],
                  ].map(([label, value]) => <div key={label}><span>{label}</span><strong>{value}</strong></div>)}
                </div>
                <p className="safety-note">OpenVigie explique et référence les preuves publiques sans exécuter d’exploit.</p>
              </section>
            )}

            {tab === 'summary' && (
              <section className="tab-panel" aria-label="Fiche technique">
                <p className="section-label">Synthèse défensive</p>
                <div className="fact-grid">
                  {[
                    ['Faiblesse', 'CWE-787 · écriture hors limites'],
                    ['Vecteur', 'Réseau · sans authentification'],
                    ['Composant', 'FortiOS sslvpnd'],
                    ['Exploitation', 'Observée dans la nature'],
                    ['Remédiation', 'Installer une version corrigée'],
                    ['Contournement', 'Désactiver SSL-VPN temporairement'],
                  ].map(([label, value]) => <div key={label}><span>{label}</span><strong>{value}</strong></div>)}
                </div>
              </section>
            )}

            {tab === 'evidence' && (
              <section className="tab-panel" aria-label="Preuves publiques">
                <p className="section-label">Corrélation des preuves</p>
                <div className="evidence-list">
                  {evidence.map(([source, description, status]) => (
                    <div className="evidence-row" key={source}>
                      <strong>{source}</strong><span>{description}</span><em>{status}</em>
                    </div>
                  ))}
                </div>
              </section>
            )}
          </article>
        </section>
        )}
      </div>
    </main>
  );
}
