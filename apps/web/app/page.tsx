'use client';

import { useState } from 'react';

type Tab = 'summary' | 'attack' | 'evidence';

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
  const asset = assets.find((item) => item.id === assetId) ?? assets[0];

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
              ['◫', 'Mon parc', true],
              ['⌁', 'Veille', false],
              ['◇', 'Dossiers CVE', false],
              ['△', 'Preuves', false],
              ['≋', 'Sources', false],
              ['⚙', 'Réglages', false],
            ].map(([icon, label, active]) => (
              <button className="nav-item" type="button" aria-current={active ? 'page' : undefined} key={String(label)}>
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
      </div>
    </main>
  );
}
