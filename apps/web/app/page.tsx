'use client';

import { useState } from 'react';
import { issues, type Cadence } from './bulletin-data';
import InventoryWorkspace from './inventory-workspace';
import LiveBulletinFeed from './live-bulletin-feed';

type View = 'bulletin' | 'assets';

export default function Home() {
  const [view, setView] = useState<View>('bulletin');
  const [cadence, setCadence] = useState<Cadence>('daily');
  const issue = issues[cadence];

  const selectCadence = (nextCadence: Cadence) => {
    setCadence(nextCadence);
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
        <div className="sync-state"><span aria-hidden="true" />CVE + sources éditoriales en direct</div>
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
            ].map(([id, icon, label]) => (
              <button
                className="nav-item"
                type="button"
                aria-current={view === id ? 'page' : undefined}
                key={id}
                onClick={() => setView(id as View)}
              >
                <span className="nav-icon" aria-hidden="true">{icon}</span><span>{label}</span>
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
              <div className="edition-note"><span>Édition vivante</span><p>{issue.note}</p></div>
            </header>

            <LiveBulletinFeed cadence={cadence} key={cadence} />
          </section>
        ) : (
          <InventoryWorkspace />
        )}
      </div>
    </main>
  );
}
