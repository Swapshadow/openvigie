'use client';

import { useState } from 'react';
import { issues, type Cadence } from './bulletin-data';
import InventoryWorkspace from './inventory-workspace';
import LiveBulletinFeed from './live-bulletin-feed';
import DeepSearch from './deep-search';
import LeakToday from './leak-today';
import SurveillanceMatrix from './surveillance-matrix';
import BulletinUnified from './bulletin-unified';
import VigiChat from './vigi-chat';

type View = 'unified' | 'bulletin' | 'leaks' | 'assets' | 'matrix' | 'search';

type IconName = View | 'radar' | 'notifications';

function AppIcon({ name }: { name: IconName }) {
  const paths: Record<IconName, React.ReactNode> = {
    unified: <><path d="M4 6.5h7M4 11h7M4 15.5h5" /><path d="M14.5 5.5h5.5v13h-5.5z" /><path d="M16 8.5h2.5M16 11.5h2.5M16 14.5h1.5" /></>,
    bulletin: <><path d="M6.5 4.5h8.25A2.25 2.25 0 0 1 17 6.75v12.75H6.5A2.5 2.5 0 0 1 4 17V7a2.5 2.5 0 0 1 2.5-2.5Z" /><path d="M8 8h5M8 11.5h5M8 15h3.5M17 7h.5A2.5 2.5 0 0 1 20 9.5V17a2.5 2.5 0 0 1-2.5 2.5H17" /></>,
    leaks: <><path d="M12 3.5s5.25 5.75 5.25 10a5.25 5.25 0 0 1-10.5 0c0-4.25 5.25-10 5.25-10Z" /><path d="M9.5 14.25a2.5 2.5 0 0 0 2.5 2.5" /></>,
    assets: <><rect x="3.5" y="5" width="17" height="14" rx="2.5" /><path d="M8 19v2M16 19v2M8.5 9.5h7M8.5 13h4.5" /><circle cx="17" cy="13" r="1" fill="currentColor" stroke="none" /></>,
    matrix: <><path d="M4 5.5h16M4 12h16M4 18.5h16M8 3.5v17M15.5 3.5v17" /><path d="m10 15 1.5 1.5 2.75-3" /></>,
    search: <><circle cx="10.5" cy="10.5" r="6" /><path d="m15 15 5 5M10.5 8v5M8 10.5h5" /></>,
    radar: <><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="3.5" /><path d="M12 12 18.5 5.5" /></>,
    notifications: <><path d="M6.5 9.5a5.5 5.5 0 0 1 11 0c0 6 2.25 6.25 2.25 6.25H4.25S6.5 15.5 6.5 9.5Z" /><path d="M10 19.5h4" /></>,
  };

  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}

export default function Home() {
  const [view, setView] = useState<View>('unified');
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
          <span className="brand-mark"><AppIcon name="radar" /></span>
          <span><b>OPEN</b>VIGIE</span>
        </a>
        <div className="sync-state"><span aria-hidden="true" />CVE + sources éditoriales en direct</div>
        <div className="top-actions">
          <button type="button" className="icon-button" aria-label="Rechercher" onClick={() => setView('search')}><AppIcon name="search" /></button>
          <button type="button" className="icon-button" aria-label="Notifications"><AppIcon name="notifications" /></button>
        </div>
      </header>

      <div className="workspace">
        <aside className="sidebar glass-panel" aria-label="Navigation principale">
          <p className="eyebrow">Navigation</p>
          <nav className="nav-list">
            {[
              ['unified', 'Bulletin unifié'],
              ['bulletin', 'Le Bulletin'],
              ['leaks', 'Leak today?'],
              ['assets', 'Mon parc'],
              ['matrix', 'Plan de veille'],
              ['search', 'Recherche approfondie'],
            ].map(([id, label]) => (
              <button
                className="nav-item"
                type="button"
                aria-current={view === id ? 'page' : undefined}
                key={id}
                onClick={() => setView(id as View)}
              >
                <span className="nav-icon"><AppIcon name={id as View} /></span><span>{label}</span>
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

        {view === 'unified' ? (
          <BulletinUnified />
        ) : view === 'bulletin' ? (
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
        ) : view === 'leaks' ? (
          <LeakToday />
        ) : view === 'assets' ? (
          <InventoryWorkspace />
        ) : view === 'matrix' ? (
          <SurveillanceMatrix />
        ) : <DeepSearch />}
      </div>

      <VigiChat cadence={cadence} />
    </main>
  );
}
