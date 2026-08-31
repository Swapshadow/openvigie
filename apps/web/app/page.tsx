'use client';

import { useState } from 'react';
import { issues, stories, type Cadence } from './bulletin-data';
import InventoryWorkspace from './inventory-workspace';

type View = 'bulletin' | 'assets';

export default function Home() {
  const [view, setView] = useState<View>('assets');
  const [cadence, setCadence] = useState<Cadence>('daily');
  const [selectedStoryId, setSelectedStoryId] = useState(issues.daily.lead);
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
        <div className="sync-state"><span aria-hidden="true" />NVD + CISA KEV en direct</div>
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
          <InventoryWorkspace />
        )}
      </div>
    </main>
  );
}
