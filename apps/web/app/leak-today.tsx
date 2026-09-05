'use client';

import { useCallback, useEffect, useState } from 'react';

type Scope = 'all' | 'france' | 'international';
type Leak = { id: string; title: string; url: string; excerpt: string; publishedAt: string; scope: 'france' | 'international'; actor: string; source: { name: string; homepage: string; kind: string } };
type Payload = { generatedAt: string; period: { label: string }; items: Leak[]; counts: { france: number; international: number }; watchlist: string[]; sources: Array<{ name: string; url: string; status: string }>; method: string; error?: string };

function date(value: string) {
  return new Intl.DateTimeFormat('fr-FR', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
}

export default function LeakToday() {
  const [days, setDays] = useState('all');
  const [scope, setScope] = useState<Scope>('all');
  const [historyQuery, setHistoryQuery] = useState('');
  const [visibleCount, setVisibleCount] = useState(100);
  const [data, setData] = useState<Payload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true); setError('');
    try {
      const response = await fetch(`/api/leaks?days=${days}`, { cache: 'no-store' });
      const payload = await response.json() as Payload;
      if (!response.ok) throw new Error(payload.error ?? 'Veille indisponible.');
      setData(payload);
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Veille indisponible.'); }
    finally { setLoading(false); }
  }, [days]);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);
  const query = historyQuery.trim().toLocaleLowerCase('fr-FR');
  const items = (data?.items ?? []).filter((item) => {
    const inScope = scope === 'all' || item.scope === scope;
    const searchable = `${item.title} ${item.excerpt} ${item.source.name}`.toLocaleLowerCase('fr-FR');
    return inScope && (!query || searchable.includes(query));
  });
  const visibleItems = items.slice(0, visibleCount);

  return <section className="content leak-watch" id="main-content">
    <header className="leak-hero glass-panel">
      <div><p className="eyebrow neon">Veille attribuée · France et international</p><h1>FUITES DE <em>DONNÉES</em></h1><p>Les signalements français et les incidents majeurs internationaux, sans republier de données compromises.</p></div>
      <div className="leak-live"><i /><strong>{data?.period.label ?? 'Synchronisation'}</strong><span>Mis à jour {data ? date(data.generatedAt) : 'en cours'}</span></div>
    </header>

    <div className="leak-toolbar glass-panel">
      <div role="tablist" aria-label="Périmètre des fuites">
        {([['all', 'Toutes'], ['france', `France · ${data?.counts.france ?? 0}`], ['international', `International · ${data?.counts.international ?? 0}`]] as const).map(([id, label]) => <button type="button" role="tab" aria-selected={scope === id} onClick={() => { setScope(id); setVisibleCount(100); }} key={id}>{label}</button>)}
      </div>
      <label className="leak-history-search"><span>Rechercher</span><input type="search" value={historyQuery} onChange={(event) => { setHistoryQuery(event.target.value); setVisibleCount(100); }} placeholder="Organisme, source…" /></label>
      <label><span>Période</span><select value={days} onChange={(event) => { setDays(event.target.value); setVisibleCount(100); }}><option value="all">Tout l’historique</option><option value="1">Aujourd’hui</option><option value="7">7 jours</option><option value="30">30 jours</option><option value="365">1 an</option></select></label>
    </div>

    {error ? <div className="search-state glass-panel"><b>△</b><p>{error}</p><button type="button" onClick={() => void load()}>Réessayer</button></div> : null}
    {loading && !data ? <div className="news-message news-loading glass-panel"><i /><div><strong>OpenVigie recoupe les registres</strong><p>Lecture des flux officiels en cours.</p></div></div> : null}
    {!loading && data && !items.length ? <div className="leak-empty glass-panel"><b>✓</b><h2>Aucune fuite recensée sur ce périmètre</h2><p>Une absence de signalement ne prouve pas une absence d’incident. Élargis la période pour consulter les entrées récentes.</p></div> : null}

    {items.length ? <section className="leak-results glass-panel"><header><div><p>Du plus récent au plus ancien</p><h2>{items.length} signalement{items.length > 1 ? 's' : ''}</h2></div><strong>Sources attribuées</strong></header><div className="leak-grid">{visibleItems.map((item) => <article key={item.id}>
      <div className="leak-card-meta"><span>{item.scope === 'france' ? 'FRANCE' : item.actor || 'INTERNATIONAL'}</span><time>{date(item.publishedAt)}</time></div>
      <h3><a href={item.url} target="_blank" rel="noreferrer">{item.title}</a></h3>
      {item.excerpt ? <p>{item.excerpt}</p> : null}
      <footer><strong>{item.source.name}</strong><a href={item.url} target="_blank" rel="noreferrer">Voir le signalement ↗</a></footer>
    </article>)}</div>{visibleCount < items.length ? <button type="button" className="load-more-leaks" onClick={() => setVisibleCount((count) => count + 100)}>Afficher 100 signalements supplémentaires · {items.length - visibleCount} restants</button> : null}</section> : null}

    {data ? <footer className="leak-sources glass-panel"><div><strong>Sources françaises</strong>{data.sources.map((source) => <a href={source.url} target="_blank" rel="noreferrer" key={source.name}><i />{source.name} ↗</a>)}</div><div><strong>Acteurs internationaux suivis</strong><span>{data.watchlist.join(' · ')}</span></div><p>{data.method} Les signalements restent à vérifier auprès de l’organisme concerné.</p></footer> : null}
  </section>;
}
