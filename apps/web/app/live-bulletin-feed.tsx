'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { Cadence } from './bulletin-data';
import type { LiveArticle, LiveBulletinResponse } from './bulletin-types';

const REFRESH_INTERVAL = 30 * 60 * 1000;
const FRONT_PAGE = '__front__';

function formatDate(value: string | null, includeTime = false) {
  if (!value) return 'Date non fournie';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Date non fournie';
  return new Intl.DateTimeFormat('fr-FR', { dateStyle: 'medium', ...(includeTime ? { timeStyle: 'short' as const } : {}) }).format(date);
}

function cadenceLabel(cadence: Cadence) {
  return { daily: 'Le journal du jour', weekly: 'La revue de la semaine', monthly: 'Le mensuel' }[cadence];
}

function StoryMeta({ article }: { article: LiveArticle }) {
  return <div className="automatic-meta"><span>{article.category}</span><strong>{article.source.name}</strong></div>;
}

export default function LiveBulletinFeed({ cadence }: { cadence: Cadence }) {
  const [data, setData] = useState<LiveBulletinResponse | null>(null);
  const [page, setPage] = useState(FRONT_PAGE);
  const [loadedPage, setLoadedPage] = useState(FRONT_PAGE);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const requestSequence = useRef(0);

  const load = useCallback(async (signal?: AbortSignal) => {
    const requestId = ++requestSequence.current;
    setLoading(true);
    setError('');
    const parameters = new URLSearchParams({ cadence, limit: page === FRONT_PAGE ? '18' : '24' });
    if (page !== FRONT_PAGE) parameters.set('category', page);
    try {
      const response = await fetch(`/api/articles?${parameters}`, { cache: 'no-store', signal });
      const payload = await response.json() as LiveBulletinResponse & { error?: string };
      if (!response.ok) throw new Error(payload.error ?? 'Le bulletin automatique est indisponible.');
      if (requestId !== requestSequence.current) return;
      setData(payload);
      setLoadedPage(page);
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === 'AbortError') return;
      if (requestId !== requestSequence.current) return;
      setError(caught instanceof Error ? caught.message : 'Le bulletin automatique est indisponible.');
    } finally {
      if (!signal?.aborted && requestId === requestSequence.current) setLoading(false);
    }
  }, [cadence, page]);

  useEffect(() => {
    const controller = new AbortController();
    const initial = window.setTimeout(() => void load(controller.signal), 0);
    const interval = window.setInterval(() => void load(), REFRESH_INTERVAL);
    return () => {
      requestSequence.current += 1;
      controller.abort();
      window.clearTimeout(initial);
      window.clearInterval(interval);
    };
  }, [load]);

  const pages = useMemo(() => [FRONT_PAGE, ...(data?.categories.map((item) => item.name) ?? [])], [data]);
  const pageIndex = Math.max(0, pages.indexOf(page));
  const onlineSources = data?.sources.filter((source) => source.status === 'online').length ?? 0;
  const degradedSources = data?.sources.filter((source) => source.status === 'degraded').length ?? 0;
  const pageReady = loadedPage === page;
  const lead = pageReady ? data?.articles[0] : undefined;
  const frontSecondary = pageReady ? data?.articles.slice(1, 3) ?? [] : [];
  const frontBriefs = pageReady ? data?.articles.slice(3, 5) ?? [] : [];
  const categoryArticles = pageReady ? data?.articles.slice(0, 18) ?? [] : [];

  const turnPage = (direction: -1 | 1) => {
    const nextIndex = Math.min(pages.length - 1, Math.max(0, pageIndex + direction));
    setPage(pages[nextIndex]);
    document.querySelector('.live-newsroom')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <section className="live-newsroom glass-panel" aria-live="polite">
      <header className="live-newsroom-header newspaper-header">
        <div><p>Sources ouvertes · collecte continue</p><h2>{page === FRONT_PAGE ? cadenceLabel(cadence) : page}</h2><span>{data?.period.label ?? 'Synchronisation des flux en cours'}</span></div>
        <div className="newspaper-folio"><strong>PAGE {String(pageIndex + 1).padStart(2, '0')}</strong><span>SUR {String(Math.max(1, pages.length)).padStart(2, '0')}</span></div>
        <div className="feed-health"><strong><i data-state={degradedSources ? 'degraded' : 'online'} />{data ? `${onlineSources}/${data.sources.length} flux actifs` : 'Synchronisation des flux'}</strong><span>{data ? `Actualisé le ${formatDate(data.generatedAt, true)}` : 'Première synchronisation en cours'}</span></div>
      </header>

      {data?.categories.length ? (
        <nav className="newspaper-sections" aria-label="Pages du bulletin">
          <button type="button" aria-current={page === FRONT_PAGE ? 'page' : undefined} onClick={() => setPage(FRONT_PAGE)}>La Une</button>
          {data.categories.map((item) => <button type="button" aria-current={page === item.name ? 'page' : undefined} onClick={() => setPage(item.name)} key={item.name}>{item.name} <span>{item.count}</span></button>)}
        </nav>
      ) : null}

      {error ? <div className="news-message news-error"><span aria-hidden="true">△</span><div><strong>Le journal n’a pas pu être chargé</strong><p>{error}</p></div><button type="button" onClick={() => void load()}>Réessayer</button></div> : null}
      {loading && (!data || !pageReady) ? <div className="news-message news-loading"><i /><div><strong>OpenVigie compose l’édition</strong><p>Les annonces majeures sont classées à partir des sources officielles.</p></div></div> : null}
      {!loading && !error && !lead ? <div className="news-message"><span aria-hidden="true">⌁</span><div><strong>Aucun article dans cette page</strong><p>Le collecteur poursuit sa synchronisation en arrière-plan.</p></div></div> : null}

      {lead && page === FRONT_PAGE ? (
        <div className="front-page">
          {data?.archiveFallback ? <p className="archive-notice">Aucune publication dans la période choisie : les dernières archives sont affichées.</p> : null}
          <div className="front-page-banner"><span>LA UNE</span><p>Les cinq annonces prioritaires de l’édition · fraîcheur, autorité de la source et signaux CVE</p></div>
          <article className="front-lead"><StoryMeta article={lead} /><h3><a href={lead.url} target="_blank" rel="noreferrer">{lead.title}</a></h3>{lead.excerpt ? <p>{lead.excerpt}</p> : null}<footer><span>{formatDate(lead.publishedAt)}{lead.author ? ` · ${lead.author}` : ''}</span><a href={lead.url} target="_blank" rel="noreferrer">Lire l’annonce originale ↗</a></footer></article>
          <div className="front-secondary">{frontSecondary.map((article, index) => <article key={article.id}><b>0{index + 2}</b><StoryMeta article={article} /><h3><a href={article.url} target="_blank" rel="noreferrer">{article.title}</a></h3>{article.excerpt ? <p>{article.excerpt}</p> : null}<a href={article.url} target="_blank" rel="noreferrer">Source originale ↗</a></article>)}</div>
          {frontBriefs.length ? <div className="front-briefs"><strong>EN BREF</strong>{frontBriefs.map((article) => <article key={article.id}><span>{article.category}</span><h3><a href={article.url} target="_blank" rel="noreferrer">{article.title}</a></h3><small>{article.source.name}</small></article>)}</div> : null}
        </div>
      ) : null}

      {lead && page !== FRONT_PAGE ? (
        <div className="section-page">
          <header><span>RUBRIQUE</span><h3>{page}</h3><p>{categoryArticles.length} publication{categoryArticles.length > 1 ? 's' : ''} sélectionnée{categoryArticles.length > 1 ? 's' : ''} dans cette page.</p></header>
          <article className="section-lead"><StoryMeta article={lead} /><h3><a href={lead.url} target="_blank" rel="noreferrer">{lead.title}</a></h3>{lead.excerpt ? <p>{lead.excerpt}</p> : null}<footer><span>{formatDate(lead.publishedAt)}</span><a href={lead.url} target="_blank" rel="noreferrer">Lire chez {lead.source.name} ↗</a></footer></article>
          <div className="section-columns">{categoryArticles.slice(1).map((article, index) => <article key={article.id}><b>{String(index + 2).padStart(2, '0')}</b><StoryMeta article={article} /><h3><a href={article.url} target="_blank" rel="noreferrer">{article.title}</a></h3>{article.excerpt ? <p>{article.excerpt}</p> : null}<footer><span>{formatDate(article.publishedAt)}</span><a href={article.url} target="_blank" rel="noreferrer">Source ↗</a></footer></article>)}</div>
        </div>
      ) : null}

      {data ? <><nav className="page-turner" aria-label="Tourner les pages du bulletin"><button type="button" disabled={pageIndex === 0} onClick={() => turnPage(-1)}>← Page précédente</button><span>{page === FRONT_PAGE ? 'La Une' : page}</span><button type="button" disabled={pageIndex === pages.length - 1} onClick={() => turnPage(1)}>Page suivante →</button></nav><footer className="automatic-footer"><div><strong>Sélection automatisée · pas une validation éditoriale</strong><span>{data.ranking.method}</span><span>Aucune IA ne réécrit ou ne complète les faits des sources.</span></div><details><summary>{data.sources.length} sources suivies · {degradedSources ? `${degradedSources} dégradée(s)` : 'toutes disponibles'}</summary><div className="feed-source-list">{data.sources.map((source) => <a href={source.homepage} target="_blank" rel="noreferrer" key={source.id}><i data-state={source.status} /><span><strong>{source.name}</strong><small>{source.kind}</small></span></a>)}</div></details></footer></> : null}
    </section>
  );
}
