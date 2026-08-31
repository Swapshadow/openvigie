'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { Cadence } from './bulletin-data';
import type { LiveBulletinResponse } from './bulletin-types';

const REFRESH_INTERVAL = 30 * 60 * 1000;

function formatDate(value: string | null, includeTime = false) {
  if (!value) return 'Date non fournie';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Date non fournie';
  return new Intl.DateTimeFormat('fr-FR', {
    dateStyle: 'medium',
    ...(includeTime ? { timeStyle: 'short' as const } : {}),
  }).format(date);
}

function cadenceLabel(cadence: Cadence) {
  return { daily: 'Fil quotidien', weekly: 'Revue hebdomadaire', monthly: 'Revue mensuelle' }[cadence];
}

export default function LiveBulletinFeed({ cadence }: { cadence: Cadence }) {
  const [data, setData] = useState<LiveBulletinResponse | null>(null);
  const [category, setCategory] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const requestSequence = useRef(0);

  const load = useCallback(async (signal?: AbortSignal) => {
    const requestId = ++requestSequence.current;
    setLoading(true);
    setError('');
    const parameters = new URLSearchParams({ cadence, limit: cadence === 'daily' ? '18' : '24' });
    if (category) parameters.set('category', category);
    try {
      const response = await fetch(`/api/articles?${parameters}`, { cache: 'no-store', signal });
      const payload = await response.json() as LiveBulletinResponse & { error?: string };
      if (!response.ok) throw new Error(payload.error ?? 'Le bulletin automatique est indisponible.');
      if (requestId !== requestSequence.current) return;
      setData(payload);
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === 'AbortError') return;
      if (requestId !== requestSequence.current) return;
      setError(caught instanceof Error ? caught.message : 'Le bulletin automatique est indisponible.');
    } finally {
      if (!signal?.aborted && requestId === requestSequence.current) setLoading(false);
    }
  }, [cadence, category]);

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

  useEffect(() => {
    if (!loading && !error && data?.articles.length === 0) {
      const retry = window.setTimeout(() => void load(), 20_000);
      return () => window.clearTimeout(retry);
    }
  }, [data, error, load, loading]);

  const onlineSources = useMemo(
    () => data?.sources.filter((source) => source.status === 'online').length ?? 0,
    [data],
  );
  const degradedSources = useMemo(
    () => data?.sources.filter((source) => source.status === 'degraded').length ?? 0,
    [data],
  );
  const lead = data?.articles[0];
  const remaining = data?.articles.slice(1) ?? [];

  return (
    <section className="live-newsroom glass-panel" aria-live="polite">
      <header className="live-newsroom-header">
        <div>
          <p>Sources ouvertes · collecte continue</p>
          <h2>{cadenceLabel(cadence)}</h2>
          <span>{data?.period.label ?? 'Synchronisation des flux en cours'}</span>
        </div>
        <div className="feed-health">
          <strong><i data-state={degradedSources ? 'degraded' : 'online'} />{onlineSources}/{data?.sources.length ?? 14} flux actifs</strong>
          <span>{data ? `Sélection actualisée le ${formatDate(data.generatedAt, true)}` : 'Première synchronisation en cours'}</span>
        </div>
      </header>

      {data?.categories.length ? (
        <div className="news-filters" aria-label="Filtrer les articles par thème">
          <button type="button" aria-pressed={!category} onClick={() => setCategory('')}>Tout</button>
          {data.categories.map((item) => (
            <button type="button" aria-pressed={category === item.name} onClick={() => setCategory(item.name)} key={item.name}>
              {item.name} <span>{item.count}</span>
            </button>
          ))}
        </div>
      ) : null}

      {error ? (
        <div className="news-message news-error">
          <span aria-hidden="true">△</span>
          <div><strong>Le fil n’a pas pu être chargé</strong><p>{error}</p></div>
          <button type="button" onClick={() => void load()}>Réessayer</button>
        </div>
      ) : null}

      {loading && !data ? (
        <div className="news-message news-loading"><i /><div><strong>OpenVigie interroge les sources</strong><p>Les premiers articles arrivent généralement en moins d’une minute.</p></div></div>
      ) : null}

      {!loading && !error && !lead ? (
        <div className="news-message"><span aria-hidden="true">⌁</span><div><strong>Aucun article dans cette période</strong><p>Le collecteur poursuit sa première synchronisation en arrière-plan.</p></div></div>
      ) : null}

      {lead ? (
        <>
          {data.archiveFallback ? <p className="archive-notice">Aucun article dans la période choisie : les dernières publications archivées sont affichées.</p> : null}
          <article className="automatic-lead">
            <div className="automatic-lead-index">UNE</div>
            <div>
              <div className="automatic-meta"><span>{lead.category}</span><strong>{lead.source.name}</strong></div>
              <h3><a href={lead.url} target="_blank" rel="noreferrer">{lead.title}</a></h3>
              {lead.excerpt ? <p>{lead.excerpt}</p> : null}
              <div className="automatic-byline">
                <span>{formatDate(lead.publishedAt)}{lead.author ? ` · ${lead.author}` : ''}</span>
                {lead.cves.map((cve) => <b key={cve}>{cve}</b>)}
              </div>
              <a className="original-link" href={lead.url} target="_blank" rel="noreferrer">Lire chez {lead.source.name} ↗</a>
            </div>
            <aside>
              <span>Nature de la source</span>
              <strong>{lead.source.kind}</strong>
              <p>Article original, attribution et lien conservés. OpenVigie ne copie pas le corps de la publication.</p>
            </aside>
          </article>

          <div className="automatic-grid">
            {remaining.map((article, index) => (
              <article className="automatic-card" key={article.id}>
                <div className="automatic-card-index">{String(index + 2).padStart(2, '0')}</div>
                <div className="automatic-meta"><span>{article.category}</span><strong>{article.source.name}</strong></div>
                <h3><a href={article.url} target="_blank" rel="noreferrer">{article.title}</a></h3>
                {article.excerpt ? <p>{article.excerpt}</p> : null}
                <footer>
                  <span>{formatDate(article.publishedAt)}</span>
                  {article.cves.length ? <b>{article.cves.slice(0, 2).join(' · ')}</b> : null}
                  <a href={article.url} target="_blank" rel="noreferrer" aria-label={`Lire l’article original chez ${article.source.name}`}>Source ↗</a>
                </footer>
              </article>
            ))}
          </div>
        </>
      ) : null}

      {data ? (
        <footer className="automatic-footer">
          <div>
            <strong>Classement automatisé · pas une validation éditoriale</strong>
            <span>{data.ranking.method}</span>
            <span>Aucune IA ne réécrit, ne traduit ou ne complète les faits des sources.</span>
          </div>
          <details>
            <summary>{data.sources.length} sources suivies · {degradedSources ? `${degradedSources} dégradée(s)` : 'toutes disponibles'}</summary>
            <div className="feed-source-list">
              {data.sources.map((source) => (
                <a href={source.homepage} target="_blank" rel="noreferrer" key={source.id}>
                  <i data-state={source.status} /><span><strong>{source.name}</strong><small>{source.kind}</small></span>
                </a>
              ))}
            </div>
          </details>
        </footer>
      ) : null}
    </section>
  );
}
