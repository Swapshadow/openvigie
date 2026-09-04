'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import type { LiveArticle } from './bulletin-types';

type CveArticle = { title: string; url: string; source: string; publishedAt: string | null };

type TopCve = {
  cve: string;
  mentions: number;
  kev: boolean;
  kevRansomware: boolean;
  kevDateAdded: string | null;
  vendor: string | null;
  product: string | null;
  articles: CveArticle[];
};

type WeeklyReport = {
  generatedAt: string;
  period: { label: string; start: string; end: string };
  stats: { articles: number; sources: number; cves: number; kev: number; categories: number };
  topCve: TopCve[];
  topNews: LiveArticle[];
  trending: Array<{ term: string; count: number }>;
  categories: Array<{ name: string; count: number }>;
  sources: string[];
  ranking: { method: string; warning: string };
};

function formatDate(value: string | null, withTime = false) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat('fr-FR', {
    dateStyle: 'medium',
    ...(withTime ? { timeStyle: 'short' as const } : {}),
  }).format(date);
}

export default function WeeklyReport() {
  const [data, setData] = useState<WeeklyReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const requestSequence = useRef(0);

  const load = useCallback(async (signal?: AbortSignal) => {
    const requestId = ++requestSequence.current;
    setLoading(true);
    setError('');
    try {
      const response = await fetch('/api/bulletin-weekly', { cache: 'no-store', signal });
      const payload = await response.json() as WeeklyReport & { error?: string };
      if (!response.ok) throw new Error(payload.error ?? 'Le rapport hebdomadaire est indisponible.');
      if (requestId !== requestSequence.current) return;
      setData(payload);
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === 'AbortError') return;
      if (requestId !== requestSequence.current) return;
      setError(caught instanceof Error ? caught.message : 'Le rapport hebdomadaire est indisponible.');
    } finally {
      if (!signal?.aborted && requestId === requestSequence.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => void load(controller.signal), 0);
    return () => {
      requestSequence.current += 1;
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [load]);

  const maxCategory = data ? Math.max(1, ...data.categories.map((item) => item.count)) : 1;
  const maxTrend = data ? Math.max(1, ...data.trending.map((item) => item.count)) : 1;

  return (
    <section className="content weekly" id="main-content">
      <header className="weekly-masthead glass-panel">
        <div className="weekly-title">
          <p className="eyebrow">Synthèse éditoriale · 7 jours</p>
          <h1>OPENVIGIE <em>RAPPORT HEBDO</em></h1>
          <p className="weekly-sub">
            {data
              ? `${formatDate(data.period.start)} → ${formatDate(data.period.end)} · généré le ${formatDate(data.generatedAt, true)}`
              : 'Compilation de la semaine…'}
          </p>
        </div>
        <div className="weekly-actions">
          <button type="button" onClick={() => void load()} className="weekly-refresh">Actualiser</button>
        </div>
      </header>

      {error ? (
        <div className="weekly-message weekly-error glass-panel">
          <strong>Rapport indisponible</strong>
          <p>{error}</p>
          <button type="button" onClick={() => void load()}>Réessayer</button>
        </div>
      ) : loading && !data ? (
        <div className="weekly-message glass-panel"><i /><p>OpenVigie compile les 7 derniers jours…</p></div>
      ) : data ? (
        <>
          <div className="weekly-kpis">
            {[
              ['Articles', data.stats.articles],
              ['Sources actives', data.stats.sources],
              ['CVE citées', data.stats.cves],
              ['Dont CISA KEV', data.stats.kev],
              ['Catégories', data.stats.categories],
            ].map(([label, value]) => (
              <div key={label} className="weekly-kpi glass-panel">
                <strong>{value}</strong><span>{label}</span>
              </div>
            ))}
          </div>

          <section className="weekly-block glass-panel">
            <h2>Top CVE de la semaine</h2>
            {data.topCve.length === 0 ? (
              <p className="weekly-empty">Aucune CVE citée sur la période.</p>
            ) : (
              <ul className="weekly-cve">
                {data.topCve.map((entry) => (
                  <li key={entry.cve}>
                    <div className="weekly-cve-head">
                      <span className="weekly-cve-id">{entry.cve}</span>
                      {entry.kev ? <span className="weekly-badge kev">CISA KEV</span> : null}
                      {entry.kevRansomware ? <span className="weekly-badge ransom">Rançongiciel</span> : null}
                      <span className="weekly-cve-count">{entry.mentions} citation{entry.mentions > 1 ? 's' : ''}</span>
                    </div>
                    {(entry.vendor || entry.product) ? (
                      <p className="weekly-cve-vendor">{[entry.vendor, entry.product].filter(Boolean).join(' · ')}
                        {entry.kevDateAdded ? ` · KEV depuis le ${formatDate(entry.kevDateAdded)}` : ''}</p>
                    ) : null}
                    <ul className="weekly-cve-articles">
                      {entry.articles.map((article) => (
                        <li key={article.url}>
                          <a href={article.url} target="_blank" rel="noreferrer noopener">{article.title}</a>
                          <em>{article.source}</em>
                        </li>
                      ))}
                    </ul>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="weekly-block glass-panel">
            <h2>Top actualités</h2>
            {data.topNews.length === 0 ? (
              <p className="weekly-empty">Aucune actualité sur la période.</p>
            ) : (
              <ol className="weekly-news">
                {data.topNews.map((article) => (
                  <li key={article.id}>
                    <a href={article.url} target="_blank" rel="noreferrer noopener">{article.title}</a>
                    <div className="weekly-news-meta">
                      {article.source.name} · {formatDate(article.publishedAt)}
                      {article.cves.length ? ` · ${article.cves.slice(0, 4).join(', ')}` : ''}
                    </div>
                    {article.excerpt ? <p>{article.excerpt}</p> : null}
                  </li>
                ))}
              </ol>
            )}
          </section>

          <section className="weekly-block glass-panel">
            <h2>Mots-clés en tendance</h2>
            {data.trending.length === 0 ? (
              <p className="weekly-empty">Pas assez de volume pour dégager une tendance.</p>
            ) : (
              <div className="weekly-trend">
                {data.trending.map((item) => (
                  <span key={item.term} style={{ fontSize: `${0.82 + (item.count / maxTrend) * 0.7}rem` }}>
                    {item.term}<i>{item.count}</i>
                  </span>
                ))}
              </div>
            )}
          </section>

          <section className="weekly-block glass-panel">
            <h2>Répartition par catégorie</h2>
            <ul className="weekly-cats">
              {data.categories.map((item) => (
                <li key={item.name}>
                  <span>{item.name}</span>
                  <span className="weekly-bar"><i style={{ width: `${(item.count / maxCategory) * 100}%` }} /></span>
                  <b>{item.count}</b>
                </li>
              ))}
            </ul>
          </section>

          <footer className="weekly-footer glass-panel">
            <p><strong>Sélection automatisée</strong> · {data.ranking.method}</p>
            <p>{data.ranking.warning}</p>
          </footer>
        </>
      ) : null}
    </section>
  );
}
