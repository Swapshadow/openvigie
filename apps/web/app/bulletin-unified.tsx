'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { FeedStatus, LiveArticle } from './bulletin-types';

const REFRESH_INTERVAL = 15 * 60 * 1000;
const ALL_CATEGORIES = '__all__';

export type UnifiedCadence = 'today' | 'daily' | 'weekly' | 'monthly';

type CategoryFacet = { name: string; count: number };

type UnifiedBulletinResponse = {
  cadence: UnifiedCadence;
  generatedAt: string;
  period: { label: string; start: string; end: string };
  archiveFallback: boolean;
  articles: LiveArticle[];
  categories: CategoryFacet[];
  selectedCategories: CategoryFacet[];
  totalInWindow: number;
  returned: number;
  limit: number;
  sources: FeedStatus[];
  ranking: { method: string; warning: string };
};

const CADENCES: Array<[UnifiedCadence, string]> = [
  ['today', "Aujourd’hui"],
  ['daily', '48 heures'],
  ['weekly', 'Semaine'],
  ['monthly', 'Mois'],
];

function formatDate(value: string | null, includeTime = false) {
  if (!value) return 'Date non fournie';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Date non fournie';
  return new Intl.DateTimeFormat('fr-FR', {
    dateStyle: 'medium',
    ...(includeTime ? { timeStyle: 'short' as const } : {}),
  }).format(date);
}

function ArticleThumb({ src, alt, eager = false }: { src: string; alt: string; eager?: boolean }) {
  const [failed, setFailed] = useState(false);
  if (failed) return null;
  return (
    <figure className="unified-media">
      {/* Feed-provided cover; hidden on load failure so the card stays clean. */}
      <img
        src={src}
        alt={alt}
        loading={eager ? 'eager' : 'lazy'}
        referrerPolicy="no-referrer"
        onError={() => setFailed(true)}
      />
    </figure>
  );
}

function ArticleMeta({ article }: { article: LiveArticle }) {
  return (
    <div className="unified-item-head">
      <span className="unified-cat">{article.category}</span>
      <strong className="unified-source">{article.source.name}</strong>
      <time dateTime={article.publishedAt ?? undefined}>{formatDate(article.publishedAt, true)}</time>
    </div>
  );
}

function CveList({ cves, max = 8 }: { cves: string[]; max?: number }) {
  if (!cves.length) return null;
  return (
    <ul className="unified-cves">
      {cves.slice(0, max).map((cve) => <li key={cve}>{cve}</li>)}
      {cves.length > max ? <li className="more">+{cves.length - max}</li> : null}
    </ul>
  );
}

/** The one story the window is about: full-width, image-led, longest excerpt. */
function LeadStory({ article }: { article: LiveArticle }) {
  return (
    <article className={`unified-lead${article.imageUrl ? ' has-media' : ''}`}>
      {article.imageUrl ? <ArticleThumb src={article.imageUrl} alt="" eager /> : null}
      <div className="unified-lead-copy">
        <ArticleMeta article={article} />
        <h2><a href={article.url} target="_blank" rel="noreferrer noopener">{article.title}</a></h2>
        {article.excerpt ? <p>{article.excerpt}</p> : null}
        <CveList cves={article.cves} />
      </div>
    </article>
  );
}

/** Second tier: a magazine row of image-led cards under the lead. */
function FeatureCard({ article }: { article: LiveArticle }) {
  return (
    <article className={`unified-feature${article.imageUrl ? ' has-media' : ''}`}>
      {article.imageUrl ? <ArticleThumb src={article.imageUrl} alt="" /> : null}
      <div className="unified-feature-copy">
        <ArticleMeta article={article} />
        <h3><a href={article.url} target="_blank" rel="noreferrer noopener">{article.title}</a></h3>
        {article.excerpt ? <p>{article.excerpt}</p> : null}
        <CveList cves={article.cves} max={4} />
      </div>
    </article>
  );
}

export default function BulletinUnified() {
  const [cadence, setCadence] = useState<UnifiedCadence>('today');
  const [category, setCategory] = useState(ALL_CATEGORIES);
  const [query, setQuery] = useState('');
  const [data, setData] = useState<UnifiedBulletinResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const requestSequence = useRef(0);

  const load = useCallback(async (signal?: AbortSignal) => {
    const requestId = ++requestSequence.current;
    setLoading(true);
    setError('');
    try {
      const parameters = new URLSearchParams({ cadence, limit: '50' });
      const response = await fetch(`/api/bulletin-unified?${parameters}`, { cache: 'no-store', signal });
      const payload = await response.json() as UnifiedBulletinResponse & { error?: string };
      if (!response.ok) throw new Error(payload.error ?? 'Le bulletin unifié est indisponible.');
      if (requestId !== requestSequence.current) return;
      setData(payload);
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === 'AbortError') return;
      if (requestId !== requestSequence.current) return;
      setError(caught instanceof Error ? caught.message : 'Le bulletin unifié est indisponible.');
    } finally {
      if (!signal?.aborted && requestId === requestSequence.current) setLoading(false);
    }
  }, [cadence]);

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

  // Facets describe the whole window; the chips filter what is actually loaded.
  const loadedFacets = useMemo(() => data?.selectedCategories ?? [], [data]);
  const articles = useMemo(() => data?.articles ?? [], [data]);

  // Derive the effective filter instead of storing an invalid one: a stale category
  // (e.g. after switching cadence) simply falls back to "all" during render.
  const activeCategory = category !== ALL_CATEGORIES && loadedFacets.some((facet) => facet.name === category)
    ? category
    : ALL_CATEGORIES;

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return articles.filter((article) => {
      if (activeCategory !== ALL_CATEGORIES && article.category !== activeCategory) return false;
      if (!needle) return true;
      return `${article.title} ${article.excerpt} ${article.source.name} ${article.cves.join(' ')}`
        .toLowerCase()
        .includes(needle);
    });
  }, [articles, activeCategory, query]);

  const onlineSources = data?.sources.filter((source) => source.status === 'online').length ?? 0;
  const totalSources = data?.sources.length ?? 0;
  const withCve = visible.filter((article) => article.cves.length > 0).length;

  // Editorial layout: the ranking already ordered the window, so the front page is
  // a slice of it — but an illustrated story is promoted to the lead when one is
  // near the top, because a lead with no image reads as a broken page.
  const layout = useMemo(() => {
    if (!visible.length) return { lead: null, features: [] as LiveArticle[], rest: [] as LiveArticle[] };
    const leadIndex = visible.slice(0, 4).findIndex((article) => article.imageUrl);
    const lead = visible[leadIndex >= 0 ? leadIndex : 0];
    const remaining = visible.filter((article) => article.id !== lead.id);
    return { lead, features: remaining.slice(0, 4), rest: remaining.slice(4) };
  }, [visible]);

  return (
    <div className="unified">
      <div className="unified-toolbar">
        <div className="unified-cadence" role="tablist" aria-label="Fenêtre du bulletin">
          {CADENCES.map(([id, label]) => (
            <button
              type="button"
              role="tab"
              key={id}
              aria-selected={cadence === id}
              onClick={() => { setCadence(id); setCategory(ALL_CATEGORIES); }}
            >
              {label}
            </button>
          ))}
        </div>
        <label className="unified-search">
          <span className="sr-only">Filtrer le fil</span>
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Filtrer : produit, éditeur, CVE…"
            aria-label="Filtrer le fil"
          />
        </label>
        <div className="unified-stats">
          <span><strong>{visible.length}</strong> affichés</span>
          <span><strong>{withCve}</strong> avec CVE</span>
          <span><strong>{onlineSources}/{totalSources}</strong> sources</span>
        </div>
      </div>

      <nav className="unified-filters" aria-label="Filtrer par catégorie">
        <button
          type="button"
          aria-pressed={activeCategory === ALL_CATEGORIES}
          onClick={() => setCategory(ALL_CATEGORIES)}
        >
          Tout <i>{articles.length}</i>
        </button>
        {loadedFacets.map((facet) => (
          <button
            type="button"
            key={facet.name}
            aria-pressed={activeCategory === facet.name}
            onClick={() => setCategory(facet.name)}
          >
            {facet.name} <i>{facet.count}</i>
          </button>
        ))}
      </nav>

      {error ? (
        <div className="unified-message unified-error">
          <strong>Fil indisponible</strong>
          <p>{error}</p>
          <button type="button" onClick={() => void load()}>Réessayer</button>
        </div>
      ) : loading && !data ? (
        <div className="unified-message">
          <i />
          <div>
            <strong>OpenVigie agrège les sources</strong>
            <p>Le fil unifié rassemble les {totalSources || 44} flux suivis.</p>
          </div>
        </div>
      ) : !layout.lead ? (
        <div className="unified-message">
          <div>
            <strong>Aucun article pour ce filtre</strong>
            <p>Élargis la fenêtre ou retire le filtre de catégorie.</p>
          </div>
        </div>
      ) : (
        <div className="unified-front">
          <LeadStory article={layout.lead} />

          {layout.features.length > 0 ? (
            <div className="unified-features">
              {layout.features.map((article) => <FeatureCard key={article.id} article={article} />)}
            </div>
          ) : null}

          {layout.rest.length > 0 ? (
            <section className="unified-more">
              <h3 className="unified-rule">Le reste du fil <i>{layout.rest.length}</i></h3>
              <ol className="unified-feed">
                {layout.rest.map((article) => (
                  <li key={article.id} className={`unified-item${article.imageUrl ? ' has-media' : ''}`}>
                    {article.imageUrl ? <ArticleThumb src={article.imageUrl} alt="" /> : null}
                    <div className="unified-item-copy">
                      <ArticleMeta article={article} />
                      <h4><a href={article.url} target="_blank" rel="noreferrer noopener">{article.title}</a></h4>
                      {article.excerpt ? <p>{article.excerpt}</p> : null}
                      <CveList cves={article.cves} max={6} />
                    </div>
                  </li>
                ))}
              </ol>
            </section>
          ) : null}
        </div>
      )}

      <footer className="unified-footer">
        <p><strong>Sélection automatisée</strong> · pas une validation éditoriale.</p>
        <p>{data?.ranking.method}</p>
        <p>{data?.ranking.warning}</p>
      </footer>
    </div>
  );
}
