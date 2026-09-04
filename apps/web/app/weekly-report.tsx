'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
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

const HTML_ESCAPES: Record<string, string> = {
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
};

function esc(value: string) {
  return value.replace(/[&<>"']/g, (char) => HTML_ESCAPES[char] ?? char);
}

function buildReportHtml(data: WeeklyReport): string {
  const generated = formatDate(data.generatedAt, true);
  const range = `${formatDate(data.period.start)} → ${formatDate(data.period.end)}`;
  const kpi = (label: string, value: number) =>
    `<div class="kpi"><span class="kpi-value">${value}</span><span class="kpi-label">${esc(label)}</span></div>`;
  const cveRows = data.topCve
    .map((entry) => {
      const tags = [
        entry.kev ? '<span class="tag kev">CISA KEV</span>' : '',
        entry.kevRansomware ? '<span class="tag ransom">Rançongiciel</span>' : '',
      ].join('');
      const vendor = [entry.vendor, entry.product].filter(Boolean).join(' · ');
      const links = entry.articles
        .map((article) => `<li><a href="${esc(article.url)}">${esc(article.title)}</a> <em>${esc(article.source)}</em></li>`)
        .join('');
      return `<tr><td><strong>${esc(entry.cve)}</strong>${tags}${vendor ? `<div class="muted">${esc(vendor)}</div>` : ''}</td>`
        + `<td class="num">${entry.mentions}</td><td><ul class="sources">${links}</ul></td></tr>`;
    })
    .join('');
  const newsRows = data.topNews
    .map((article) => `<li><a href="${esc(article.url)}">${esc(article.title)}</a>`
      + `<div class="muted">${esc(article.source.name)} · ${esc(formatDate(article.publishedAt))}`
      + `${article.cves.length ? ` · ${esc(article.cves.slice(0, 4).join(', '))}` : ''}</div>`
      + `${article.excerpt ? `<p>${esc(article.excerpt)}</p>` : ''}</li>`)
    .join('');
  const trendingRows = data.trending
    .map((item) => `<span class="chip">${esc(item.term)}<b>${item.count}</b></span>`)
    .join('');
  const categoryRows = data.categories
    .map((item) => `<li><span>${esc(item.name)}</span><b>${item.count}</b></li>`)
    .join('');

  return `<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>OpenVigie · Rapport hebdomadaire ${esc(range)}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #16202b; background: #fff; margin: 0; padding: 40px; max-width: 900px; margin-inline: auto; }
  h1 { font-size: 26px; margin: 0 0 4px; }
  h2 { font-size: 18px; margin: 34px 0 12px; padding-bottom: 6px; border-bottom: 2px solid #e2e8f0; }
  .head-meta { color: #64748b; font-size: 13px; margin-bottom: 8px; }
  .kpis { display: flex; flex-wrap: wrap; gap: 12px; margin: 18px 0 6px; }
  .kpi { flex: 1 1 120px; border: 1px solid #e2e8f0; border-radius: 12px; padding: 12px 14px; }
  .kpi-value { display: block; font-size: 24px; font-weight: 700; }
  .kpi-label { color: #64748b; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #edf1f6; vertical-align: top; }
  td.num, th.num { text-align: right; white-space: nowrap; }
  .tag { display: inline-block; margin-left: 6px; padding: 1px 7px; border-radius: 999px; font-size: 11px; font-weight: 700; }
  .tag.kev { background: #fee2e2; color: #b91c1c; }
  .tag.ransom { background: #fef3c7; color: #92400e; }
  .muted { color: #64748b; font-size: 12px; margin-top: 2px; }
  ul.sources { margin: 0; padding-left: 16px; }
  ul.sources em { color: #94a3b8; font-style: normal; }
  ol.news { padding-left: 18px; }
  ol.news li { margin-bottom: 12px; }
  ol.news p { margin: 4px 0 0; color: #334155; font-size: 13px; }
  .chips { display: flex; flex-wrap: wrap; gap: 8px; }
  .chip { border: 1px solid #e2e8f0; border-radius: 999px; padding: 3px 10px; font-size: 13px; }
  .chip b { margin-left: 6px; color: #2563eb; }
  ul.cats { list-style: none; padding: 0; margin: 0; }
  ul.cats li { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #edf1f6; }
  footer { margin-top: 34px; padding-top: 12px; border-top: 1px solid #e2e8f0; color: #64748b; font-size: 12px; }
  a { color: #1d4ed8; }
  @media print { body { padding: 0; } a { color: inherit; text-decoration: none; } h2 { break-after: avoid; } tr, li { break-inside: avoid; } }
</style></head><body>
<h1>OpenVigie — Rapport hebdomadaire</h1>
<div class="head-meta">Période : ${esc(range)} · Généré le ${esc(generated)}</div>
<div class="kpis">
  ${kpi('Articles', data.stats.articles)}
  ${kpi('Sources actives', data.stats.sources)}
  ${kpi('CVE citées', data.stats.cves)}
  ${kpi('Dont CISA KEV', data.stats.kev)}
  ${kpi('Catégories', data.stats.categories)}
</div>
<h2>Top CVE de la semaine</h2>
${data.topCve.length ? `<table><thead><tr><th>CVE</th><th class="num">Citations</th><th>Articles</th></tr></thead><tbody>${cveRows}</tbody></table>` : '<p class="muted">Aucune CVE citée sur la période.</p>'}
<h2>Top actualités</h2>
${data.topNews.length ? `<ol class="news">${newsRows}</ol>` : '<p class="muted">Aucune actualité sur la période.</p>'}
<h2>Mots-clés en tendance</h2>
${data.trending.length ? `<div class="chips">${trendingRows}</div>` : '<p class="muted">Pas assez de volume pour dégager une tendance.</p>'}
<h2>Répartition par catégorie</h2>
<ul class="cats">${categoryRows}</ul>
<footer>
  <p><strong>Sélection automatisée</strong> — ${esc(data.ranking.method)}</p>
  <p>${esc(data.ranking.warning)}</p>
  <p>Sources : ${esc(data.sources.join(', '))}</p>
</footer>
</body></html>`;
}

function triggerDownload(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
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

  const stamp = useMemo(() => {
    const date = data ? new Date(data.generatedAt) : new Date();
    return Number.isNaN(date.getTime()) ? 'rapport' : date.toISOString().slice(0, 10);
  }, [data]);

  const exportHtml = useCallback(() => {
    if (!data) return;
    triggerDownload(`openvigie-rapport-hebdo-${stamp}.html`, new Blob([buildReportHtml(data)], { type: 'text/html;charset=utf-8' }));
  }, [data, stamp]);

  const exportPdf = useCallback(() => {
    if (!data) return;
    const printer = window.open('', '_blank', 'noopener,noreferrer,width=920,height=1000');
    if (!printer) {
      setError('Autorise les fenêtres surgissantes pour générer le PDF, ou utilise l’export HTML puis imprime-le.');
      return;
    }
    printer.document.open();
    printer.document.write(buildReportHtml(data));
    printer.document.close();
    printer.focus();
    window.setTimeout(() => printer.print(), 400);
  }, [data]);

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
          <button type="button" onClick={exportHtml} disabled={!data}>Exporter HTML</button>
          <button type="button" onClick={exportPdf} disabled={!data}>Exporter PDF</button>
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
