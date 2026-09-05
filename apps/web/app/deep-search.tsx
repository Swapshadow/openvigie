'use client';

import { FormEvent, useState } from 'react';

type Result = { id: string; title: string; url: string; excerpt: string; publishedAt: string; category: string; cves: string[]; matchedTerms: string[]; source: { id: string; name: string; homepage: string; kind: string } };
type Payload = { query: string; generatedAt: string; results: Result[]; total: number; method: string; webSearch?: { active: boolean; provider: string; error?: string | null }; error?: string };

const EXAMPLES = ['MSS Palantir espion', 'Pegasus iPhone', 'GrapheneOS restriction Pixel 11', 'attaque supply chain VPN'];

function date(value: string) {
  return new Intl.DateTimeFormat('fr-FR', { dateStyle: 'medium' }).format(new Date(value));
}

export default function DeepSearch() {
  const [query, setQuery] = useState('');
  const [days, setDays] = useState('365');
  const [data, setData] = useState<Payload | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function search(nextQuery = query) {
    const cleaned = nextQuery.trim();
    if (cleaned.length < 2) return setError('Saisis au moins deux caractères.');
    setQuery(cleaned); setLoading(true); setError('');
    try {
      const response = await fetch(`/api/search?${new URLSearchParams({ q: cleaned, days, limit: '40' })}`, { cache: 'no-store' });
      const payload = await response.json() as Payload;
      if (!response.ok) throw new Error(payload.error ?? 'Recherche indisponible.');
      setData(payload);
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Recherche indisponible.'); }
    finally { setLoading(false); }
  }

  return <div className="deep-search">
    <header className="search-hero">
      <p className="eyebrow neon">Exploration multi-sources</p>
      <h2>Recherche approfondie</h2>
      <p>Retrouve un sujet, une entreprise, une menace ou un produit dans les archives des meilleures sources cyber suivies par OpenVigie.</p>
      <form onSubmit={(event: FormEvent) => { event.preventDefault(); void search(); }} className="search-console">
        <label><span>Requête libre</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Ex. Pegasus iPhone" autoFocus /></label>
        <label><span>Période</span><select value={days} onChange={(event) => setDays(event.target.value)}><option value="30">30 jours</option><option value="90">3 mois</option><option value="365">1 an</option><option value="1095">3 ans</option><option value="3650">Toutes les archives</option></select></label>
        <button type="submit" disabled={loading}>{loading ? 'Analyse…' : 'Lancer la recherche ↗'}</button>
      </form>
      <div className="search-examples"><span>Essayer :</span>{EXAMPLES.map((example) => <button type="button" onClick={() => void search(example)} key={example}>{example}</button>)}</div>
    </header>

    {error ? <div className="search-state glass-panel"><b>△</b><p>{error}</p></div> : null}
    {!data && !error ? <div className="search-intro glass-panel"><div><strong>33 sources cyber sélectionnées</strong><span>CERT-FR, CISA, éditeurs, chercheurs, presse spécialisée et défense des libertés numériques.</span></div><div><strong>Résultats traçables</strong><span>Chaque résultat renvoie vers la publication originale. Aucun fait n’est inventé ou réécrit.</span></div><div><strong>Actualisation continue</strong><span>Les flux sont collectés automatiquement et deviennent immédiatement recherchables.</span></div></div> : null}
    {data ? <section className="search-results glass-panel">
      <header><div><p>Résultats pour</p><h2>« {data.query} »</h2></div><strong>{data.total} résultat{data.total > 1 ? 's' : ''}</strong></header>
      {data.webSearch && !data.webSearch.active ? <p className="web-search-warning">La recherche web est temporairement indisponible : les archives OpenVigie restent consultées.</p> : null}
      {!data.results.length ? <div className="search-empty"><b>⌁</b><h3>Aucun résultat dans la période choisie</h3><p>Essaie une période plus longue, moins de mots, un nom de produit ou une CVE.</p></div> : <div className="result-list">{data.results.map((item, index) => <article key={item.id}>
        <span className="result-number">{String(index + 1).padStart(2, '0')}</span><div className="result-copy"><div className="result-meta"><span>{item.category}</span><strong>{item.source.name}</strong><time>{date(item.publishedAt)}</time></div><h3><a href={item.url} target="_blank" rel="noreferrer">{item.title}</a></h3>{item.excerpt ? <p>{item.excerpt}</p> : null}<footer>{item.matchedTerms.map((term) => <i key={term}>{term}</i>)}{item.cves.slice(0, 3).map((cve) => <i className="cve" key={cve}>{cve}</i>)}<a href={item.url} target="_blank" rel="noreferrer">Lire la source originale ↗</a></footer></div>
      </article>)}</div>}
      <footer className="search-method">{data.method} {data.webSearch?.active ? `Recherche web fournie par ${data.webSearch.provider}. ` : ''}La présence dans les résultats ne constitue pas une validation éditoriale.</footer>
    </section> : null}
  </div>;
}
