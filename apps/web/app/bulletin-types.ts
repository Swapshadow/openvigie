import type { Cadence } from './bulletin-data';

export type LiveArticle = {
  id: string;
  title: string;
  url: string;
  excerpt: string;
  author: string | null;
  publishedAt: string | null;
  fetchedAt: string | null;
  category: string;
  cves: string[];
  score: number;
  source: {
    id: string;
    name: string;
    homepage: string;
    kind: string;
    license: string;
  };
};

export type FeedStatus = {
  id: string;
  name: string;
  homepage: string;
  kind: string;
  status: 'pending' | 'online' | 'degraded';
  lastSuccess: string | null;
  nextRefresh: string | null;
  error: string | null;
};

export type LiveBulletinResponse = {
  cadence: Cadence;
  generatedAt: string;
  period: { label: string; start: string; end: string };
  archiveFallback: boolean;
  articles: LiveArticle[];
  categories: Array<{ name: string; count: number }>;
  sources: FeedStatus[];
  ranking: { method: string; warning: string };
};
