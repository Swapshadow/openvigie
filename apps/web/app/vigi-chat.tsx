'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { vendorCatalog } from './asset-catalog';
import type { InventoryAsset } from './vulnerability-types';
import type { Cadence } from './bulletin-data';

const INVENTORY_STORAGE_KEY = 'openvigie.inventory.v1';

type ChatRole = 'user' | 'assistant';

type ChatSource = { name: string; url: string };

type ChatMessage = {
  role: ChatRole;
  content: string;
  sources?: ChatSource[];
  usedContext?: { bulletin: boolean; cadence: Cadence | null; assets: number };
  error?: boolean;
};

type ResolvedAsset = {
  label: string;
  vendor: string;
  product: string;
  version: string;
  exposure: string;
};

const SUGGESTIONS = [
  'Quelles sont les vulnérabilités majeures du bulletin du jour ?',
  'Y a-t-il une alerte qui concerne mon parc ?',
  'Résume les menaces à surveiller cette semaine.',
];

const WELCOME =
  "Bonjour, je suis Vigi, l'assistant d'OpenVigie. Je réponds à partir du bulletin " +
  'attribué et de votre parc déclaré — je n’invente rien et je cite mes sources. ' +
  'Posez-moi une question sur les vulnérabilités ou les menaces suivies.';

function resolveInventory(): ResolvedAsset[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = window.localStorage.getItem(INVENTORY_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as InventoryAsset[];
    if (!Array.isArray(parsed)) return [];
    return parsed.slice(0, 60).map((asset) => {
      const vendor = vendorCatalog.find((entry) => entry.id === asset.vendorId);
      const product = vendor?.products.find((entry) => entry.id === asset.productId);
      return {
        label: (asset.label ?? '').slice(0, 80),
        vendor: vendor?.name ?? asset.vendorId ?? '',
        product: product?.name ?? asset.productId ?? '',
        version: (asset.version ?? '').slice(0, 80),
        exposure: (asset.exposure ?? '').slice(0, 80),
      };
    });
  } catch {
    return [];
  }
}

export default function VigiChat({ cadence = 'daily' as Cadence }: { cadence?: Cadence }) {
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [draft, setDraft] = useState('');
  const [messages, setMessages] = useState<ChatMessage[]>([{ role: 'assistant', content: WELCOME }]);
  const threadRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (open && threadRef.current) {
      threadRef.current.scrollTop = threadRef.current.scrollHeight;
    }
  }, [messages, open, pending]);

  useEffect(() => () => abortRef.current?.abort(), []);

  const assetCount = useMemo(() => (open ? resolveInventory().length : 0), [open]);

  const send = useCallback(
    async (text: string) => {
      const question = text.trim();
      if (!question || pending) return;

      const assets = resolveInventory();
      const history = [...messages, { role: 'user' as ChatRole, content: question }];
      setMessages(history);
      setDraft('');
      setPending(true);

      const controller = new AbortController();
      abortRef.current = controller;

      try {
        const response = await fetch('/api/ai/chat', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          cache: 'no-store',
          signal: controller.signal,
          body: JSON.stringify({
            cadence,
            assets,
            messages: history
              .filter((entry) => entry.role === 'user' || entry.role === 'assistant')
              .slice(-12)
              .map((entry) => ({ role: entry.role, content: entry.content })),
          }),
        });
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload?.error ?? `Erreur ${response.status}`);
        }
        setMessages((current) => [
          ...current,
          {
            role: 'assistant',
            content: String(payload.reply ?? '').trim() || 'Vigi n’a pas renvoyé de réponse.',
            sources: Array.isArray(payload.sources) ? payload.sources.slice(0, 8) : [],
            usedContext: payload.usedContext,
          },
        ]);
      } catch (error) {
        if (controller.signal.aborted) return;
        const detail = error instanceof Error ? error.message : 'Service indisponible.';
        setMessages((current) => [
          ...current,
          {
            role: 'assistant',
            error: true,
            content:
              `Vigi est indisponible (${detail}). L’inférence locale peut être lente au ` +
              'premier appel : réessayez dans quelques instants.',
          },
        ]);
      } finally {
        setPending(false);
        abortRef.current = null;
      }
    },
    [cadence, messages, pending],
  );

  return (
    <>
      <button
        type="button"
        className="vigi-fab"
        aria-expanded={open}
        aria-label={open ? 'Fermer Vigi' : 'Ouvrir Vigi, l’assistant OpenVigie'}
        onClick={() => setOpen((value) => !value)}
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          {open ? (
            <path d="m6 6 12 12M18 6 6 18" />
          ) : (
            <>
              <circle cx="12" cy="12" r="8" />
              <circle cx="12" cy="12" r="3.4" />
              <path d="M12 12 18.4 5.6" />
            </>
          )}
        </svg>
        <span>Vigi</span>
      </button>

      {open ? (
        <section className="vigi-panel glass-panel" aria-label="Vigi, assistant IA local d’OpenVigie">
          <header className="vigi-head">
            <div>
              <strong>Vigi</strong>
              <span>Assistant IA local · bulletin + parc</span>
            </div>
            <p className="vigi-scope">
              {assetCount > 0
                ? `${assetCount} équipement${assetCount > 1 ? 's' : ''} du parc pris en compte`
                : 'Aucun équipement déclaré dans « Mon parc »'}
            </p>
          </header>

          <div className="vigi-thread" ref={threadRef}>
            {messages.map((message, index) => (
              <article
                key={index}
                className={`vigi-msg vigi-msg-${message.role}${message.error ? ' vigi-msg-error' : ''}`}
              >
                <p>{message.content}</p>
                {message.usedContext?.bulletin ? (
                  <span className="vigi-context">Fondé sur le bulletin {message.usedContext.cadence}</span>
                ) : null}
                {message.sources && message.sources.length > 0 ? (
                  <ul className="vigi-sources">
                    {message.sources.map((source, position) => (
                      <li key={`${source.url}-${position}`}>
                        <a href={source.url} target="_blank" rel="noreferrer noopener">
                          {source.name}
                        </a>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </article>
            ))}
            {pending ? (
              <article className="vigi-msg vigi-msg-assistant vigi-msg-pending">
                <p>Vigi consulte le bulletin et rédige une réponse locale…</p>
              </article>
            ) : null}
          </div>

          {messages.length <= 1 ? (
            <div className="vigi-suggestions">
              {SUGGESTIONS.map((suggestion) => (
                <button type="button" key={suggestion} onClick={() => send(suggestion)} disabled={pending}>
                  {suggestion}
                </button>
              ))}
            </div>
          ) : null}

          <form
            className="vigi-input"
            onSubmit={(event) => {
              event.preventDefault();
              send(draft);
            }}
          >
            <textarea
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && !event.shiftKey) {
                  event.preventDefault();
                  send(draft);
                }
              }}
              placeholder="Demandez à Vigi les vulnérabilités du bulletin, une alerte parc…"
              rows={2}
              disabled={pending}
              aria-label="Message pour Vigi"
            />
            <button type="submit" disabled={pending || !draft.trim()}>
              {pending ? '…' : 'Envoyer'}
            </button>
          </form>
        </section>
      ) : null}
    </>
  );
}
