import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const collectorBase = process.env.OPENVIGIE_COLLECTOR_URL?.replace(/\/$/, '');
  if (!collectorBase) return NextResponse.json({ error: 'La recherche est disponible avec Docker.' }, { status: 503 });
  const incoming = new URL(request.url);
  const q = incoming.searchParams.get('q')?.trim() ?? '';
  if (q.length < 2) return NextResponse.json({ error: 'Saisis au moins deux caractères.' }, { status: 400 });
  const target = new URL('/search', collectorBase);
  for (const key of ['q', 'days', 'source', 'limit']) {
    const value = incoming.searchParams.get(key);
    if (value) target.searchParams.set(key, value.slice(0, 240));
  }
  try {
    const response = await fetch(target, { cache: 'no-store', signal: AbortSignal.timeout(15_000) });
    return new NextResponse(await response.arrayBuffer(), { status: response.status, headers: { 'Content-Type': 'application/json' } });
  } catch {
    return NextResponse.json({ error: 'Le moteur de recherche est momentanément indisponible.' }, { status: 503 });
  }
}
