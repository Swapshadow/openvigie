import { NextResponse } from 'next/server';

const ALLOWED_CADENCES = new Set(['daily', 'weekly', 'monthly']);

export async function GET(request: Request) {
  const collectorBase = process.env.OPENVIGIE_COLLECTOR_URL?.replace(/\/$/, '');
  if (!collectorBase) {
    return NextResponse.json(
      { error: 'Le collecteur d’articles est disponible avec le lancement Docker d’OpenVigie.' },
      { status: 503 },
    );
  }

  const incoming = new URL(request.url);
  const cadence = incoming.searchParams.get('cadence') ?? 'daily';
  const limit = incoming.searchParams.get('limit') ?? '18';
  const category = incoming.searchParams.get('category')?.trim();
  if (!ALLOWED_CADENCES.has(cadence)) {
    return NextResponse.json({ error: 'Période de bulletin invalide.' }, { status: 400 });
  }

  const target = new URL('/articles', collectorBase);
  target.searchParams.set('cadence', cadence);
  target.searchParams.set('limit', limit);
  if (category) target.searchParams.set('category', category.slice(0, 80));

  try {
    const response = await fetch(target, {
      cache: 'no-store',
      signal: AbortSignal.timeout(15_000),
    });
    return new NextResponse(await response.arrayBuffer(), {
      status: response.status,
      headers: { 'Content-Type': response.headers.get('Content-Type') ?? 'application/json' },
    });
  } catch {
    return NextResponse.json(
      { error: 'Le collecteur prépare ou actualise encore les sources. Réessaie dans quelques instants.' },
      { status: 503 },
    );
  }
}
