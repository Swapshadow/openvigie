import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const collectorBase = process.env.OPENVIGIE_COLLECTOR_URL?.replace(/\/$/, '');
  if (!collectorBase) {
    return NextResponse.json(
      { error: 'Le collecteur d’articles est disponible avec le lancement Docker d’OpenVigie.' },
      { status: 503 },
    );
  }

  const days = new URL(request.url).searchParams.get('days') ?? '30';
  const target = new URL('/bulletin/cert-fr', collectorBase);
  target.searchParams.set('days', days);

  try {
    const response = await fetch(target, { cache: 'no-store', signal: AbortSignal.timeout(25_000) });
    return new NextResponse(await response.arrayBuffer(), {
      status: response.status,
      headers: { 'Content-Type': response.headers.get('Content-Type') ?? 'application/json' },
    });
  } catch {
    return NextResponse.json(
      { error: 'Le collecteur prépare ou actualise encore les avis CERT-FR. Réessaie dans quelques instants.' },
      { status: 503 },
    );
  }
}
