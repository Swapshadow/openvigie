import { NextResponse } from 'next/server';

const TIMEOUT = 12_000;

function collectorBase() {
  return process.env.OPENVIGIE_COLLECTOR_URL?.replace(/\/$/, '') ?? '';
}

function unavailable() {
  return NextResponse.json(
    { error: 'Le collecteur d’alertes est disponible avec le lancement Docker d’OpenVigie.' },
    { status: 503 },
  );
}

async function passThrough(response: Response) {
  return new NextResponse(await response.arrayBuffer(), {
    status: response.status,
    headers: { 'Content-Type': response.headers.get('Content-Type') ?? 'application/json' },
  });
}

export async function GET() {
  const base = collectorBase();
  if (!base) return unavailable();
  try {
    const response = await fetch(`${base}/watch-plan/alerts`, {
      cache: 'no-store',
      signal: AbortSignal.timeout(TIMEOUT),
    });
    return await passThrough(response);
  } catch {
    return unavailable();
  }
}

export async function POST(request: Request) {
  const base = collectorBase();
  if (!base) return unavailable();
  try {
    const body = await request.json() as Record<string, unknown>;
    // One route, two collector endpoints: an `action` field means a state change.
    const isAction = typeof body.action === 'string' && body.action.length > 0;
    const target = isAction ? `${base}/watch-plan/alert/action` : `${base}/watch-plan/alert`;
    const response = await fetch(target, {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT),
    });
    return await passThrough(response);
  } catch {
    return unavailable();
  }
}

export async function DELETE(request: Request) {
  const base = collectorBase();
  if (!base) return unavailable();
  const id = new URL(request.url).searchParams.get('id')?.slice(0, 40) ?? '';
  if (!id) return NextResponse.json({ error: 'id est requis.' }, { status: 400 });
  try {
    const response = await fetch(`${base}/watch-plan/alert?id=${encodeURIComponent(id)}`, {
      method: 'DELETE',
      cache: 'no-store',
      signal: AbortSignal.timeout(TIMEOUT),
    });
    return await passThrough(response);
  } catch {
    return unavailable();
  }
}
