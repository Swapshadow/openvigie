import { NextRequest, NextResponse } from 'next/server';

const collectorUrl = process.env.OPENVIGIE_COLLECTOR_URL ?? 'http://collector:8787';

export async function GET(request: NextRequest) {
  const target = new URL('/ai/news-brief', collectorUrl);
  request.nextUrl.searchParams.forEach((value, key) => target.searchParams.set(key, value));

  try {
    const response = await fetch(target, { cache: 'no-store', signal: AbortSignal.timeout(190_000) });
    const payload = await response.json();
    return NextResponse.json(payload, { status: response.status });
  } catch {
    return NextResponse.json({ error: 'Le service local de synthèse IA est indisponible.' }, { status: 503 });
  }
}

export async function POST(request: NextRequest) {
  const target = new URL('/ai/triage', collectorUrl);
  try {
    const body = await request.text();
    const response = await fetch(target, {
      method: 'POST', body, cache: 'no-store',
      headers: { 'content-type': 'application/json' },
      signal: AbortSignal.timeout(310_000),
    });
    const payload = await response.json();
    return NextResponse.json(payload, { status: response.status });
  } catch {
    return NextResponse.json({ error: 'Le service local de tri IA est indisponible.' }, { status: 503 });
  }
}
