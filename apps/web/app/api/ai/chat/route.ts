import { NextRequest, NextResponse } from 'next/server';

const collectorUrl = process.env.OPENVIGIE_COLLECTOR_URL ?? 'http://collector:8787';

export async function POST(request: NextRequest) {
  const target = new URL('/ai/chat', collectorUrl);

  try {
    const body = await request.text();
    const response = await fetch(target, {
      method: 'POST',
      body,
      cache: 'no-store',
      headers: { 'content-type': 'application/json' },
      signal: AbortSignal.timeout(250_000),
    });
    const payload = await response.json();
    return NextResponse.json(payload, { status: response.status });
  } catch {
    return NextResponse.json(
      { error: 'Vigi, l’assistant IA local, est indisponible pour le moment.' },
      { status: 503 },
    );
  }
}
