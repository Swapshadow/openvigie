import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const collectorBase = process.env.OPENVIGIE_COLLECTOR_URL?.replace(/\/$/, '');
  if (!collectorBase) return NextResponse.json({ error: 'La veille des fuites est disponible avec Docker.' }, { status: 503 });
  const incoming = new URL(request.url);
  const requestedDays = incoming.searchParams.get('days') ?? 'all';
  const days = requestedDays === 'all' ? '0' : requestedDays;
  const target = new URL('/leaks', collectorBase);
  target.searchParams.set('days', days.slice(0, 4));
  try {
    const response = await fetch(target, { cache: 'no-store', signal: AbortSignal.timeout(15_000) });
    return new NextResponse(await response.arrayBuffer(), {
      status: response.status,
      headers: { 'Content-Type': response.headers.get('Content-Type') ?? 'application/json' },
    });
  } catch {
    return NextResponse.json({ error: 'La veille des fuites est momentanément indisponible.' }, { status: 503 });
  }
}
