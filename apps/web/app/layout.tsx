import type { Metadata } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import './globals.css';

const geistSans = Geist({ variable: '--font-geist-sans', subsets: ['latin'] });
const geistMono = Geist_Mono({ variable: '--font-geist-mono', subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'OpenVigie — Veille cyber, vulnérabilités et bulletin stratégique',
  description: 'Plateforme open source de veille cyber : vulnérabilités contextualisées, bulletin quotidien, synthèse hebdomadaire et dossier stratégique mensuel.',
  openGraph: {
    type: 'website',
    locale: 'fr_FR',
    title: 'OpenVigie',
    description: 'La veille cyber centrée sur votre parc et les enjeux stratégiques.',
    images: [
      {
        url: 'https://raw.githubusercontent.com/Swapshadow/openvigie/main/apps/web/public/og.png',
        width: 1672,
        height: 941,
        alt: 'OpenVigie — La veille cyber centrée sur votre parc',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'OpenVigie',
    description: 'La veille cyber centrée sur votre parc et les enjeux stratégiques.',
    images: ['https://raw.githubusercontent.com/Swapshadow/openvigie/main/apps/web/public/og.png'],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="fr">
      <body className={`${geistSans.variable} ${geistMono.variable}`}>{children}</body>
    </html>
  );
}
