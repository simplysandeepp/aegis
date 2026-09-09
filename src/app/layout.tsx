import type { Metadata } from 'next';
import Link from 'next/link';
import './globals.css';

export const metadata: Metadata = {
  title: 'Aegis — LLM guardrail gateway',
  description: 'Guardrail gateway and red-team evaluation harness for LLM applications',
};

const NAV = [
  { href: '/', label: 'Overview' },
  { href: '/traffic', label: 'Traffic' },
  { href: '/playground', label: 'Playground' },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen bg-background text-foreground antialiased">
        <header className="border-b border-border">
          <div className="mx-auto flex max-w-7xl items-center gap-6 px-6 py-3">
            <Link href="/" className="font-semibold tracking-tight">
              Aegis
            </Link>
            <nav className="flex gap-4 text-sm text-muted-foreground">
              {NAV.map((n) => (
                <Link key={n.href} href={n.href} className="transition-colors hover:text-foreground">
                  {n.label}
                </Link>
              ))}
            </nav>
            <span className="ml-auto text-xs text-muted-foreground">
              guardrail gateway + red-team harness
            </span>
          </div>
        </header>
        <main className="mx-auto max-w-7xl px-6 py-8">{children}</main>
      </body>
    </html>
  );
}
