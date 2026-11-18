"use client";

import { AppShell } from "@/components/app-shell";

export function BlankPage({ title, names = [] }: { title: string; names?: string[] }) {
  return (
    <AppShell crumb={[title]}>
      <div className="h-full overflow-auto px-4 py-4">
        <h1 className="zg-title mb-4 text-lg font-semibold">{title}</h1>
        {names.length > 0 ? (
          <ul className="zg-panel max-w-md divide-y divide-emerald-900/15 overflow-hidden rounded-lg border">
            {names.map((name) => (
              <li key={name} className="zg-title px-4 py-3 text-sm">
                {name}
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    </AppShell>
  );
}
