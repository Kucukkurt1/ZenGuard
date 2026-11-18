"use client";

import { Sidebar } from "@/components/sidebar";
import { TopBar } from "@/components/top-bar";

export function AppShell({
  crumb,
  search,
  onSearch,
  onQuickUpload,
  uploading,
  children,
}: {
  crumb: string[];
  search?: string;
  onSearch?: (value: string) => void;
  onQuickUpload?: (file: File) => void;
  uploading?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="zg-canvas flex h-screen w-full overflow-hidden">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar
          crumb={crumb}
          search={search}
          onSearch={onSearch}
          onQuickUpload={onQuickUpload}
          uploading={uploading}
        />
        <div className="min-h-0 flex-1">{children}</div>
      </div>
    </div>
  );
}
