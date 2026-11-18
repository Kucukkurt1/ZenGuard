import { BrandMark } from "@/components/brand-mark";
import { HealthPills } from "@/components/health-pills";

export function SiteHeader() {
  return (
    <div className="flex flex-col gap-4 py-5 lg:flex-row lg:items-center lg:justify-between">
      <BrandMark />
      <HealthPills />
    </div>
  );
}
