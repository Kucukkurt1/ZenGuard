import { AnalysisDetailView } from "@/components/analysis-detail";

export default async function AnalysisRoute({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <AnalysisDetailView id={id} />;
}
