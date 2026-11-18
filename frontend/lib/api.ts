export type ServiceState = "ok" | "down" | "unknown";

export type HealthResponse = {
  api: ServiceState | string;
  db: ServiceState | string;
  redis: ServiceState | string;
  clamav: ServiceState | string;
};

export type AnalysisStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "rejected"
  | string;

export type RiskBand = "clean" | "low" | "medium" | "high" | "critical" | string;

export type AnalysisSummary = {
  id: string;
  created_at: string;
  updated_at: string;
  original_filename: string;
  sha256: string;
  size_bytes: number;
  mime_type: string;
  status: AnalysisStatus;
  risk_score: number | null;
  risk_band: RiskBand | null;
  coverage: string | null;
  progress_percent?: number | null;
  progress_stage?: string | null;
};

export type FindingReason = {
  code?: string;
  points?: number;
  member_path?: string;
  evidence?: Record<string, unknown>;
  rule?: string;
  severity?: string;
};

export type ScoreComponent = {
  awarded: number;
  max: number;
  reasons: FindingReason[];
};

export type AnalysisReport = {
  report_version?: number;
  coverage?: string;
  members?: Array<{
    path: string;
    sha256: string;
    size_bytes: number;
    depth: number;
    mime_type: string;
  }>;
  engines?: {
    clamav?: { status?: string; signature?: string | null };
    yara?: { status?: string; matches?: unknown[] };
    static?: { status?: string; signals?: unknown[] };
    archive?: { status?: string; signals?: unknown[] };
  };
  score?: {
    mode: string;
    value: number;
    band: string;
    raw_sum: number;
    clipped: number;
    evidence_sum?: number;
    floor?: number | null;
    components?: {
      clamav?: ScoreComponent;
      yara?: ScoreComponent;
      static?: ScoreComponent;
      archive?: ScoreComponent;
    };
  };
};

export type AnalysisDetail = AnalysisSummary & {
  started_at: string | null;
  finished_at: string | null;
  storage_path: string;
  ruleset_version: string | null;
  engine_versions: Record<string, unknown> | null;
  task_id: string | null;
  error_code: string | null;
  error_message: string | null;
  report: AnalysisReport | null;
};

export type AnalysisList = {
  items: AnalysisSummary[];
  limit: number;
  offset: number;
  total: number;
};

export type AnalysisUpload = {
  id: string;
  sha256: string;
  status: AnalysisStatus;
  original_filename: string;
  size_bytes: number;
};

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "") ||
  "http://127.0.0.1:8000/api/v1";

export function apiBase(): string {
  return API_BASE;
}

async function errorMessage(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: unknown };
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail)) {
      const text = body.detail
        .map((item) => {
          if (item && typeof item === "object" && "msg" in item) {
            return String((item as { msg: unknown }).msg);
          }
          return "";
        })
        .filter(Boolean)
        .join(" ");
      if (text) return text;
    }
  } catch {
    /* gövde JSON değil */
  }
  return `İstek tamamlanamadı (${response.status})`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: init?.body instanceof FormData ? init.headers : {
        Accept: "application/json",
        ...init?.headers,
      },
    });
  } catch {
    throw new ApiError(0, "API'ye ulaşılamadı. Backend'in 127.0.0.1:8000 üzerinde açık olduğunu kontrol edin.");
  }

  if (!response.ok) {
    const message = await errorMessage(response);
    if (response.status === 413) {
      throw new ApiError(413, "Dosya 50 MiB yükleme sınırını aşıyor.");
    }
    if (response.status === 404) {
      throw new ApiError(404, "Analiz kaydı bulunamadı.");
    }
    throw new ApiError(response.status, message);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/health");
}

export function listAnalyses(params?: {
  limit?: number;
  offset?: number;
  sha256?: string;
  status?: string;
}): Promise<AnalysisList> {
  const query = new URLSearchParams();
  query.set("limit", String(params?.limit ?? 20));
  query.set("offset", String(params?.offset ?? 0));
  if (params?.sha256) query.set("sha256", params.sha256);
  if (params?.status) query.set("status", params.status);
  return request<AnalysisList>(`/analyses?${query.toString()}`);
}

export function getAnalysis(id: string): Promise<AnalysisDetail> {
  return request<AnalysisDetail>(`/analyses/${id}`);
}

export function startAnalysis(id: string): Promise<AnalysisUpload> {
  return request<AnalysisUpload>(`/analyses/${id}/run`, { method: "POST" });
}

export function deleteAnalysis(id: string): Promise<void> {
  return request<void>(`/analyses/${id}`, { method: "DELETE" });
}

export function uploadAnalysis(file: File, rescan: boolean): Promise<AnalysisUpload> {
  const body = new FormData();
  body.append("file", file);
  const query = rescan ? "?rescan=true" : "";
  return request<AnalysisUpload>(`/analyses${query}`, {
    method: "POST",
    body,
  });
}
