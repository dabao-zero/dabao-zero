export interface ImageSummary {
  name: string;
  description: string;
  upstream: string;
  bases: string[];
  latest_tag: string | null;
  updated_at: number | null;
  total: number;
  open: number;
  fixed: number;
  patched: number;
  unpatched: number;
  pending: number;
  needs_human: number;
  median_time_to_patch_s: number | null;
}

export interface Tag {
  digest: string;
  tag: string;
  stream: string;
  status: string;
  published_at: number;
  revoked_at: number | null;
  revoked_reason: string | null;
  open_cves: number;
  fixed_cves: number;
}

export interface Affected {
  id: number;
  advisory_id: string;
  stream: string;
  image: string;
  package: string;
  version: string;
  status: string;
  created_at: number;
  patched_at: number | null;
}

export interface ImageDetail extends ImageSummary {
  tags: Tag[];
  advisories: Affected[];
}

export interface Gate {
  name: string;
  passed: boolean;
  reason: string;
}

export interface Attempt {
  id: number;
  outcome: string;
  started_at: number;
  finished_at: number | null;
  tokens_in: number;
  tokens_out: number;
  cost_usd: number;
  patch_source: string | null;
  patch_upstream_ref: string | null;
  patch_diff: string | null;
  gates: Gate[] | null;
}

export interface AdvisoryDetail {
  id: string;
  aliases: string[];
  affected: (Affected & { attempts: Attempt[] })[];
}

export interface Stats {
  attempts: number;
  fixes: number;
  median_time_to_fix_s: number | null;
  median_cost_per_fix_usd: number | null;
  failed_spend_usd: number;
  total_spend_usd: number;
}

export interface Run {
  attempt_id: number;
  advisory_id: string;
  image: string;
  package: string;
  outcome: string;
  status: string;
  started_at: number;
  duration_s: number | null;
  tokens_in: number;
  tokens_out: number;
  cost_usd: number;
}

const BASE: string = import.meta.env.VITE_API_URL ?? "";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

export async function getJson<T>(path: string, fetchFn: typeof fetch = fetch): Promise<T> {
  const res = await fetchFn(`${BASE}${path}`);
  if (!res.ok) throw new ApiError(res.status, `${res.status} ${res.statusText}`.trim());
  return (await res.json()) as T;
}

const enc = encodeURIComponent;

export const api = {
  images: () => getJson<ImageSummary[]>("/v1/images"),
  image: (name: string) => getJson<ImageDetail>(`/v1/images/${enc(name)}`),
  advisory: (id: string) => getJson<AdvisoryDetail>(`/v1/advisories/${enc(id)}`),
  stats: () => getJson<Stats>("/v1/stats"),
  runs: (limit = 20) => getJson<Run[]>(`/v1/runs?limit=${limit}`),
};
