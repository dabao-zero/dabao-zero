export interface ImageSummary {
  name: string;
  total: number;
  patched: number;
  unpatched: number;
  pending: number;
  median_time_to_patch_s: number | null;
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
}

export interface AdvisoryDetail {
  id: string;
  aliases: string[];
  affected: (Affected & { attempts: Attempt[] })[];
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
  if (!res.ok) throw new ApiError(res.status, `${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

export const api = {
  images: () => getJson<ImageSummary[]>("/v1/images"),
  image: (name: string) => getJson<Affected[]>(`/v1/images/${encodeURIComponent(name)}`),
  advisory: (id: string) => getJson<AdvisoryDetail>(`/v1/advisories/${encodeURIComponent(id)}`),
};
