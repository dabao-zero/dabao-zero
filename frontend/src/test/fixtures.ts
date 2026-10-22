import type { AdvisoryDetail, ImageDetail, ImageSummary, Run, Stats } from "../lib/api";

export const summary = (over: Partial<ImageSummary> = {}): ImageSummary => ({
  name: "nginx",
  description: "HTTP server and reverse proxy.",
  upstream: "nginx",
  bases: ["debian"],
  latest_tag: "1.22.0-1-dabao1",
  updated_at: 1_700_000_000,
  total: 3,
  open: 1,
  fixed: 2,
  patched: 2,
  unpatched: 1,
  pending: 0,
  needs_human: 0,
  median_time_to_patch_s: 3600,
  ...over,
});

export const images: ImageSummary[] = [
  summary(),
  summary({ name: "python", description: "Python runtime.", bases: ["alpine", "debian"], open: 0, latest_tag: "3.12.4-dabao2" }),
  summary({ name: "redis", description: "In-memory data store.", bases: ["alpine"], open: 2 }),
];

export const detail: ImageDetail = {
  ...summary(),
  tags: [
    { digest: "sha256:" + "a".repeat(64), tag: "1.22.0-1-dabao2", stream: "debian", status: "PUBLISHED", published_at: 1_700_000_000, revoked_at: null, revoked_reason: null, open_cves: 1, fixed_cves: 2 },
    { digest: "sha256:" + "b".repeat(64), tag: "1.22.0-1-dabao1", stream: "debian", status: "REVOKED", published_at: 1_690_000_000, revoked_at: 1_695_000_000, revoked_reason: "bad build", open_cves: 2, fixed_cves: 1 },
  ],
  advisories: [
    { id: 1, advisory_id: "DEMO-1", stream: "debian", image: "nginx", package: "libssl3", version: "3.0.1", status: "PATCHED", created_at: 1_699_000_000, patched_at: 1_699_003_600 },
    { id: 2, advisory_id: "DEMO-2", stream: "debian", image: "nginx", package: "zlib1g", version: "1.2", status: "UNPATCHED", created_at: 1_699_000_000, patched_at: null },
  ],
};

export const advisory: AdvisoryDetail = {
  id: "DEMO-1",
  aliases: [],
  affected: [
    {
      ...detail.advisories[0],
      attempts: [
        {
          id: 7, runner: "agent", outcome: "SUCCEEDED", started_at: 1_699_000_100, finished_at: 1_699_003_600,
          tokens_in: 1000, tokens_out: 200, cost_usd: 0.12, patch_source: "upstream",
          patch_upstream_ref: "abc123",
          patch_diff: "--- a/x.c\n+++ b/x.c\n@@ -1 +1 @@\n-old\n+new\n",
          gates: [
            { name: "scanners_clear", passed: true, reason: "clear" },
            { name: "tests_pass", passed: false, reason: "1 failed" },
          ],
        },
      ],
    },
  ],
};

export const stats: Stats = {
  attempts: 10, fixes: 7, median_time_to_fix_s: 5400, median_cost_per_fix_usd: 0.31,
  failed_spend_usd: 0.9, total_spend_usd: 3.1,
};

export const runs: Run[] = [
  { attempt_id: 1, runner: "agent", advisory_id: "DEMO-1", image: "nginx", package: "libssl3", outcome: "SUCCEEDED", status: "PATCHED", started_at: 1_699_000_100, duration_s: 120, tokens_in: 1, tokens_out: 1, cost_usd: 0.12 },
];
