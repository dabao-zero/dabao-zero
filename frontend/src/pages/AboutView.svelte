<script lang="ts">
  import type { Run, Stats } from "../lib/api";
  import { fixHref, formatDateTime, formatDuration, formatUsd, formatCount } from "../lib/format";
  import { REPO_URL } from "../lib/config";
  import OpenBox from "../components/OpenBox.svelte";

  let { stats, runs }: { stats: Stats; runs: Run[] } = $props();

  const steps = [
    ["An advisory lands", "We read public feeds (OSV, the Debian tracker) and note which images are affected."],
    ["An agent looks upstream", "It finds the fix the upstream project already shipped. It does not invent patches."],
    ["The agent proposes", "It backports the upstream change into a patch and builds the image."],
    ["Machines check", "Five deterministic gates decide. The agent has no say in the verdict."],
    ["The image is signed", "Only an image that passed every gate can be signed."],
    ["It is published", "The new tag appears here, with a receipt you can read."],
  ];
  const checks = [
    ["Advisory was open before", "The CVE was really present in the previous image."],
    ["Scanners are clear", "The scanners no longer report the CVE."],
    ["Tests pass", "The image's own test suite still passes."],
    ["Build diff is small", "Only the files the patch should touch changed."],
    ["Provenance holds", "The patch comes from a fetched upstream ref, nothing else."],
  ];
  const cannot = [
    "Mark its own work as passing.",
    "Sign or publish an image.",
    "Use a patch that did not come from upstream.",
    "Spend past the per-fix or monthly cost cap.",
  ];
</script>

<div class="page-narrow">
  <div style="display: flex; gap: 24px; align-items: center; flex-wrap: wrap; margin-top: 32px;">
    <div style="flex: 1 1 320px;">
      <h1 class="ts-headline-large" style="margin: 0;">How a fix gets packed</h1>
      <p class="ts-body-large muted" style="margin: 12px 0 0;">
        {`dabao-zero`} images are patched by LLM agents with no human in the patch path. Humans only handle incidents.
      </p>
    </div>
    <OpenBox steam label="An open takeaway box" maxWidth={200} />
  </div>

  <h2 class="ts-title-large" style="margin: 32px 0 12px;">The six steps</h2>
  <ol style="margin: 0; padding-left: 24px; display: flex; flex-direction: column; gap: 12px;">
    {#each steps as [title, body]}
      <li><strong>{title}.</strong> <span class="muted">{body}</span></li>
    {/each}
  </ol>

  <h2 class="ts-title-large" style="margin: 32px 0 12px;">The five checks</h2>
  <ul style="margin: 0; padding-left: 24px; display: flex; flex-direction: column; gap: 8px;">
    {#each checks as [title, body]}
      <li><strong>{title}.</strong> <span class="muted">{body}</span></li>
    {/each}
  </ul>

  <h2 class="ts-title-large" style="margin: 32px 0 12px;">What the agent cannot do</h2>
  <ul style="margin: 0; padding-left: 24px; display: flex; flex-direction: column; gap: 8px;">
    {#each cannot as item}<li>{item}</li>{/each}
  </ul>

  <h2 class="ts-title-large" style="margin: 32px 0 12px;">By the numbers</h2>
  <div class="table-scroll">
    <table class="dtable" style="min-width: 0;" aria-label="Fix statistics">
      <tbody>
        <tr><th scope="row">Attempts</th><td class="num">{formatCount(stats.attempts)}</td></tr>
        <tr><th scope="row">Fixes shipped</th><td class="num">{formatCount(stats.fixes)}</td></tr>
        <tr><th scope="row">Median time to fix</th><td class="num">{formatDuration(stats.median_time_to_fix_s)}</td></tr>
        <tr><th scope="row">Median cost per fix</th><td class="num">{formatUsd(stats.median_cost_per_fix_usd)}</td></tr>
        <tr><th scope="row">Spend on failed attempts</th><td class="num">{formatUsd(stats.failed_spend_usd)}</td></tr>
        <tr><th scope="row">Total spend</th><td class="num">{formatUsd(stats.total_spend_usd)}</td></tr>
      </tbody>
    </table>
  </div>

  <h2 class="ts-title-large" style="margin: 32px 0 12px;">Recent runs</h2>
  {#if runs.length === 0}
    <p class="muted">No runs yet.</p>
  {:else}
    <div class="table-scroll">
      <table class="dtable" aria-label="Recent runs">
        <thead>
          <tr><th>Advisory</th><th>Image</th><th>Package</th><th>Outcome</th><th>Started</th><th>Took</th><th>Cost</th></tr>
        </thead>
        <tbody>
          {#each runs as r (r.attempt_id)}
            <tr>
              <td><a class="link" href={fixHref(r.advisory_id)}>{r.advisory_id}</a></td>
              <td>{r.image}</td>
              <td class="mono">{r.package}</td>
              <td>{r.outcome}</td>
              <td>{formatDateTime(r.started_at)}</td>
              <td class="num">{formatDuration(r.duration_s)}</td>
              <td class="num">{formatUsd(r.cost_usd)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  <section class="card-filled" style="margin-top: 32px; padding: 20px;">
    <h2 class="ts-title-large" style="margin: 0;">Free, as is</h2>
    <p style="margin: 8px 0 0;">
      This is a free, open source project. There is no warranty and no SLA; use it at your own risk.
      Source and issues live on <a class="link" href={REPO_URL}>GitHub</a>.
    </p>
  </section>
</div>
