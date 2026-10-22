<script lang="ts">
  import type { AdvisoryDetail } from "../lib/api";
  import { GATE_LABELS, parseDiff } from "../lib/diff";
  import { agentRunSummary, fixHref, imageHref } from "../lib/format";
  import Icon from "../components/Icon.svelte";
  import Receipt from "../components/Receipt.svelte";
  import StatusPill from "../components/StatusPill.svelte";

  let { advisory, rowId }: { advisory: AdvisoryDetail; rowId: number | null } = $props();

  const row = $derived(advisory.affected.find((r) => r.id === rowId) ?? advisory.affected[0] ?? null);
  const attempt = $derived(row && row.attempts.length > 0 ? row.attempts[row.attempts.length - 1] : null);
  const runSummary = $derived(attempt ? agentRunSummary(attempt) : null);
  const diff = $derived(attempt?.patch_diff ? parseDiff(attempt.patch_diff) : null);
  const others = $derived(advisory.affected.filter((r) => r !== row));
  const fixed = $derived(row?.status === "PATCHED");
  const intro = $derived(
    !row
      ? ""
      : fixed
        ? `A flaw in ${row.package} ${row.version} on ${row.stream}. The fix was taken from upstream and backported.`
        : `A flaw in ${row.package} ${row.version} on ${row.stream}. There is no published fix yet.`,
  );
</script>

{#if !row}
  <h1 class="ts-headline-large" style="margin-top: 32px;">{advisory.id}</h1>
  <p class="ts-body-large muted" style="margin-top: 8px;">No image is affected by this advisory.</p>
{:else}
  <nav aria-label="Breadcrumb" class="ts-body-medium muted" style="display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-top: 8px;">
    <a class="link" href="#/images">Images</a><span aria-hidden="true">/</span>
    <a class="link" href={imageHref(row.image)}>{row.image}</a><span aria-hidden="true">/</span>
    <span aria-current="page">{advisory.id}</span>
  </nav>

  <div style="display: flex; flex-wrap: wrap; align-items: center; gap: 12px 16px; margin-top: 20px;">
    <h1 class="mono" style="font-size: 2rem; line-height: 2.5rem; font-weight: 500;">{advisory.id}</h1>
    <StatusPill kind={fixed ? "good" : row.status === "NEEDS_HUMAN" ? "human" : row.status === "PENDING" ? "quiet" : "bad"} label={fixed ? "Fixed" : row.status === "NEEDS_HUMAN" ? "Needs a human" : row.status === "PENDING" ? "Queued" : "Open"} icon={fixed} />
  </div>
  <p class="ts-body-large muted" style="margin-top: 8px; max-width: 64ch;">{intro}</p>
  {#if runSummary}
    <p class="ts-body-medium muted" style="margin-top: 4px;">Agent run: {runSummary}</p>
  {/if}
  {#if attempt?.runner === "manual_codex"}
    <p class="ts-body-medium muted" style="margin-top: 4px;">Agent-patched, run started by the maintainer. The same automatic checks decided it.</p>
  {/if}

  <div style="display: flex; flex-wrap: wrap; gap: 40px; align-items: flex-start; margin-top: 32px;">
    <section style="flex: 0 1 400px; min-width: 0;" aria-label="Receipt">
      <Receipt advisoryId={advisory.id} aliases={advisory.aliases} {row} {attempt} />
    </section>

    <div style="flex: 1 1 420px; min-width: 0; display: flex; flex-direction: column; gap: 28px;">
      {#if attempt?.gates}
        <section class="card-filled" style="padding: 20px 20px 12px;" aria-labelledby="checks-h">
          <h2 id="checks-h" class="ts-title-large" style="margin-bottom: 8px;">What checked this fix</h2>
          <ul class="plain">
            {#each attempt.gates as g (g.name)}
              <li style="display: flex; align-items: flex-start; gap: 14px; padding: 10px 0;">
                <span class="lead-ic" style="flex: 0 0 28px; width: 28px; height: 28px; background: {g.passed ? 'var(--md-sys-color-primary-container)' : 'var(--md-sys-color-error-container)'}; color: {g.passed ? 'var(--md-sys-color-on-primary-container)' : 'var(--md-sys-color-on-error-container)'};">
                  <Icon name={g.passed ? "check" : "alert"} size={16} />
                </span>
                <div style="min-width: 0;">
                  <div class="ts-title-small">{GATE_LABELS[g.name] ?? g.name}</div>
                  <div class="ts-body-small muted">{g.reason}</div>
                </div>
                <span class="visually-hidden">{g.passed ? "Passed" : "Failed"}</span>
              </li>
            {/each}
          </ul>
        </section>
      {/if}

      {#if diff}
        <section aria-labelledby="diff-h">
          <div style="display: flex; align-items: baseline; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 8px;">
            <h2 id="diff-h" class="ts-title-large">The patch</h2>
            <span class="ts-body-small muted">{diff.files} {diff.files === 1 ? "file" : "files"}, +{diff.added} −{diff.removed}</span>
          </div>
          <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
          <pre class="diff" tabindex="0" aria-label="Patch diff">{#each diff.lines as l, i (i)}<div class={l.kind === "ctx" ? "" : l.kind}>{l.text}</div>{/each}</pre>
        </section>
      {:else if !fixed}
        <p class="ts-body-medium muted">There is no patch to show yet.</p>
      {/if}

      {#if others.length > 0}
        <section aria-labelledby="also-h">
          <h2 id="also-h" class="ts-title-medium" style="margin-bottom: 8px;">Also affects</h2>
          <ul class="plain" style="display: flex; flex-wrap: wrap; gap: 8px;">
            {#each others as o (o.id)}
              <li><a class="chip sl" href={fixHref(advisory.id, o.id)}>{o.image} · {o.package}</a></li>
            {/each}
          </ul>
        </section>
      {/if}

      <p class="ts-body-medium muted">
        Curious how an agent produced this patch, and what it cost? <a class="link" href="#/about">See how dabao-zero works</a>.
      </p>
    </div>
  </div>
{/if}
