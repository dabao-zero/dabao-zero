<script lang="ts">
  import type { Affected, Attempt } from "../lib/api";
  import { formatDateTime, formatDuration } from "../lib/format";

  let {
    advisoryId,
    aliases,
    row,
    attempt,
  }: { advisoryId: string; aliases: string[]; row: Affected; attempt: Attempt | null } = $props();
  const fixedAfter = $derived(row.patched_at === null ? null : row.patched_at - row.created_at);
</script>

<div class="receipt-wrap">
  <div class="receipt">
    <div class="line"><span style="font-weight: 600;">dabao-zero</span><span class="muted">fix receipt</span></div>
    <hr class="rule" />
    <div style="font-size: 20px; line-height: 28px; font-weight: 600;">{advisoryId}</div>
    {#if aliases.length > 0}<div class="muted">also {aliases.join(", ")}</div>{/if}
    <hr class="rule" />
    <div class="line"><span class="muted">Image</span><span>{row.image}</span></div>
    <div class="line"><span class="muted">Package</span><span>{row.package} {row.version}</span></div>
    <div class="line"><span class="muted">Base</span><span>{row.stream}</span></div>
    <hr class="rule" />
    <div class="line"><span class="muted">First seen</span><span>{formatDateTime(row.created_at)}</span></div>
    {#if row.patched_at !== null}
      <div class="line"><span class="muted">Fixed</span><span>{formatDateTime(row.patched_at)}</span></div>
      <div class="line total"><span>Fixed after</span><span>{formatDuration(fixedAfter)}</span></div>
    {:else}
      <div class="line total"><span>Not fixed yet</span><span>open</span></div>
    {/if}
    {#if attempt?.patch_upstream_ref}
      <hr class="rule" />
      <div class="muted">Fix taken from upstream</div>
      <div style="word-break: break-all;">{attempt.patch_upstream_ref.replace(/^https?:\/\//, "")}</div>
    {/if}
    <hr class="rule" />
    <div class="thanks">Thank you, pull again!</div>
  </div>
</div>
