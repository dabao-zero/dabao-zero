<script lang="ts" generics="T">
  import type { Snippet } from "svelte";
  import { ApiError } from "../lib/api";

  let {
    load,
    children,
    notFound,
  }: { load: () => Promise<T>; children: Snippet<[T]>; notFound?: Snippet } = $props();
  const promise = $derived(load());
</script>

{#await promise}
  <p role="status" class="ts-body-large muted" style="padding: 32px 0;">Loading…</p>
{:then data}
  {@render children(data)}
{:catch err}
  {#if err instanceof ApiError && err.status === 404 && notFound}
    {@render notFound()}
  {:else}
    <p role="alert" class="ts-body-large" style="padding: 32px 0; color: var(--md-sys-color-error);">
      Could not load this page: {err instanceof Error ? err.message : String(err)}. Is the API running?
    </p>
  {/if}
{/await}
