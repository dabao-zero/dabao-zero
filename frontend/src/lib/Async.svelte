<script lang="ts" generics="T">
  import type { Snippet } from "svelte";

  let { load, children }: { load: () => Promise<T>; children: Snippet<[T]> } = $props();
  const promise = $derived(load());
</script>

{#await promise}
  <p role="status">Loading…</p>
{:then data}
  {@render children(data)}
{:catch err}
  <p role="alert">Could not load: {err instanceof Error ? err.message : String(err)}</p>
{/await}
