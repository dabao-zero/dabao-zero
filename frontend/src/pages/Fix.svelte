<script lang="ts">
  import { api } from "../lib/api";
  import Async from "../components/Async.svelte";
  import FixView from "./FixView.svelte";

  let { id, row }: { id: string; row: number | null } = $props();
</script>

<Async load={() => api.advisory(id)}>
  {#snippet children(advisory)}<FixView {advisory} rowId={row} />{/snippet}
  {#snippet notFound()}
    <h1 class="ts-headline-large" style="margin-top: 32px;">No advisory called {id}</h1>
    <p class="ts-body-large muted" style="margin-top: 8px;"><a class="link" href="#/images">Back to all images</a></p>
  {/snippet}
</Async>
