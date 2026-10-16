<script lang="ts">
  import { api } from "../lib/api";
  import Async from "../components/Async.svelte";
  import CatalogView from "./CatalogView.svelte";
</script>

<Async load={api.images}>
  {#snippet children(images)}
    <CatalogView {images} />
    <p class="ts-body-small muted" style="margin-top: 16px;">CVE counts come from the scanners that gate each build.</p>
  {/snippet}
</Async>
