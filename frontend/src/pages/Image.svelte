<script lang="ts">
  import { api } from "../lib/api";
  import type { ImageTab } from "../lib/format";
  import Async from "../components/Async.svelte";
  import ImageView from "./ImageView.svelte";

  let { name, tab }: { name: string; tab: ImageTab } = $props();
</script>

<Async load={() => api.image(name)}>
  {#snippet children(image)}<ImageView {image} {tab} />{/snippet}
  {#snippet notFound()}
    <h1 class="ts-headline-large" style="margin-top: 32px;">No image called {name}</h1>
    <p class="ts-body-large muted" style="margin-top: 8px;"><a class="link" href="#/">Back to all images</a></p>
  {/snippet}
</Async>
