<script lang="ts">
  import type { ImageSummary } from "../lib/api";
  import { imageHref, openCvesLabel, relativeTime } from "../lib/format";
  import StatusPill from "./StatusPill.svelte";

  let { image }: { image: ImageSummary } = $props();
</script>

<a class="card-outlined sl image-card" href={imageHref(image.name)}>
  <div style="display: flex; align-items: center; gap: 14px;">
    <span class="monogram" aria-hidden="true">{image.name.charAt(0)}</span>
    <div style="min-width: 0;">
      <div class="ts-title-large">{image.name}</div>
      <div class="mono ts-body-small muted" style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
        {image.latest_tag ?? "no published tag yet"}
      </div>
    </div>
  </div>
  <p class="ts-body-medium muted" style="flex: 1 1 auto;">{image.description || "No description yet."}</p>
  <div style="display: flex; flex-wrap: wrap; gap: 6px;">
    {#each image.bases as base (base)}<span class="tag">{base}</span>{/each}
  </div>
  <div style="display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap;">
    <StatusPill kind={image.open > 0 ? "bad" : image.unfixed > 0 ? "quiet" : "good"} label={openCvesLabel(image.open, image.unfixed)} />
    <span class="ts-body-small muted">{image.fixed} fixed · updated {relativeTime(image.updated_at)}</span>
  </div>
</a>

<style>
  .image-card { display: flex; flex-direction: column; gap: 14px; padding: 20px; height: 100%; }
</style>
