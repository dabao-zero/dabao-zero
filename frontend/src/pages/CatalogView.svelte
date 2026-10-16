<script lang="ts">
  import type { ImageSummary } from "../lib/api";
  import { pullCommand } from "../lib/config";
  import CopyCode from "../components/CopyCode.svelte";
  import Icon from "../components/Icon.svelte";
  import ImageCard from "../components/ImageCard.svelte";
  import OpenBox from "../components/OpenBox.svelte";

  let { images }: { images: ImageSummary[] } = $props();

  let q = $state("");
  let base = $state("all");

  const bases = $derived([...new Set(images.flatMap((i) => i.bases))].sort());
  const shown = $derived(
    images.filter(
      (i) =>
        (base === "all" || i.bases.includes(base)) &&
        (q.trim() === "" ||
          i.name.toLowerCase().includes(q.trim().toLowerCase()) ||
          i.description.toLowerCase().includes(q.trim().toLowerCase())),
    ),
  );
  const example = $derived(images.find((i) => i.latest_tag !== null));
  const title = (b: string) => b.charAt(0).toUpperCase() + b.slice(1);
</script>

<section class="hero">
  <div style="flex: 1 1 420px; min-width: 0;">
    <h1 class="ts-display-small hero-title">Images with the CVEs already fixed.</h1>
    <p class="ts-body-large muted" style="margin-top: 16px; max-width: 52ch;">
      Drop-in versions of the official images. Fixes come from upstream, agents backport them, and
      machines check the result. Free to pull.
    </p>
    <label class="search" style="margin-top: 28px; max-width: 560px;">
      <Icon name="search" size={24} />
      <span class="visually-hidden">Search images</span>
      <input type="search" placeholder="Search images, for example nginx" bind:value={q} />
    </label>
    {#if example && example.latest_tag}
      <div style="margin-top: 16px; max-width: 560px;">
        <CopyCode text={pullCommand(example.name, example.latest_tag)} label="Copy pull command" />
      </div>
    {/if}
  </div>
  <div style="flex: 0 1 420px; min-width: 0;"><OpenBox /></div>
</section>

<section aria-labelledby="images-h">
  <div style="display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px 24px;">
    <div style="display: flex; align-items: baseline; gap: 12px;">
      <h2 id="images-h" class="ts-headline-small">Images</h2>
      <span class="ts-body-medium muted" aria-live="polite">{shown.length} {shown.length === 1 ? "image" : "images"}</span>
    </div>
    {#if bases.length > 0}
      <div role="group" aria-label="Filter by base" style="display: flex; flex-wrap: wrap; gap: 8px;">
        <button type="button" class="chip sl" aria-pressed={base === "all"} onclick={() => (base = "all")}>
          <span>All</span><span class="n">{images.length}</span>
        </button>
        {#each bases as b (b)}
          <button type="button" class="chip sl" aria-pressed={base === b} onclick={() => (base = b)}>
            <span>{title(b)}</span><span class="n">{images.filter((i) => i.bases.includes(b)).length}</span>
          </button>
        {/each}
      </div>
    {/if}
  </div>

  {#if shown.length > 0}
    <ul class="plain grid-cards">
      {#each shown as image (image.name)}<li><ImageCard {image} /></li>{/each}
    </ul>
  {:else}
    <div class="card-outlined empty">
      <div style="width: 110px; flex: 0 0 110px;"><OpenBox food={false} sticker={null} steam={false} maxWidth={110} /></div>
      <div>
        {#if images.length === 0}
          <div class="ts-title-medium">No images yet</div>
          <p class="ts-body-medium muted" style="margin-top: 4px;">Once the first image is published it will show up here.</p>
        {:else}
          <div class="ts-title-medium">Nothing matches that search</div>
          <p class="ts-body-medium muted" style="margin-top: 4px;">Try a shorter name, or switch the base filter back to All.</p>
        {/if}
      </div>
    </div>
  {/if}
</section>

<style>
  .hero { display: flex; flex-wrap: wrap; align-items: center; gap: 24px 56px; padding: 48px 0 40px; }
  .hero-title { font-size: 3.25rem; line-height: 3.5rem; letter-spacing: -0.01em; max-width: 14ch; }
  .grid-cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(340px, 100%), 1fr)); gap: 16px; margin-top: 20px; }
  .empty { margin-top: 20px; padding: 32px; display: flex; flex-wrap: wrap; align-items: center; gap: 24px; }
  @media (max-width: 600px) { .hero-title { font-size: 2.25rem; line-height: 2.75rem; } .hero { padding-top: 24px; } }
</style>
