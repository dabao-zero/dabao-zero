<script lang="ts">
  import { api } from "../lib/api";
  import { formatDuration } from "../lib/format";
  import Async from "../lib/Async.svelte";
</script>

<h1>Images</h1>
<Async load={api.images}>
  {#snippet children(images)}
    {#if images.length === 0}
      <p>No images yet.</p>
    {:else}
      <table>
        <thead>
          <tr><th>Image</th><th>Patched</th><th>Unpatched</th><th>Pending</th><th>Median time to patch</th></tr>
        </thead>
        <tbody>
          {#each images as img (img.name)}
            <tr>
              <td><a href={`#/images/${encodeURIComponent(img.name)}`}>{img.name}</a></td>
              <td>{img.patched}</td>
              <td>{img.unpatched}</td>
              <td>{img.pending}</td>
              <td>{formatDuration(img.median_time_to_patch_s)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  {/snippet}
</Async>
