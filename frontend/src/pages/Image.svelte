<script lang="ts">
  import { api } from "../lib/api";
  import { formatDate } from "../lib/format";
  import Async from "../lib/Async.svelte";

  let { name }: { name: string } = $props();
</script>

<p><a href="#/">← Images</a></p>
<h1>{name}</h1>
<Async load={() => api.image(name)}>
  {#snippet children(rows)}
    <table>
      <thead>
        <tr><th>Advisory</th><th>Stream</th><th>Package</th><th>Status</th><th>First seen</th></tr>
      </thead>
      <tbody>
        {#each rows as r (r.id)}
          <tr>
            <td><a href={`#/advisories/${encodeURIComponent(r.advisory_id)}`}>{r.advisory_id}</a></td>
            <td>{r.stream}</td>
            <td>{r.package} {r.version}</td>
            <td><span class="status {r.status.toLowerCase()}">{r.status}</span></td>
            <td>{formatDate(r.created_at)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/snippet}
</Async>
