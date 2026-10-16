<script lang="ts">
  import { api } from "../lib/api";
  import { formatDate } from "../lib/format";
  import Async from "../lib/Async.svelte";

  let { id }: { id: string } = $props();
</script>

<p><a href="#/">← Images</a></p>
<h1>{id}</h1>
<Async load={() => api.advisory(id)}>
  {#snippet children(adv)}
    {#if adv.aliases.length > 0}<p>Also known as: {adv.aliases.join(", ")}</p>{/if}
    {#each adv.affected as a (a.id)}
      <section>
        <h2>{a.image}: {a.package} {a.version} <small>({a.stream})</small></h2>
        <p><span class="status {a.status.toLowerCase()}">{a.status}</span></p>
        {#if a.attempts.length === 0}
          <p>No attempts yet.</p>
        {/if}
        {#each a.attempts as t (t.id)}
          <article>
            <h3>Attempt {t.id}: {t.outcome}</h3>
            <p>
              Started {formatDate(t.started_at)} · {t.tokens_in + t.tokens_out} tokens · ${t.cost_usd.toFixed(2)}
            </p>
            {#if t.patch_diff}
              <p>Source: {t.patch_source} · <code>{t.patch_upstream_ref}</code></p>
              <pre>{t.patch_diff}</pre>
            {/if}
          </article>
        {/each}
      </section>
    {/each}
  {/snippet}
</Async>
