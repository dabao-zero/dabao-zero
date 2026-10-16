<script lang="ts">
  import { parseRoute } from "./lib/format";
  import Advisory from "./pages/Advisory.svelte";
  import Image from "./pages/Image.svelte";
  import Images from "./pages/Images.svelte";

  let route = $state(parseRoute(window.location.hash));
  $effect(() => {
    const onChange = () => (route = parseRoute(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  });
</script>

<main>
  {#if route.page === "images"}
    <Images />
  {:else if route.page === "image"}
    <Image name={route.name} />
  {:else if route.page === "advisory"}
    <Advisory id={route.id} />
  {:else}
    <h1>Not found</h1>
    <p><a href="#/">Back to images</a></p>
  {/if}
  <footer>
    Free and open source. Provided as is, without warranty or SLA; use at your own risk.
  </footer>
</main>

<style>
  :global(body) { font-family: system-ui, sans-serif; margin: 0; color: #1a1a1a; background: #fff; }
  @media (prefers-color-scheme: dark) {
    :global(body) { color: #e8e8e8; background: #14161a; }
    :global(a) { color: #8ab4ff; }
  }
  main { max-width: 60rem; margin: 0 auto; padding: 1rem 16px; }
  :global(table) { border-collapse: collapse; width: 100%; display: block; overflow-x: auto; }
  :global(th), :global(td) { text-align: left; padding: 0.4rem 0.8rem; border-bottom: 1px solid #8884; }
  :global(pre) { overflow-x: auto; padding: 0.8rem; background: #8882; }
  :global(.status) { padding: 0.1rem 0.5rem; border-radius: 0.8rem; background: #8883; font-size: 0.85em; }
  :global(.status.patched) { background: #2a7a3b44; }
  :global(.status.unpatched), :global(.status.needs_human) { background: #b3261e44; }
  footer { margin-top: 3rem; font-size: 0.85em; opacity: 0.8; }
</style>
