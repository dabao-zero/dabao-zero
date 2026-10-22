<script lang="ts">
  import { SITE_NAME } from "./lib/config";
  import { parseRoute } from "./lib/format";
  import TopBar from "./components/TopBar.svelte";
  import About from "./pages/About.svelte";
  import Catalog from "./pages/Catalog.svelte";
  import Fix from "./pages/Fix.svelte";
  import Image from "./pages/Image.svelte";
  import Landing from "./pages/Landing.svelte";

  let hash = $state(window.location.hash);
  const route = $derived(parseRoute(hash));

  $effect(() => {
    const onChange = () => (hash = window.location.hash);
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  });

  $effect(() => {
    const r = route;
    document.title =
      r.page === "catalog" ? `Images · ${SITE_NAME}`
      : r.page === "image" ? `${r.name} · ${SITE_NAME}`
      : r.page === "fix" ? `${r.id} · ${SITE_NAME}`
      : r.page === "about" ? `About · ${SITE_NAME}`
      : SITE_NAME;
  });
</script>

<TopBar page={route.page} />
<main class="page">
  {#if route.page === "home"}
    <Landing />
  {:else if route.page === "catalog"}
    <Catalog />
  {:else if route.page === "image"}
    {#key route.name}<Image name={route.name} tab={route.tab} />{/key}
  {:else if route.page === "fix"}
    {#key route.id}<Fix id={route.id} row={route.row} />{/key}
  {:else if route.page === "about"}
    <About />
  {:else}
    <h1 class="ts-headline-large" style="margin-top: 32px;">Page not found</h1>
    <p class="ts-body-large muted"><a class="link" href="#/images">Back to all images</a></p>
  {/if}
</main>
<footer class="page ts-label-small muted" style="padding-top: 24px;">
  Free and open source. Provided as is, without warranty or SLA; use at your own risk.
</footer>
