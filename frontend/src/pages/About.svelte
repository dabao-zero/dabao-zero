<script lang="ts">
  import { api } from "../lib/api";
  import Async from "../components/Async.svelte";
  import AboutView from "./AboutView.svelte";

  const load = () => Promise.all([api.stats(), api.runs(10)]);
</script>

<Async {load}>
  {#snippet children([stats, runs])}<AboutView {stats} {runs} />{/snippet}
</Async>
