<script lang="ts">
  import Icon from "./Icon.svelte";

  type Kind = "good" | "bad" | "quiet" | "human";
  let { kind, label, icon = false }: { kind: Kind; label: string; icon?: boolean } = $props();
  const cls = { good: "st-patched", bad: "st-unpatched", quiet: "st-pending", human: "st-human" } as const;
</script>

<span class="status {cls[kind]}">
  {#if icon}<Icon name="check" size={14} />{/if}{label}
</span>
