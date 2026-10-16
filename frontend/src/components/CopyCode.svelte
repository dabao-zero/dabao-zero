<script lang="ts">
  import Icon from "./Icon.svelte";

  let { text, label = "Copy command" }: { text: string; label?: string } = $props();
  let copied = $state(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
      setTimeout(() => (copied = false), 1800);
    } catch {
      copied = false; // clipboard blocked: the text stays selectable in the box
    }
  }
</script>

<div class="code">
  <code>{text}</code>
  <button type="button" class="icon-btn sl" onclick={copy} aria-label={label}>
    <Icon name={copied ? "check" : "copy"} />
  </button>
  <span class="visually-hidden" role="status">{copied ? "Copied" : ""}</span>
</div>
