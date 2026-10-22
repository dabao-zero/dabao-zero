<script lang="ts">
  import { REPO_URL, SITE_NAME } from "../lib/config";
  import { applyTheme, currentTheme, type Theme } from "../lib/theme";
  import Icon from "./Icon.svelte";
  import Logo from "./Logo.svelte";

  let { page }: { page: "home" | "catalog" | "image" | "fix" | "about" | "notfound" } = $props();
  let theme = $state<Theme>(currentTheme());

  function toggle() {
    theme = theme === "dark" ? "light" : "dark";
    applyTheme(theme);
  }
  const inImages = $derived(page === "catalog" || page === "image" || page === "fix");
</script>

<header class="topbar">
  <a class="wordmark" href="#/" aria-label="{SITE_NAME} home"><Logo /><span>{SITE_NAME}</span></a>
  <nav aria-label="Primary" style="display: flex; gap: 4px; flex: 1 1 auto;">
    <a class="toplink sl" href="#/images" aria-current={inImages ? "page" : undefined}>Images</a>
    <a class="toplink sl" href="#/about" aria-current={page === "about" ? "page" : undefined}>About</a>
  </nav>
  <button type="button" class="icon-btn sl" onclick={toggle} aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}>
    <Icon name={theme === "dark" ? "sun" : "moon"} size={22} />
  </button>
  <a class="icon-btn sl" href={REPO_URL} aria-label="{SITE_NAME} on GitHub"><Icon name="github" size={24} /></a>
</header>
