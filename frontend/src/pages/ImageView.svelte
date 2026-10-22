<script lang="ts">
  import type { ImageDetail } from "../lib/api";
  import { pullCommand, REGISTRY, REPO_URL } from "../lib/config";
  import {
    fixHref,
    formatDate,
    formatDuration,
    IMAGE_TABS,
    imageHref,
    openCvesLabel,
    type ImageTab,
  } from "../lib/format";
  import CopyCode from "../components/CopyCode.svelte";
  import Icon from "../components/Icon.svelte";
  import StatusPill from "../components/StatusPill.svelte";

  let { image, tab }: { image: ImageDetail; tab: ImageTab } = $props();

  const labels: Record<ImageTab, string> = { overview: "Overview", tags: "Tags", fixes: "Fixes", verify: "Verify" };
  const live = $derived(image.tags.filter((t) => t.status === "PUBLISHED"));
  const latest = $derived(live[0] ?? null);
  const ref = $derived(latest ? `${REGISTRY}/${image.name}@${latest.digest}` : null);

  const advisoryKind = (status: string) =>
    status === "PATCHED" ? "good" : status === "NEEDS_HUMAN" ? "human" : status === "PENDING" ? "quiet" : "bad";
  const advisoryLabel: Record<string, string> = {
    PATCHED: "Fixed",
    UNPATCHED: "Open",
    PENDING: "Queued",
    NEEDS_HUMAN: "Needs a human",
  };
  const advisoryDetail = (a: ImageDetail["advisories"][number]) =>
    a.status === "PATCHED"
      ? `Fixed after ${formatDuration((a.patched_at ?? a.created_at) - a.created_at)}`
      : a.status === "UNPATCHED"
        ? "No fix yet. Scanners still report it after the upstream patch."
        : a.status === "NEEDS_HUMAN"
          ? "Stopped for a person to look at"
          : "Waiting for an agent";

  function go(next: ImageTab) {
    window.location.hash = imageHref(image.name, next);
  }
</script>

<nav aria-label="Breadcrumb" class="ts-body-medium muted" style="display: flex; gap: 8px; align-items: center; margin-top: 8px;">
  <a class="link" href="#/images">Images</a><span aria-hidden="true">/</span><span aria-current="page">{image.name}</span>
</nav>

<section style="display: flex; flex-wrap: wrap; gap: 24px 40px; align-items: flex-start; margin-top: 20px;">
  <div style="flex: 1 1 440px; min-width: 0;">
    <div style="display: flex; align-items: center; gap: 16px;">
      <span class="monogram" aria-hidden="true" style="flex-basis: 56px; width: 56px; height: 56px; font-size: 1.75rem;">{image.name.charAt(0)}</span>
      <h1 class="ts-headline-large" style="font-size: 2.75rem; line-height: 3rem;">{image.name}</h1>
    </div>
    <p class="ts-body-large muted" style="margin-top: 16px; max-width: 60ch;">
      {image.description || "No description yet."} A drop-in replacement for the official image, with known CVEs fixed from upstream patches.
    </p>
    <div style="display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; align-items: center;">
      {#each image.bases as b (b)}<span class="tag">{b}</span>{/each}
      <StatusPill kind={image.open === 0 ? "good" : "bad"} label={openCvesLabel(image.open)} />
      {#if latest}<StatusPill kind="good" label="Signed" icon />{/if}
    </div>
  </div>
  <div class="card-filled" style="flex: 0 1 460px; min-width: 0; padding: 20px;">
    <div class="ts-title-medium">Pull the latest</div>
    {#if latest}
      <div style="margin-top: 12px;"><CopyCode text={pullCommand(image.name, latest.tag)} label="Copy pull command" /></div>
      <p class="ts-body-small muted" style="margin-top: 12px;">
        <span class="mono">{latest.tag}</span> on {latest.stream}, built {formatDate(latest.published_at)}. Pin a tag or a digest in production.
      </p>
    {:else}
      <p class="ts-body-medium muted" style="margin-top: 8px;">No image has been published yet.</p>
    {/if}
  </div>
</section>

<div style="display: flex; flex-wrap: wrap; gap: 32px; align-items: flex-start; margin-top: 32px;">
  <div style="flex: 999 1 640px; min-width: 0;">
    <div class="tabs" role="tablist" aria-label={image.name}>
      {#each IMAGE_TABS as t (t)}
        <button type="button" role="tab" class="tab sl" aria-selected={tab === t} onclick={() => go(t)}>{labels[t]}</button>
      {/each}
    </div>

    <div role="tabpanel" style="padding-top: 24px;">
      {#if tab === "overview"}
        <h2 class="ts-title-large" style="margin-bottom: 8px;">Use it</h2>
        <p class="ts-body-medium muted" style="margin-bottom: 12px;">
          Change the image in your Dockerfile. Entrypoint, shell and package manager match the official image.
        </p>
        {#if latest}
          <pre class="code-block">{#if image.upstream}<span style="color: var(--md-sys-color-error);">- FROM {image.upstream.replace(/^docker\.io\/library\//, "")}</span>
{/if}<span style="color: var(--md-sys-color-primary);">+ FROM {REGISTRY}/{image.name}:{latest.tag}</span></pre>
        {:else}
          <p class="ts-body-medium muted">Nothing to pull yet.</p>
        {/if}
      {:else if tab === "tags"}
        {#if image.tags.length === 0}
          <p class="ts-body-medium muted">No tags have been published yet.</p>
        {:else}
          <div class="table-scroll">
            <table class="dtable">
              <thead>
                <tr>
                  <th scope="col">Tag</th><th scope="col">Base</th><th scope="col">Digest</th>
                  <th scope="col">Published</th><th scope="col">CVEs</th><th scope="col"><span class="visually-hidden">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {#each image.tags as t (t.digest)}
                  <tr>
                    <td class="mono" style="font-size: 13px;">{t.tag}</td>
                    <td><span class="tag">{t.stream}</span></td>
                    <td class="mono muted" style="font-size: 13px;" title={t.digest}>{t.digest.slice(0, 19)}…</td>
                    <td class="num">{formatDate(t.published_at)}</td>
                    <td>
                      {#if t.status === "REVOKED"}
                        <StatusPill kind="human" label="Revoked" />
                      {:else}
                        <StatusPill kind={t.open_cves === 0 ? "good" : "bad"} label={t.open_cves === 0 ? "No open CVEs" : `${t.open_cves} open`} />
                      {/if}
                    </td>
                    <td style="text-align: right;">
                      {#if t.status !== "REVOKED"}
                        <button type="button" class="icon-btn sl" aria-label="Copy pull command for {t.tag}" onclick={() => navigator.clipboard?.writeText(pullCommand(image.name, t.tag))}>
                          <Icon name="copy" />
                        </button>
                      {/if}
                    </td>
                  </tr>
                  {#if t.status === "REVOKED" && t.revoked_reason}
                    <tr><td colspan="6" class="ts-body-small muted" style="padding-top: 0;">Revoked: {t.revoked_reason}</td></tr>
                  {/if}
                {/each}
              </tbody>
            </table>
          </div>
          <p class="ts-body-small muted" style="margin-top: 12px;">A revoked tag stays in the list so you can see why it should not be used.</p>
        {/if}
      {:else if tab === "fixes"}
        {#if image.advisories.length === 0}
          <p class="ts-body-medium muted">No advisories have affected this image.</p>
        {:else}
          <ul class="plain" style="display: flex; flex-direction: column; gap: 8px;">
            {#each image.advisories as a (a.id)}
              <li>
                <a class="row sl" href={fixHref(a.advisory_id, a.id)}>
                  <span class="lead-ic" style="background: {a.status === 'PATCHED' ? 'var(--md-sys-color-primary-container)' : 'var(--md-sys-color-error-container)'}; color: {a.status === 'PATCHED' ? 'var(--md-sys-color-on-primary-container)' : 'var(--md-sys-color-on-error-container)'};">
                    <Icon name={a.status === "PATCHED" ? "check" : "alert"} size={22} />
                  </span>
                  <div style="flex: 1 1 auto; min-width: 0;">
                    <div class="mono ts-title-small" style="letter-spacing: 0;">{a.advisory_id}</div>
                    <div class="ts-body-medium muted">{a.package} {a.version} · {a.stream}</div>
                  </div>
                  <div class="ts-body-medium muted detail">{advisoryDetail(a)}</div>
                  <StatusPill kind={advisoryKind(a.status)} label={advisoryLabel[a.status] ?? a.status} />
                </a>
              </li>
            {/each}
          </ul>
        {/if}
      {:else if tab === "verify"}
        <p class="ts-body-medium muted" style="max-width: 64ch;">
          Every published image is signed and ships with a bill of materials. Check them yourself before you trust them.
        </p>
        {#if ref}
          <div style="display: flex; flex-direction: column; gap: 20px; margin-top: 20px;">
            <div>
              <h2 class="ts-title-medium" style="margin-bottom: 8px;">Verify the signature</h2>
              <pre class="code-block">{`cosign verify ${ref} \\
  --certificate-identity-regexp '${REPO_URL}/.*' \\
  --certificate-oidc-issuer https://token.actions.githubusercontent.com`}</pre>
            </div>
            <div>
              <h2 class="ts-title-medium" style="margin-bottom: 8px;">Read the bill of materials</h2>
              <pre class="code-block">{`cosign download sbom ${ref}`}</pre>
            </div>
          </div>
        {:else}
          <p class="ts-body-medium muted" style="margin-top: 16px;">Nothing to verify until an image is published.</p>
        {/if}
      {/if}
    </div>
  </div>

  <aside aria-label="Details" class="card-outlined" style="flex: 1 1 280px; max-width: 340px; padding: 20px;">
    <h2 class="ts-title-medium" style="margin-bottom: 12px;">Details</h2>
    <dl class="ts-body-medium details">
      <dt class="muted">Latest tag</dt><dd class="mono">{latest?.tag ?? "none"}</dd>
      <dt class="muted">Bases</dt><dd>{image.bases.join(", ") || "none"}</dd>
      <dt class="muted">Last built</dt><dd>{formatDate(image.updated_at)}</dd>
      <dt class="muted">Fixed so far</dt><dd>{image.fixed}</dd>
      <dt class="muted">Median fix time</dt><dd>{formatDuration(image.median_time_to_patch_s)}</dd>
      {#if image.upstream}<dt class="muted">Upstream</dt><dd>{image.upstream.replace(/^docker\.io\/library\//, "")}</dd>{/if}
    </dl>
  </aside>
</div>

<style>
  .details { display: grid; grid-template-columns: auto 1fr; gap: 10px 16px; margin: 0; }
  .details dd { margin: 0; text-align: right; font-size: 0.875rem; overflow-wrap: anywhere; }
  .details dd.mono { font-size: 13px; }
  .detail { flex: 0 1 240px; min-width: 0; text-align: right; }
  @media (max-width: 700px) { .detail { display: none; } }
</style>
