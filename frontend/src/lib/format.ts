export function formatDuration(seconds: number | null): string {
  if (seconds === null) return "n/a";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

const pad = (n: number) => String(n).padStart(2, "0");

/** 2027-01-06 13:00 UTC */
export function formatDateTime(epochSeconds: number | null): string {
  if (epochSeconds === null) return "n/a";
  const d = new Date(epochSeconds * 1000);
  return `${formatDate(epochSeconds)} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
}

/** 2027-01-06 */
export function formatDate(epochSeconds: number | null): string {
  if (epochSeconds === null) return "n/a";
  const d = new Date(epochSeconds * 1000);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

/** "3 days ago", "just now". `nowSeconds` is injectable so tests never depend on the clock. */
export function relativeTime(epochSeconds: number | null, nowSeconds = Date.now() / 1000): string {
  if (epochSeconds === null) return "never";
  const diff = Math.max(0, nowSeconds - epochSeconds);
  if (diff < 60) return "just now";
  if (diff < 3600) return plural(Math.floor(diff / 60), "minute") + " ago";
  if (diff < 86400) return plural(Math.floor(diff / 3600), "hour") + " ago";
  if (diff < 86400 * 60) return plural(Math.floor(diff / 86400), "day") + " ago";
  return plural(Math.floor(diff / (86400 * 30)), "month") + " ago";
}

function plural(n: number, unit: string): string {
  return `${n} ${unit}${n === 1 ? "" : "s"}`;
}

export function formatUsd(value: number | null): string {
  return value === null ? "n/a" : `$${value.toFixed(2)}`;
}

export function formatCount(n: number): string {
  return n.toLocaleString("en-US");
}

export function openCvesLabel(open: number): string {
  if (open === 0) return "No open CVEs";
  return `${open} open ${open === 1 ? "CVE" : "CVEs"}`;
}

export type Route =
  | { page: "catalog" }
  | { page: "image"; name: string; tab: ImageTab }
  | { page: "fix"; id: string; row: number | null }
  | { page: "about" }
  | { page: "notfound" };

export type ImageTab = "overview" | "tags" | "fixes" | "verify";
export const IMAGE_TABS: ImageTab[] = ["overview", "tags", "fixes", "verify"];

export function parseRoute(hash: string): Route {
  const parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  if (parts.length === 0) return { page: "catalog" };
  if (parts[0] === "about" && parts.length === 1) return { page: "about" };
  if (parts[0] === "images" && (parts.length === 2 || parts.length === 3)) {
    const tab = (parts[2] ?? "tags") as ImageTab;
    if (!IMAGE_TABS.includes(tab)) return { page: "notfound" };
    return { page: "image", name: parts[1], tab };
  }
  if (parts[0] === "fixes" && (parts.length === 2 || parts.length === 3)) {
    const row = parts[2] === undefined ? null : Number(parts[2]);
    if (row !== null && !Number.isInteger(row)) return { page: "notfound" };
    return { page: "fix", id: parts[1], row };
  }
  return { page: "notfound" };
}

export const imageHref = (name: string, tab?: ImageTab) =>
  `#/images/${encodeURIComponent(name)}${tab ? `/${tab}` : ""}`;
export const fixHref = (id: string, row?: number) =>
  `#/fixes/${encodeURIComponent(id)}${row === undefined ? "" : `/${row}`}`;
