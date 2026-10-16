export function formatDuration(seconds: number | null): string {
  if (seconds === null) return "n/a";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

export function formatDate(epochSeconds: number | null): string {
  if (epochSeconds === null) return "n/a";
  return new Date(epochSeconds * 1000).toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

export type Route =
  | { page: "images" }
  | { page: "image"; name: string }
  | { page: "advisory"; id: string }
  | { page: "notfound" };

export function parseRoute(hash: string): Route {
  const parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  if (parts.length === 0) return { page: "images" };
  if (parts.length === 2 && parts[0] === "images") return { page: "image", name: parts[1] };
  if (parts.length === 2 && parts[0] === "advisories") return { page: "advisory", id: parts[1] };
  return { page: "notfound" };
}
