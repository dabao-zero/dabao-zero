import { describe, expect, it } from "vitest";
import { agentRunSummary, catalogHref, fixHref, formatDuration, imageHref, openCvesLabel, parseCatalogQuery, parseRoute, relativeTime } from "./format";

describe("format", () => {
  it("formats durations", () => {
    expect(formatDuration(null)).toBe("n/a");
    expect(formatDuration(30)).toBe("30s");
    expect(formatDuration(7200)).toBe("2.0h");
  });
  it("relative time uses the injected clock", () => {
    expect(relativeTime(1000, 1000 + 86400 * 3)).toBe("3 days ago");
    expect(relativeTime(1000, 1010)).toBe("just now");
    expect(relativeTime(null)).toBe("never");
  });
  it("labels open CVEs", () => {
    expect(openCvesLabel(0)).toBe("No open CVEs");
    expect(openCvesLabel(1)).toBe("1 open CVE");
    expect(openCvesLabel(3)).toBe("3 open CVEs");
  });
});

describe("parseRoute", () => {
  it("parses every route", () => {
    expect(parseRoute("")).toEqual({ page: "home" });
    expect(parseRoute("#/")).toEqual({ page: "home" });
    expect(parseRoute("#/images")).toEqual({ page: "catalog" });
    expect(parseRoute("#/about")).toEqual({ page: "about" });
    expect(parseRoute("#/images/nginx")).toEqual({ page: "image", name: "nginx", tab: "tags" });
    expect(parseRoute("#/images/nginx/verify")).toEqual({ page: "image", name: "nginx", tab: "verify" });
    expect(parseRoute("#/fixes/CVE-1-2/5")).toEqual({ page: "fix", id: "CVE-1-2", row: 5 });
    expect(parseRoute("#/fixes/CVE-1-2")).toEqual({ page: "fix", id: "CVE-1-2", row: null });
  });
  it("rejects unknown routes", () => {
    expect(parseRoute("#/nope")).toEqual({ page: "notfound" });
    expect(parseRoute("#/images/nginx/bogus")).toEqual({ page: "notfound" });
    expect(parseRoute("#/fixes/x/abc")).toEqual({ page: "notfound" });
  });
  it("round-trips hrefs", () => {
    expect(parseRoute(imageHref("a b", "fixes"))).toEqual({ page: "image", name: "a b", tab: "fixes" });
    expect(parseRoute(fixHref("X/Y", 2))).toEqual({ page: "fix", id: "X/Y", row: 2 });
  });
});

describe("catalog query", () => {
  it("routes #/images with or without a query to the catalog", () => {
    expect(parseRoute("#/images?base=alpine&sort=open")).toEqual({ page: "catalog" });
  });
  it("parses filters and falls back to defaults on bad values", () => {
    expect(parseCatalogQuery("#/images?q=re&base=alpine&status=open&sort=open")).toEqual({
      q: "re", base: "alpine", status: "open", sort: "open",
    });
    expect(parseCatalogQuery("#/images?status=bogus&sort=nope")).toEqual({
      q: "", base: "all", status: "all", sort: "name",
    });
    expect(parseCatalogQuery("")).toEqual({ q: "", base: "all", status: "all", sort: "name" });
  });
  it("builds a short href and round-trips", () => {
    expect(catalogHref({ q: "", base: "all", status: "all", sort: "name" })).toBe("#/images");
    const s = { q: "a b", base: "alpine", status: "fixed" as const, sort: "updated" as const };
    expect(parseCatalogQuery(catalogHref(s))).toEqual(s);
  });
});

describe("agentRunSummary", () => {
  it("joins time, tokens and cost, skipping what is unknown or zero", () => {
    expect(agentRunSummary({ agent_seconds: 378, tokens_in: 1000, tokens_out: 200, cost_usd: 0.12 })).toBe(
      "6m · 1,000 tokens in, 200 out · $0.12",
    );
    expect(agentRunSummary({ agent_seconds: 378, tokens_in: 1000, tokens_out: 200, cost_usd: 0 })).toBe(
      "6m · 1,000 tokens in, 200 out",
    );
    expect(agentRunSummary({ agent_seconds: null, tokens_in: 0, tokens_out: 0, cost_usd: 0 })).toBeNull();
    expect(agentRunSummary({ agent_seconds: 42, tokens_in: 0, tokens_out: 0, cost_usd: 0 })).toBe("42s");
  });
});
