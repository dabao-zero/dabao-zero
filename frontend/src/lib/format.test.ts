import { describe, expect, it } from "vitest";
import { fixHref, formatDuration, imageHref, openCvesLabel, parseRoute, relativeTime } from "./format";

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
    expect(parseRoute("")).toEqual({ page: "catalog" });
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
