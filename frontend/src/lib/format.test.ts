import { describe, expect, it } from "vitest";
import { formatDate, formatDuration, parseRoute } from "./format";

describe("formatDuration", () => {
  it("handles null and each unit boundary", () => {
    expect(formatDuration(null)).toBe("n/a");
    expect(formatDuration(30)).toBe("30s");
    expect(formatDuration(300)).toBe("5m");
    expect(formatDuration(7200)).toBe("2.0h");
    expect(formatDuration(172800)).toBe("2.0d");
  });
});

describe("formatDate", () => {
  it("formats epoch seconds as UTC", () => {
    expect(formatDate(0)).toBe("1970-01-01 00:00 UTC");
    expect(formatDate(null)).toBe("n/a");
  });
});

describe("parseRoute", () => {
  it("routes the known pages and decodes names", () => {
    expect(parseRoute("")).toEqual({ page: "images" });
    expect(parseRoute("#/")).toEqual({ page: "images" });
    expect(parseRoute("#/images/nginx")).toEqual({ page: "image", name: "nginx" });
    expect(parseRoute("#/advisories/CVE-2024-0001")).toEqual({ page: "advisory", id: "CVE-2024-0001" });
    expect(parseRoute("#/images/a%2Fb")).toEqual({ page: "image", name: "a/b" });
  });
  it("falls back to notfound", () => {
    expect(parseRoute("#/nope")).toEqual({ page: "notfound" });
    expect(parseRoute("#/images")).toEqual({ page: "notfound" });
  });
});
