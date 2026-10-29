import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, endpoint } from "./api";

afterEach(() => vi.unstubAllGlobals());

describe("endpoint", () => {
  it("keeps the path for a live API", () => {
    expect(endpoint("/v1/images", false, "")).toBe("/v1/images");
    expect(endpoint("/v1/runs?limit=5", false, "https://api.example")).toBe(
      "https://api.example/v1/runs?limit=5",
    );
  });
  it("maps a path to a .json file under the site base in static mode", () => {
    expect(endpoint("/v1/images", true, "/dabao-zero/")).toBe("/dabao-zero/v1/images.json");
    expect(endpoint("/v1/images/nginx", true, "/dabao-zero/")).toBe(
      "/dabao-zero/v1/images/nginx.json",
    );
    expect(endpoint("/v1/runs?limit=10", true, "/dabao-zero")).toBe("/dabao-zero/v1/runs.json");
    expect(endpoint("/v1/advisories/CVE-2024-1", true, "/")).toBe("/v1/advisories/CVE-2024-1.json");
  });
});

describe("api", () => {
  it("requests the runs endpoint with a limit", async () => {
    const f = vi.fn().mockResolvedValue(new Response("[]"));
    vi.stubGlobal("fetch", f);
    await api.runs(5);
    expect(String(f.mock.calls[0][0])).toContain("/v1/runs?limit=5");
  });
  it("throws ApiError carrying the status", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("no", { status: 404 })));
    await expect(api.image("x")).rejects.toMatchObject({ status: 404 });
    await expect(api.image("x")).rejects.toBeInstanceOf(ApiError);
  });
});
