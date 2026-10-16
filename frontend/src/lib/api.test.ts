import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError } from "./api";

afterEach(() => vi.unstubAllGlobals());

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
