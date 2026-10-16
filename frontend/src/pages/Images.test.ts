import { render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it, vi } from "vitest";
import Images from "./Images.svelte";

afterEach(() => vi.unstubAllGlobals());

function stubFetch(status: number, body: unknown) {
  vi.stubGlobal("fetch", async () => new Response(JSON.stringify(body), { status }));
}

describe("Images page", () => {
  it("lists images with their counts and links to the detail page", async () => {
    stubFetch(200, [
      { name: "nginx", total: 2, patched: 1, unpatched: 1, pending: 0, median_time_to_patch_s: 300 },
    ]);
    render(Images);
    const link = await screen.findByRole("link", { name: "nginx" });
    expect(link.getAttribute("href")).toBe("#/images/nginx");
    expect(screen.getByText("5m")).toBeTruthy();
  });

  it("shows an alert when the API fails", async () => {
    stubFetch(500, {});
    render(Images);
    expect((await screen.findByRole("alert")).textContent).toContain("500");
  });

  it("shows an empty state", async () => {
    stubFetch(200, []);
    render(Images);
    expect(await screen.findByText("No images yet.")).toBeTruthy();
  });
});
