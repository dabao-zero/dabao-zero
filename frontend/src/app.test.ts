import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App.svelte";
import CopyCode from "./components/CopyCode.svelte";
import AboutView from "./pages/AboutView.svelte";
import CatalogView from "./pages/CatalogView.svelte";
import FixView from "./pages/FixView.svelte";
import ImageView from "./pages/ImageView.svelte";
import { advisory, detail, images, runs, stats } from "./test/fixtures";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.location.hash = "";
  delete document.documentElement.dataset.theme;
});

describe("catalog", () => {
  it("lists images and filters by search and base", async () => {
    render(CatalogView, { images });
    expect(screen.getAllByRole("listitem").length).toBeGreaterThanOrEqual(3);
    await fireEvent.input(screen.getByPlaceholderText(/search images/i), { target: { value: "redis" } });
    expect(screen.getByText("1 image")).toBeTruthy();
    await fireEvent.input(screen.getByPlaceholderText(/search images/i), { target: { value: "" } });
    await fireEvent.click(screen.getByRole("button", { name: /alpine/i }));
    expect(screen.getByText("2 images")).toBeTruthy();
  });
  it("shows an empty state", async () => {
    render(CatalogView, { images: [] });
    expect(screen.getByText("No images yet")).toBeTruthy();
    cleanup();
    render(CatalogView, { images });
    await fireEvent.input(screen.getByPlaceholderText(/search images/i), { target: { value: "zzz" } });
    expect(screen.getByText("Nothing matches that search")).toBeTruthy();
  });
  it("offers a pull command under the registry", () => {
    render(CatalogView, { images });
    expect(screen.getByText(/docker pull ghcr\.io\/leejianrong\/nginx:1\.22\.0-1-dabao1/)).toBeTruthy();
  });
});

describe("image page", () => {
  it("shows tags with the revoked one marked", () => {
    render(ImageView, { image: detail, tab: "tags" });
    expect(screen.getAllByText("1.22.0-1-dabao2").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/revoked/i).length).toBeGreaterThan(0);
  });
  it("shows fixes and links to the fix page", () => {
    render(ImageView, { image: detail, tab: "fixes" });
    const hrefs = screen.getAllByRole("link").map((a) => a.getAttribute("href"));
    expect(hrefs).toContain("#/fixes/DEMO-1/1");
  });
  it("shows verify commands", () => {
    render(ImageView, { image: detail, tab: "verify" });
    expect(screen.getAllByText(/cosign/).length).toBeGreaterThan(0);
  });
});

describe("fix page", () => {
  it("renders the receipt, gates and diff", () => {
    render(FixView, { advisory, rowId: 1 });
    expect(screen.getByRole("heading", { name: "DEMO-1" })).toBeTruthy();
    expect(screen.getByText("+new")).toBeTruthy();
    expect(screen.getByText("1 failed")).toBeTruthy();
  });
});

describe("about", () => {
  it("shows stats, runs and the disclaimer", () => {
    render(AboutView, { stats, runs });
    expect(screen.getByText("$0.31")).toBeTruthy();
    expect(screen.getByRole("link", { name: "DEMO-1" })).toBeTruthy();
    expect(screen.getByText(/no warranty and no SLA/)).toBeTruthy();
  });
});

describe("app shell", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify(images))));
  });
  it("names the site dabao-zero and routes on hash change", async () => {
    render(App);
    expect(screen.getByRole("link", { name: /dabao-zero home/i })).toBeTruthy();
    expect(document.title).toBe("dabao-zero");
    window.location.hash = "#/about";
    window.dispatchEvent(new HashChangeEvent("hashchange"));
    await vi.waitFor(() => expect(document.title).toBe("About · dabao-zero"));
  });
  it("toggles the theme and persists it", async () => {
    render(App);
    const before = document.documentElement.dataset.theme;
    await fireEvent.click(screen.getByRole("button", { name: /switch to/i }));
    expect(document.documentElement.dataset.theme).toBeTruthy();
    expect(document.documentElement.dataset.theme).not.toBe(before);
  });
  it("states the disclaimer in the footer", () => {
    render(App);
    expect(screen.getByText(/without warranty or SLA/)).toBeTruthy();
  });
});

describe("CopyCode", () => {
  it("copies the text", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    render(CopyCode, { text: "docker pull x" });
    await fireEvent.click(screen.getByRole("button", { name: /copy/i }));
    expect(writeText).toHaveBeenCalledWith("docker pull x");
  });
  it("survives a blocked clipboard", async () => {
    vi.stubGlobal("navigator", { clipboard: { writeText: vi.fn().mockRejectedValue(new Error("no")) } });
    render(CopyCode, { text: "x" });
    await fireEvent.click(screen.getByRole("button", { name: /copy/i }));
    expect(screen.getByText("x")).toBeTruthy();
  });
});
