import { describe, expect, it } from "vitest";
import { ApiError, getJson } from "./api";

function fakeFetch(status: number, body: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), { status, statusText: status === 404 ? "Not Found" : "OK" })) as typeof fetch;
}

describe("getJson", () => {
  it("returns parsed JSON on success", async () => {
    expect(await getJson("/v1/images", fakeFetch(200, [{ name: "nginx" }]))).toEqual([{ name: "nginx" }]);
  });
  it("throws ApiError with the status on failure", async () => {
    await expect(getJson("/v1/images/x", fakeFetch(404, {}))).rejects.toMatchObject({
      status: 404,
    });
    await expect(getJson("/v1/images/x", fakeFetch(404, {}))).rejects.toBeInstanceOf(ApiError);
  });
});
