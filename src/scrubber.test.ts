import { describe, expect, it } from "vitest";

import { generateId } from "./ids.js";
import { scrubHeaders, scrubSecretsFromText } from "./scrubber.js";

const encoder = new TextEncoder();

describe("zero-context output scrubber", () => {
  it("redacts raw UTF-8, standard Base64, base64url, and URL-encoded secret occurrences", () => {
    const secId = generateId("sec", 1760000000000);
    const rawSecret = "sk_live_987654321+abc/def==";
    const secretBytes = encoder.encode(rawSecret);

    const stdBase64 = Buffer.from(secretBytes).toString("base64");
    const unpaddedBase64 = stdBase64.replace(/=+$/, "");
    const urlEncoded = encodeURIComponent(rawSecret);

    const noisyOutput = [
      `Connecting with token=${rawSecret}`,
      `Base64 trace: ${stdBase64}`,
      `Unpadded trace: ${unpaddedBase64}`,
      `Query param: ?api_key=${urlEncoded}&mode=test`,
    ].join("\n");

    const scrubbed = scrubSecretsFromText(noisyOutput, [{ id: secId, valueBytes: secretBytes }]);

    expect(scrubbed).not.toContain(rawSecret);
    expect(scrubbed).not.toContain(stdBase64);
    expect(scrubbed).not.toContain(unpaddedBase64);
    expect(scrubbed).not.toContain(urlEncoded);
    expect(scrubbed).toContain(`Connecting with token=[REDACTED:${secId}]`);
    expect(scrubbed).toContain(`Base64 trace: [REDACTED:${secId}]`);
    expect(scrubbed).toContain(`?api_key=[REDACTED:${secId}]&mode=test`);
  });

  it("scrubs HTTP response headers and redacts sensitive auth headers", () => {
    const secId = generateId("sec", 1760000000000);
    const secretBytes = encoder.encode("my-super-secret-header-token");

    const safeHeaders = scrubHeaders(
      {
        "content-type": "application/json",
        "x-echo-secret": "Bearer my-super-secret-header-token",
        Authorization: "Bearer some-other-credential",
      },
      [{ id: secId, valueBytes: secretBytes }],
    );

    expect(safeHeaders["content-type"]).toBe("application/json");
    expect(safeHeaders["x-echo-secret"]).toBe(`Bearer [REDACTED:${secId}]`);
    expect(safeHeaders["Authorization"]).toBe("[REDACTED:HEADER]");
  });
});
