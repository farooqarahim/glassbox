import { describe, it, expect } from "vitest";
import { buildInteraction } from "../src/index.js";

describe("buildInteraction", () => {
  it("drops undefined fields", () => {
    const body = buildInteraction();
    expect(Object.keys(body)).toEqual([]);
  });

  it("rejects unknown fields", () => {
    expect(() =>
      // @ts-expect-error — intentional bad field
      buildInteraction({ not_a_field: 42 }),
    ).toThrow(/unknown InteractionBody field/);
  });

  it("round-trips full body through JSON", () => {
    const body = buildInteraction({
      model: { provider: "anthropic", model_name: "claude", model_version: "v" },
      decision: { decision_id: "loan-1", outcome: "approved" },
      tags: [{ key: "decision_id", value: "loan-1" }],
      metadata: { channel: "web" },
    });
    const encoded = JSON.stringify(body);
    expect(encoded).toContain("claude");
    expect(encoded).toContain("loan-1");
    expect(encoded).toContain("web");
  });
});
