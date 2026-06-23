import { describe, it, expect } from "vitest";
import { wrapAnthropic, wrapOpenAI, type InteractionBody } from "../src/index.js";

class FakeOpenAI {
  chat = {
    completions: {
      create: (args: { model: string; messages: unknown[] }) => ({
        output_text: `echoed ${JSON.stringify(args.messages)}`,
      }),
    },
  };
  id = "not-intercepted";
}

class FakeAnthropic {
  messages = {
    create: (_args: { model: string; messages: unknown[] }) => ({
      content: "echoed",
    }),
  };
}

describe("wrapOpenAI", () => {
  it("records each call and preserves the response", () => {
    const captured: InteractionBody[] = [];
    const wrapped = wrapOpenAI(new FakeOpenAI(), {
      onInteraction: (b) => captured.push(b),
      modelVersion: "2026-01-19",
    });
    const resp = wrapped.chat.completions.create({
      model: "gpt-4.1",
      messages: [{ role: "user", content: "hi" }],
    });
    expect((resp as { output_text: string }).output_text).toContain("echoed");
    expect(captured.length).toBe(1);
    const body = captured[0]!;
    expect(body.model?.provider).toBe("openai");
    expect(body.model?.model_name).toBe("gpt-4.1");
    expect(body.model?.model_version).toBe("2026-01-19");
    expect(body.input?.hash_hex.length).toBe(64);
  });

  it("passes through unrelated attributes", () => {
    const wrapped = wrapOpenAI(new FakeOpenAI(), {
      onInteraction: () => {},
    });
    expect(wrapped.id).toBe("not-intercepted");
  });

  it("never breaks the call when the audit callback throws", () => {
    const wrapped = wrapOpenAI(new FakeOpenAI(), {
      onInteraction: () => {
        throw new Error("audit pipeline down");
      },
    });
    const resp = wrapped.chat.completions.create({
      model: "gpt-4.1",
      messages: [],
    });
    expect((resp as { output_text: string }).output_text).toBeDefined();
  });
});

describe("wrapAnthropic", () => {
  it("records messages.create calls", () => {
    const captured: InteractionBody[] = [];
    const wrapped = wrapAnthropic(new FakeAnthropic(), {
      onInteraction: (b) => captured.push(b),
      modelVersion: "20260119",
    });
    const resp = wrapped.messages.create({
      model: "claude-opus-4-7",
      messages: [{ role: "user", content: "hi" }],
    });
    expect((resp as { content: string }).content).toBe("echoed");
    expect(captured.length).toBe(1);
    expect(captured[0]!.model?.provider).toBe("anthropic");
    expect(captured[0]!.model?.model_name).toBe("claude-opus-4-7");
  });
});
