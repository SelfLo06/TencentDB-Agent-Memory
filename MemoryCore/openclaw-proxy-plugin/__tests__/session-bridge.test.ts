import { describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import type { OpenClawPluginApi, ProviderWrapStreamFnContext } from "openclaw/plugin-sdk/core";
import register, { withOpenClawConversationId, wrapMemoryProxyStream } from "../index.js";

describe("MemoryProxy OpenClaw session bridge", () => {
  it("maps the same sessionId to the same conversation header", () => {
    const first = withOpenClawConversationId({ sessionId: "session-a" });
    const second = withOpenClawConversationId({ sessionId: "session-a" });

    expect(first?.headers?.["x-conversation-id"]).toBe("openclaw-session-a");
    expect(second?.headers?.["x-conversation-id"]).toBe("openclaw-session-a");
  });

  it("maps different sessionIds to different conversation headers", () => {
    const first = withOpenClawConversationId({ sessionId: "session-a" });
    const second = withOpenClawConversationId({ sessionId: "session-b" });

    expect(first?.headers?.["x-conversation-id"]).not.toBe(
      second?.headers?.["x-conversation-id"],
    );
    expect(second?.headers?.["x-conversation-id"]).toBe("openclaw-session-b");
  });

  it("normalizes surrounding whitespace before building the conversation header", () => {
    const result = withOpenClawConversationId({ sessionId: "  session-a  " });

    expect(result?.headers?.["x-conversation-id"]).toBe("openclaw-session-a");
  });

  it("preserves non-conversation headers and replaces existing conversation casing", () => {
    const result = withOpenClawConversationId({
      sessionId: "session-a",
      headers: {
        Authorization: "Bearer token",
        "x-team-id": "team-1",
        "X-Conversation-ID": "static-value",
      },
    });

    expect(result?.headers).toEqual({
      Authorization: "Bearer token",
      "x-team-id": "team-1",
      "x-conversation-id": "openclaw-session-a",
    });
  });

  it("forwards missing sessionId without inventing identity and logs clearly", () => {
    const inner = vi.fn(() => ({ stream: true })) as any;
    const logger = { warn: vi.fn() } as any;
    const wrapped = wrapMemoryProxyStream({ streamFn: inner } as ProviderWrapStreamFnContext, logger);
    const options = { headers: { "x-team-id": "team-1" } };

    wrapped?.({} as never, {} as never, options);

    expect(inner).toHaveBeenCalledWith({}, {}, options);
    expect(options.headers).toEqual({ "x-team-id": "team-1" });
    expect(options.headers?.["x-conversation-id"]).toBeUndefined();
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining("Missing native options.sessionId"));
  });

  it("injects the same conversation header on every wrapped provider request", () => {
    const inner = vi.fn(() => ({ stream: true })) as any;
    const logger = { warn: vi.fn() } as any;
    const wrapped = wrapMemoryProxyStream({ streamFn: inner } as ProviderWrapStreamFnContext, logger);

    wrapped?.({} as never, {} as never, { sessionId: "session-a" });
    wrapped?.({} as never, {} as never, { sessionId: "session-a" });

    expect(inner).toHaveBeenCalledTimes(2);
    for (const call of inner.mock.calls) {
      expect(call[2]?.headers?.["x-conversation-id"]).toBe("openclaw-session-a");
    }
  });

  it("registers only the memory-proxy provider wrapper", () => {
    const registerProvider = vi.fn();
    register({ registerProvider } as any);

    expect(registerProvider).toHaveBeenCalledTimes(1);
    expect(registerProvider).toHaveBeenCalledWith(
      expect.objectContaining({
        id: "memory-proxy",
        auth: [],
        wrapStreamFn: expect.any(Function),
      }),
    );
    const manifest = JSON.parse(readFileSync(new URL("../openclaw.plugin.json", import.meta.url), "utf8"));
    expect(manifest.providers).toEqual([registerProvider.mock.calls[0][0].id]);
  });
});
