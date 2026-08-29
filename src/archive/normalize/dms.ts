import type { Manifest } from "../loader.js";
import { loadDataType } from "../loader.js";
import type { DirectMessage } from "../../corpus/model.js";
import { unescapeHtml } from "../../util/text.js";

interface RawConversation {
  conversationId?: string;
  messages?: RawMessageEnvelope[];
}

/**
 * Message entries are tagged unions keyed by event type. `messageCreate` is the
 * only one carrying text; the rest (e.g. `endAvBroadcast`, reactions) are
 * call/'event' records we skip.
 */
interface RawMessageEnvelope {
  messageCreate?: {
    id?: string;
    createdAt?: string;
    senderId?: string;
    recipientId?: string;
    text?: string;
    mediaUrls?: string[];
  };
}

/**
 * Direct messages are ingested because you asked for the whole archive, but they
 * are the one collection containing other people's words. They land in their own
 * file and behind the `dms.read` scope, which is off by default.
 */
export function normalizeDms(archiveDir: string, manifest: Manifest): DirectMessage[] {
  const out: DirectMessage[] = [];
  for (const [type, isGroup] of [
    ["directMessages", false],
    ["directMessagesGroup", true],
  ] as const) {
    for (const conv of loadDataType<RawConversation>(archiveDir, manifest, type)) {
      const conversationId = conv.conversationId ?? "";
      for (const envelope of conv.messages ?? []) {
        const m = envelope.messageCreate;
        if (!m?.id) continue;
        out.push({
          conversationId,
          messageId: m.id,
          createdAt: m.createdAt ?? new Date(0).toISOString(),
          senderId: m.senderId ?? "",
          recipientId: m.recipientId ?? null,
          text: unescapeHtml(m.text ?? ""),
          isGroup,
          mediaUrls: m.mediaUrls ?? [],
        });
      }
    }
  }
  out.sort((a, b) => (a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : 0));
  return out;
}
