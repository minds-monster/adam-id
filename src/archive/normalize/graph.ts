import type { Manifest } from "../loader.js";
import { loadDataType } from "../loader.js";
import type { AccountRef, DirectMessage, Post, Profile } from "../../corpus/model.js";

interface RawEdge {
  accountId?: string;
}

interface RawProfile {
  description?: { bio?: string; website?: string; location?: string };
}

interface RawAccount {
  accountId?: string;
  username?: string;
  accountDisplayName?: string;
  createdAt?: string;
}

export function normalizeProfile(archiveDir: string, manifest: Manifest): Profile {
  const account = loadDataType<RawAccount>(archiveDir, manifest, "account")[0] ?? {};
  const profile = loadDataType<RawProfile>(archiveDir, manifest, "profile")[0] ?? {};
  return {
    accountId: account.accountId ?? manifest.userInfo.accountId,
    username: account.username ?? manifest.userInfo.userName,
    displayName: account.accountDisplayName ?? manifest.userInfo.displayName,
    bio: profile.description?.bio ?? null,
    website: profile.description?.website ?? null,
    location: profile.description?.location || null,
    createdAt: account.createdAt ?? null,
  };
}

/**
 * Harvest `accountId -> screenName` from every mention we can find. This matters
 * because follower.js and following.js contain *only* numeric account ids — X
 * ships no usernames for your social graph. Mentions across posts and DMs are the
 * only in-archive way to put names to a subset of those ids.
 */
export function harvestHandles(
  posts: Post[],
  dms: DirectMessage[],
  seed: Map<string, string>,
  profile: Profile,
): Map<string, string> {
  const handles = new Map(seed);
  handles.set(profile.accountId, profile.username);
  for (const p of posts) {
    for (const m of p.mentions) {
      if (m.id && m.screenName) handles.set(m.id, m.screenName);
    }
    // Reply targets give another id/handle pair that mentions sometimes miss.
    if (p.inReplyToUserId && p.inReplyToScreenName) {
      handles.set(p.inReplyToUserId, p.inReplyToScreenName);
    }
  }
  // DMs contribute ids but no handles, so they only widen the id set, not names.
  void dms;
  return handles;
}

export function normalizeAccounts(
  archiveDir: string,
  manifest: Manifest,
  handles: Map<string, string>,
): AccountRef[] {
  const followers = new Set(
    loadDataType<RawEdge>(archiveDir, manifest, "follower")
      .map((e) => e.accountId)
      .filter((id): id is string => Boolean(id)),
  );
  const following = new Set(
    loadDataType<RawEdge>(archiveDir, manifest, "following")
      .map((e) => e.accountId)
      .filter((id): id is string => Boolean(id)),
  );
  const all = new Set([...followers, ...following]);
  return [...all].map((accountId) => ({
    accountId,
    screenName: handles.get(accountId) ?? null,
    follower: followers.has(accountId),
    following: following.has(accountId),
  }));
}
