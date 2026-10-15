import "fake-indexeddb/auto";
import { describe, it, expect } from "vitest";
import { SyncService, saveSession, forgetSession } from "../packages/browser/src/sync/service";
import { proofKeys, random } from "../packages/browser/src/sync/crypto";

import { SyncEngine } from "../packages/browser/src/sync/engine";

const keyword = "synthetic private sync keyword";
const issuer = process.env.HAUNT_SYNC_BUNDLE_ISSUER;
describe.skipIf(!issuer)("single-container Nexus public HTTPS", () => {
  it("registers, encrypts and restores a snapshot through its own cloudflared and private database", async () => {
    const service = new SyncService(issuer!);
    const username = "bundle-check",
      password = "synthetic bundle master " + random();
    await service.register(username, password, await proofKeys(), undefined, keyword);
    const first = await service.signIn(username, password, undefined, keyword);
    const backup = {
      settings: { theme: "frosted" },
      credential: "synthetic-community-secret",
    };
    await service.write(first, backup, 0);
    const fresh = await service.signIn(username, password, undefined, keyword);
    expect((await service.read(fresh)).value).toEqual(backup);
    await service.logout(first);
    await service.logout(fresh);

    // Exercise the production engine against the actual API: empty snapshots
    // publish local data; loss of access must not call the local apply path.
    const local = {
      version: 1 as const,
      createdAt: new Date().toISOString(),
      accounts: [],
      servers: [],
      preferences: { "chatxo-client-preferences-v1": '{"theme":"frosted"}' },
    };
    await service.register("local-survival", password, await proofKeys(), undefined, keyword);
    const session = await service.signIn("local-survival", password, undefined, keyword);
    await saveSession(session);
    let applied = 0;
    const engine = new SyncEngine(session, async () => local, async (value) => {
      expect(value.preferences).toEqual(local.preferences);
      applied++;
    });
    try {
      await engine.sync();
      expect(applied).toBe(1);
      expect((await service.read(session)).value).toMatchObject({ preferences: local.preferences });
      await service.logout(session);
      await expect(engine.sync()).rejects.toMatchObject({ status: 401 });
      expect(applied).toBe(1);
      expect(local.preferences).toEqual({ "chatxo-client-preferences-v1": '{"theme":"frosted"}' });
    } finally {
      await forgetSession();
    }
  }, 90_000);
});
