# Signed desktop update distribution

Haunt Sync can serve a public desktop-update mirror without requiring a sync
account or sharing repository credentials. This feature is optional and returns
`client_update_unavailable` until populated.

Clients connected to an instance add:

```text
https://YOUR_SYNC_HOST/client-updates/haunt-updates.json
```

They choose the newest valid signed release and prefer the sync mirror for equal
versions. Other configured sources remain available. Logging out of sync removes
that instance's update source.

Publisher signatures, file hashes, platform checks, and desktop rollback remain
mandatory. Sync serves verified bytes; it does not replace client signature
verification.

## Import a release

From the Haunt hub checkout, download a complete signed desktop release into a
staging directory and run:

```sh
python3 scripts/import-sync-updates.py /path/to/downloaded/release
```

The importer checks the pinned client publisher key and every artifact hash,
including Linux RPM installers, before publishing the manifest. It preserves the signed bytes and refuses
to replace an existing version with different files.

The hub Compose configuration mounts `.local/sync-updates` read-only at
`/updates` by default. Set `HAUNT_SYNC_UPDATES_PATH` to choose another host
directory. For a standalone process, set `HAUNT_SYNC_UPDATES_DIR` to the same
verified release directory.

No service restart is required after a successful import. Keep older release
directories while clients may still be downloading them. Update downloads use
four streaming slots independent from authentication traffic.

## Advertise the mirror through a community

A Haunt community can advertise a Nexus mirror even to desktop users who do not
use sync accounts:

```dotenv
HAUNT_CLIENT_UPDATE_MANIFEST_URL=https://nexus.your-domain.example/client-updates/haunt-updates.json
```

Use the actual stable Nexus address. The community server distributes only the
public manifest location and does not forward authentication tokens.
