# Pre-release validation

This checklist separates offline regression checks, read-only checks of an existing Home Assistant installation, and tests that require an explicitly approved installation. Do not mark a live test as passed merely because local mocks or the image build succeed.

## 1. Offline regression and upgrade rehearsal

Use the project's validation dependencies, then run from the repository root:

```sh
python -B -m unittest discover -s tests -v
node tests/check_ui.mjs
npm ci --ignore-scripts
npx playwright install chromium
npm run test:browser
python -B tests/rehearse_upgrade.py --baseline-ref v0.15.3
git diff --check
```

The release tag must already exist locally and be trusted. The rehearsal never fetches a revision, installs dependencies, starts the app, or accepts an existing data directory. It loads the release's actual registry implementation from Git and the candidate implementation from the working tree.

The rehearsal creates only temporary synthetic data and blocks socket connections. It checks:

- SQLite integrity and foreign keys after migrating a database created by the released code.
- Preservation of existing people, fingerprint-slot records, readers, doors, personal/shared keypad credentials, settings, and mobile NFC permissions.
- A populated SQLite WAL is included through SQLite's backup API, together with `credential_encryption.key` and `esphome_connection.key`.
- Personal/shared codes and Device Builder credentials remain decryptable after migration and restart; no key or credential value is printed.
- A verified Person entity rename carries the existing grant, without reactivating revoked/suspended permissions or undoing an explicit unlink.
- Restoration of the pre-upgrade snapshot into another temporary directory using the released code, including its encryption keys, original links, and credential decryption.

The output includes the resolved release commit, candidate source hash, and named checks. Temporary databases and keys are removed on exit.

**Limits:** this is a synthetic registry/snapshot test, not a restoration of a user's backup, not a test of Supervisor's hot-backup mechanism, and not a live Ingress or OTA test. It uses the selected local Python runtime, not necessarily the app image's Python version. The hot-backup/WAL consistency item in [TODO.md](../TODO.md) remains open.

The browser suite uses request interception rather than a production backend. It exercises all seven sections at desktop, tablet, and 390/320-pixel mobile widths, with English/Spanish text, keyboard navigation, preserved unsaved forms, connection recovery, concealed credentials, and the approved hand selector. Regression tests additionally verify single execution with repeated/concurrent legacy job followers, cancellation of one observer, terminal handling of a lost legacy process, accurate failed-job status, rejection of duplicate firmware submissions, strict JSON/path and nested reader configuration validation, current/original firmware entity discovery, atomic Person creation, and refusal of new keypad credentials for unverified identities. These checks do not flash hardware.

## 2. Read-only installation preflight

Before choosing an installation target:

1. Discover the installed Access Manager app by name/repository, then record its actual slug, running state, and version privately. A stopped older local app is not a disposable test environment; do not overwrite or start it implicitly.
2. Confirm Home Assistant installation type, Core/Supervisor versions, Ingress availability, and the app's `homeassistant_api` permission. Do not change permissions during preflight.
3. Check that `config/auth/list` returns the fields used by authorization: `id`, `is_active`, `is_owner`, `system_generated`, and `group_ids`. Report only schema/availability and role counts, not account records. Success with the diagnostic connection does not prove the candidate app's own Supervisor token will work.
4. Inspect backup metadata and contents. Confirm the active app, not just an older copy, is included. Record the archive identifier and time privately. Do not download an archive or print its credentials.
5. Check where the recovery copy is stored and, if encrypted, confirm the user has the matching recovery key. An archive listing does not prove SQLite/key consistency or successful restoration.

No changes to HA entities, users, app state, backups, readers, or doors are necessary for this preflight.

## 3. Live Ingress gate

If a separate test Home Assistant is available, use it for the full candidate with synthetic people, readers, and actuators.

If there is only a production Home Assistant, do not silently install the full candidate or start the old local app. Ask for approval for a temporary, separately named, read-only Ingress diagnostic app first. That diagnostic must be prepared/reviewed before installation and must:

- Exercise the candidate's same TCP-peer check and administrator authorization code through actual Supervisor Ingress.
- Have its own slug/data directory, no shared data mounts or exposed host ports, and no Access Manager registry or production database.
- Restrict its HA requests to the authorization lookup. Do not run the Access Manager startup tasks, event subscriptions, deletion queue, credential handlers, Device Builder jobs, or door actions.
- Show only pass/fail/status information; never display tokens, Ingress session identifiers, full account lists, or credentials.
- Test an existing administrator/owner session and, with the user's cooperation, an existing non-administrator session. Do not create accounts, change roles, or disable authentication merely to complete the test.
- Leave Home Assistant running; authorization-outage and revocation fault injection remains local. Do not stop production Core or revoke a real user's role to manufacture a failure.

Expected results: an active human administrator/owner reaches the diagnostic, a non-administrator is rejected, and requests outside the trusted Ingress path do not bypass authorization using forged headers. Follow Home Assistant's [Ingress network requirements](https://developers.home-assistant.io/docs/apps/presentation/#ingress) and [user-identity contract](https://developers.home-assistant.io/docs/apps/security/#authenticating-a-user-when-using-ingress).

### Prepare the temporary diagnostic locally

```sh
python -B -m unittest discover -s tests -p test_ingress_diagnostic.py -v
python -B tools/prepare_ingress_diagnostic.py
```

The generator creates a fresh temporary directory and reports its path. `--output NEW_DIRECTORY` is optional and refuses an existing target. It does not connect to Home Assistant, install an app, build an image, or change the production app. The repository contains the generator, not a second automatically discoverable app.

The package contains `config.yaml`, `Dockerfile`, `diagnostic.py`, and `review.json`. Review records the exact candidate source hash and generated file hashes. Regenerate and re-test after candidate authorization changes. The generator extracts the candidate's peer check, role resolution, WebSocket exchange/time limits, and authentication middleware without importing or starting `main.py`. Regression tests compare their syntax trees for parity. The diagnostic's client adds an allowlist for exactly `config/auth/list`; HTTP write methods are rejected before contacting HA.

It has a distinct slug (`access_manager_ingress_diagnostic`), manual boot, no shared mounts, no host ports, no Supervisor/Docker management API permission, and no database payload. `homeassistant_api: true` is required for authorization: this is a technically privileged token, **not** a platform-enforced read-only token. Read-only scope is enforced by the reviewed code and command allowlist, not by claiming that the token cannot mutate HA. The token and account records are never returned or logged. Access logs are disabled to avoid recording Ingress URLs or identities.

`panel_admin: false` intentionally allows a normal user's session to reach the temporary diagnostic so the candidate's own authorization can reject it; it does not grant that user access. Production Access Manager retains its existing admin-only panel setting. The two read-only routes are `/` (bilingual result page) and `/health` (sanitized status plus candidate hash), both protected by the same candidate authorization gate. There are no form actions, automatic jobs, subscriptions, reader commands, or door controls.

After a separate installation approval, first verify the diagnostic slug does not already exist. Copy only this reviewed package to a newly named local-app directory, install/start only that diagnostic, and leave the active and stopped Access Manager apps unchanged. Open its UI through HA, check administrator success, and ask the user to check rejection with an existing non-administrator session if available. No account creation, role modification, HA restart, physical action, or simulated production outage is needed. When finished, request approval to stop/uninstall only this diagnostic and remove only its exact temporary source directory; do not touch Access Manager's data or other local apps.

The diagnostic validates the Ingress/authentication path only. It does not validate the full panel, production data migration, reader isolation on physical devices, or OTA. Local tests alone do not build or run its image under Supervisor; installation and later removal need explicit approval.

### Approved diagnostic installation check (2026-10-15)

After explicit user approval, only `local_access_manager_ingress_diagnostic` was installed and started, with manual boot, no host port bindings, and its own data directory. The candidate authorization source hash was `5fe9ddc9cc7086d424ecd451342c0319d5554ca3945df0caddfc89d33301611e`.

The first startup failed because a direct Python command did not receive the container environment preserved by s6. The package now starts through `/usr/bin/with-contenv`, as required for that environment; a package regression assertion checks this command. No token fallback, copied credential, or authentication bypass was introduced. The diagnostic was rebuilt and started successfully after this isolated correction.

Verified on the running diagnostic: its own token can perform `config/auth/list` with the expected response schema, a direct loopback GET with forged identity/forwarding headers returns 403, and an HTTP POST returns 405. Tokens, identity records, and Ingress session paths were not printed. The existing Access Manager and Home Assistant container IDs/start times remained unchanged, the active Access Manager source/UI hashes remained unchanged, and all previously installed apps retained their reported state/version.

The user subsequently confirmed the actual administrator session displayed the authorized result. For an existing non-administrator account, Settings was unavailable and the direct diagnostic URL returned `{"ok": false, "result": "denied"}`. These session observations are user-reported, not an automated browser check by the agent.

After explicit removal approval, a partial backup containing only the diagnostic was created and verified by metadata, without Home Assistant settings or other apps. The diagnostic was stopped and uninstalled. Its four hash-verified generated source files were moved out of the local app store to a recoverable temporary location; the generator remains in this repository. The diagnostic is absent from both installed apps and store discovery. Other app versions/states, Access Manager source/UI hashes, and the existing Access Manager/Home Assistant container IDs/start times remained unchanged. No backup was restored or deleted.

**Still pending:** full-candidate panel/integration validation and a consistent recovery plan for the active Access Manager. The isolated diagnostic results do not establish full-candidate Ingress success, restore safety, or physical OTA behavior.

## 4. Private online data recovery bundle

`tools/snapshot_registry.py` is a separate, explicitly invoked maintenance tool. It does not change app code/configuration, import the application, run migrations/startup jobs, send HA requests, or provide a live-restore command. Never run it against real data without backup approval.

```sh
python -B -m unittest discover -s tests -p test_registry_snapshot.py -v
python -B tools/snapshot_registry.py --source /path/to/active/data --destination /path/to/new/private/bundle
python -B tools/snapshot_registry.py --verify-only --destination /path/to/private/bundle
```

Use the application's own container/runtime for the snapshot, and keep the new destination outside active data. It refuses an existing destination and uses a read-only source connection with SQLite's online backup API, not a raw copy of a live database/WAL. The destination database is finalized as a standalone file. Existing credential keys and `options.json` must stay byte-identical across the snapshot; no missing key is generated. Only keys that actually exist are copied. Previous backups and obsolete database copies are not part of the active recovery payload.

The tool checks SQLite integrity and foreign keys, decrypts existing encrypted personal/shared keypad credentials without printing values, verifies their HMAC hashes, and checks the encrypted Device Builder token when present. It reconstructs/reopens another offline copy before publishing a success manifest. A deadline or any verification failure leaves no valid manifest. Local regression tests include a write committed during copying, changed keys/options, a missing key, a modified bundle, an existing target, a timeout, and a failed reconstruction.

The bundle contains `data/`, a separate `reopened/` copy, and `manifest.json` with file hashes and sanitized verification results. Directories use mode 0700 and files 0600. **The bundle contains the encryption keys alongside the database and is not an encrypted archive:** treat the whole directory as sensitive. Do not download it into a repository, expose it through a shared directory, or copy it off-host without an agreed secure destination.

### Approved data snapshot check (2026-10-15)

For the active app at version 0.15.3, an initial read from the Supervisor container returned `SQLITE_BUSY` and hit the bounded timeout; that incomplete attempt was explicitly marked invalid. The same read and online backup succeeded from the application's own container. The underlying difference between those contexts was not established, and no lock mode or source database setting was changed.

The verified data bundle was copied entirely within the HA host to a new private, persistent recovery directory and verified again there. Integrity and foreign keys passed; all encrypted keypad credentials decrypted and matched their stored hashes. The private manifest records actual row counts without including personal values in public documentation. No encrypted Device Builder token/key was present, so none was created. The private recovery metadata records the original app version/image and source/UI hashes. All app states/versions and the Access Manager/Home Assistant processes remained unchanged.

This is a manual application-data recovery point, **not** a Supervisor-restorable backup visible in the backup UI. Reopening the copied database is not a live application restore. It remains on the same HA storage, so it does not cover loss of that host/disk; an approved secure off-host destination is still needed for that risk. Before any data replacement, agree to the required app-only interruption, preserve newer data, verify this bundle again, restore only this app's matching database/keys/options, and start only the approved compatible app version. Do not provide an automatic production restore as a test. Restoring a Supervisor archive remains a different operation with separate approval.

## 5. Approved full update and recovery

After the offline and Ingress gates pass, arrange a separate approval/maintenance window for the actual update:

1. Take a fresh, consistent, recoverable backup of the active app and its complete data/key set before replacing it. Do not treat the existing unverified hot-backup mode as sufficient evidence of consistency. If stopping Access Manager is needed for a cold copy, agree to that brief access-management interruption first; do not stop Core or unrelated apps.
2. Record the previous app version and the exact recovery archive privately. Recovery should restore Access Manager and its data only where supported, not revert unrelated HA changes. An actual restore needs its own explicit approval.
3. Deploy the approved app candidate. Do not update reader firmware as part of this test.
4. Check panel access on desktop/mobile, data counts, existing identity links, credential availability without disclosing values, and separately configured readers. Do not unlock a physical door or alter a real Person just to test the update.
5. Test rename/relink behavior only with approved synthetic identities and a non-physical test actuator. Search consumers first, and do not reuse real credentials or permission grants.
6. If authentication or migration fails, stop validation and use the approved recovery plan; never bypass the security check, guess Person IDs, delete the database, or overwrite a migrated live database with older code.

Record local, read-only preflight, live Ingress, full-update, and physical-device results separately. Follow [RELEASING.md](../RELEASING.md) for publication; this checklist grants no permission to push, publish, install, restore, or flash.
