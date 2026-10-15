# Project TODO

## Local changes awaiting release validation

This audit batch is implemented locally and the full candidate has not been published or deployed. Only the separately approved, isolated Ingress diagnostic was installed, checked, and subsequently removed with approval; existing Access Manager data/configuration, Home Assistant Core, and physical readers have not been changed.

- [x] Enforce real Ingress/admin authorization for the panel and every HTTP route; treat `X-Fingerprint-Admin` only as a same-origin marker. Deny direct peers, forged identity headers, non-admin users, and failed authorization checks.
- [x] Scope reader autodetection to the intended device, including legacy readers, firmware verification, and live display-language actions. Do not select an unrelated globally available entity or confirm an OTA from a stale state after a failed refresh.
- [x] Persist Home Assistant's stable Person ID, resolve renamed entities, and preserve NFC permission references only for the same verified identity. Keep revoked/suspended permissions unchanged, and require confirmation when relinking to a different Person.
- [x] Add regression coverage for authorization, legacy registry migration, renamed/reused/ambiguous identities, NFC fail-closed behavior, and cross-reader detection.
- [x] Prepare and run a release-based offline upgrade/restore rehearsal from `v0.15.3`, with synthetic SQLite/WAL data, encryption keys, personal/shared credentials, and NFC permission states. This is not a restore of a production backup and does not close the hot-backup consistency item.
- [x] Complete read-only installation preflight: verify installed-app identity/version, the authorization response schema, and that recent backup metadata includes the active app. No app, user, entity, or backup was changed; recovery and the candidate app's actual Ingress path are still unverified.
- [x] With only one Home Assistant installation available, obtain separate approval before installing the read-only Ingress diagnostic. Approval was given and only the diagnostic was installed/started on 2026-10-15; the old local app and active Access Manager were not changed. Follow [Pre-release validation](docs/validation.md).
- [x] Prepare a separate, manually started Ingress diagnostic locally using the candidate's authorization code, a single-command HA allowlist, no production imports/data or physical handlers, sanitized results, and offline regression tests. Package generation itself does not build, install, or start it; subsequent approved installation is recorded separately below.
- [x] Build/start the separately approved diagnostic and verify its own authorization lookup, direct-peer rejection, and write rejection, with no change to existing app versions/states or Access Manager/Home Assistant processes. Correct its s6 environment startup without weakening authorization.
- [x] The user confirmed actual administrator Ingress access and non-administrator rejection through the direct URL. After separate approval, back up only the diagnostic, stop/uninstall it, and move its verified source out of the store to a recoverable temporary location. Confirm the diagnostic is absent and all other apps keep their reported versions/states, with unchanged Access Manager/Home Assistant processes. Full-candidate installation, migration and physical OTA remain separate gates.
- [x] With separate approval, create a private, persistent recovery bundle of the active app data using a read-only SQLite online backup from its own container. Verify integrity/foreign keys, matching credential hashes/decryption, stable keys/options, file hashes, private permissions, and reopening a separate offline copy. Keep it on the HA host; no live restore, external download, Supervisor-restore test, app restart or update was performed.
- [ ] Validate against a real Home Assistant test installation before publication: administrator access through Ingress, rejection of a non-admin, authorization outage/recovery, a backed-up registry upgrade, Person rename/relink, and two independent readers.
- [ ] After approval and the integration checks, publish and deploy as separate steps. Version/changelog preparation is local only; local HTTP tests use simulated Ingress and Home Assistant responses, not the production installation.

## Release candidate 0.16.0 (local only)

- [x] Align the app manifest, panel build, and latest English changelog heading at `0.16.0`; check consistency automatically instead of pinning tests to the previous version.
- [x] Pass 149 Python tests, 36 offline upgrade/restore checks from `v0.15.3`, and browser checks for all seven sections at four screen sizes. YAML, Python syntax, UI structure, and `git diff --check` also pass.
- [x] Audit the candidate file list for private databases/keys/tokens and installation-specific paths/addresses. Do not copy real recovery data into the repository.
- [x] Add offline upgrade rehearsal to CI with the required release history. Keep reader firmware at `0.6.3`; firmware sources and approved photographic assets are unchanged.
- [x] Obtain approval to push the candidate branch/open review. The user authorized submission for CI/review only; merging, tagging, publishing the release, and updating the installed app remain separate steps.
- [ ] Run the complete remote CI, including the app image build and both firmware examples. The local environment has neither Docker nor ESPHome compiler; these builds have not been verified here.
- [ ] Complete the remaining full-candidate integration/recovery gates, approve the brief public release notes, then merge/tag/publish only after the checks pass. Updating Home Assistant's app remains separately authorized.

## Reliability and compatibility

- [x] Improve the panel locally: compact responsive layout, searchable/paged people, recent-event filters, mobile credential expansion, stable menus during polling, clear connection status, keyboard tabs, and dialog focus management.
- [x] Correct free fingerprint-slot selection and preserve a valid user-selected slot during polling. Re-enable enrollment controls after mutations.
- [x] Harden backend inputs and persistence: reject malformed/scalar JSON, invalid numeric path IDs, and non-boolean flags; create a linked Person atomically; require a confirmed Person link when adding new physical credentials.
- [x] Guard firmware submissions across pending/running operations for the same configuration; deduplicate followers and bound Home Assistant request/response waits.
- [ ] Make Supervisor-managed hot backups SQLite/WAL-consistent, including the credential encryption material. A separately tested manual data snapshot tool now exists; this does not prove the current `backup: hot` archive/restore path is consistent or register the custom bundle as a Supervisor backup.
- [x] Make legacy ESPHome Dashboard `firmware/follow_job` observational and idempotent. Explicit submissions start one cached operation; repeated/concurrent followers observe it. Cancelling an observer does not cancel its process. Lost jobs after restart fail with a manual-review message rather than spawning again. Tested with simulated sockets; a real OTA remains a separate validation step.
- [x] Normalize the newer Device Builder nested `runtime_state.state` response alongside legacy flat responses, without exporting private runtime fields.
- [x] Support current English and original Spanish firmware entity names during device-scoped legacy discovery; reject invalid nested reader configuration and preserve failed process status in legacy job listings.
- [x] Add reproducible browser checks and a dedicated CI job; derive CI image build metadata from the app manifest instead of the stale `0.14.0` value.
- [ ] Refresh the CI compatibility matrix and dependency checks for supported Home Assistant, Python, ESPHome, and Device Builder versions. Firmware compilation CI still pins ESPHome `2026.7.0`; current review does not claim a newer physical firmware build.
- [ ] Gradually split authorization, person/credential storage, and Device Builder transport out of the large application module, preserving the tested behavior.
- [ ] Add a per-reader operation queue to coordinate enrollment/deletion with explicit progress, cancellation, and recovery semantics for sensors that can perform only one physical operation at a time.
- [ ] Consider backend activity pagination/export when retained history exceeds the panel's most recent 200 entries, plus full API schemas and localized structured errors.

## Reader update notifications

- [ ] Separate reader firmware update notices from ESPHome framework updates.
  - Reported on 2026-09-08: updating ESPHome repeatedly produces an update notice for a managed reader even when its Access Manager firmware release has not changed.
  - Keep the reader's own firmware version and update status separate from the ESPHome version used to build it.
  - Provide a documented, optional way to suppress the Home Assistant ESPHome-generated update entity for managed readers, without disabling their firmware-version sensors or unrelated devices' updates.
  - Preserve manual compilation and OTA through Access Manager and ESPHome Device Builder, and keep reader-release notices available in Access Manager.
  - Make the setup repeatable across installations; do not hardcode a particular reader entity ID or silently change Home Assistant configuration.
  - Explain that suppressing the generic entity also hides ESPHome maintenance/security update notices for that reader; these updates still require periodic review.
  - Verify that an ESPHome-only version change does not produce a reader-release notice, while a newer supported reader firmware release still does.

Notification status: pending. No Home Assistant entity, firmware, or notification setting has been changed. Handle this as a separate, explicitly approved configuration/design step.
