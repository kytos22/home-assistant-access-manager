# TODO

## Access Manager person lifecycle

The lifecycle must keep physical access safe without treating a temporary Home Assistant outage as a deletion. Unlinking is non-destructive; deleting is explicit, staged, and auditable.

### 1. Link health and reconciliation

- [x] Reconcile linked identities against the authoritative Home Assistant `person/list` response and track when that response was last refreshed successfully.
- [x] Expose an explicit link state for every local identity: `linked`, `missing`, `unknown`, or `unlinked`. Mark a link `missing` only after a fresh successful response; use `unknown` when Home Assistant or the People API is unavailable.
- [x] Make an explicit unlink persistent. Replace unconditional name-based auto-linking with a migration-safe rule or stored opt-out so an unlinked identity is not silently linked again on the next state refresh.

### 2. Unlinking, relinking, and mobile NFC

- [x] Add explicit **Unlink from Home Assistant** and **Link/Re-link to Home Assistant** actions. Preserve the local identity, fingerprints, and keypad credentials when unlinking, and allow local repair operations even if the old Home Assistant Person is missing.
- [x] Allow new mobile-NFC permissions only for a freshly confirmed `linked` identity, enforcing the rule in both the UI and backend. Keep existing permissions visible when a link is missing or unknown so the administrator can understand and repair them.
- [x] Do not transfer mobile-NFC authorization silently to a different Home Assistant Person after relinking. Suspend affected permissions until the administrator explicitly confirms or recreates them.

### 3. Deleting a local identity

- [x] Add a dependency preview and explicit confirmation showing fingerprints by reader, personal keypad credentials, and mobile-NFC permissions before deletion starts.
- [x] Introduce a durable `deletion_pending` lifecycle state. Deny new access for that identity while deletion is in progress and prevent new credentials or permissions from being assigned.
- [x] Revoke personal keypad credentials and mobile-NFC permissions, then queue every fingerprint deletion through the existing per-reader confirmation flow. Keep offline readers visible as recoverable blockers and retry safely after restarts.
- [x] Archive the local identity only after every fingerprint reader has confirmed deletion. Preserve the minimum identity metadata required for audit history instead of silently orphaning templates or hard-deleting evidence.
- [x] Enforce dependency cleanup consistently in SQLite, either through an explicit transactional cleanup path or a tested foreign-key migration with `PRAGMA foreign_keys = ON`.

### 4. Audit and verification

- [x] Record link, unlink, relink, deletion request, credential revocation, blocked deletion, retry, and completed archival events without logging credential values.
- [x] Cover fresh and stale People data, API outages, explicit unlink persistence, relinking, suspended NFC permissions, offline fingerprint readers, partial cleanup, restart recovery, and completed archival with backend and UI tests.

### 5. Mobile usability

- [x] Make the administration panel fully responsive and easy to navigate on phones: prevent horizontal overflow, provide compact and clear tab navigation, keep touch targets comfortably sized, adapt tables into readable mobile layouts, and ensure forms, confirmations, and modals remain usable without zooming or losing context.
