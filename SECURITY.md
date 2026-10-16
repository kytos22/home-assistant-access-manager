# Security policy

Please report security issues privately through GitHub's security advisory feature. Do not open a public issue containing credentials, access codes or Home Assistant diagnostics.

Access Manager does not store keypad codes or tags as plaintext. It stores a per-installation keyed HMAC digest and a short masked hint. Fingerprint templates remain in the physical fingerprint sensor.

## Panel authorization

The panel, API, static assets, and health route are only accessible through Home Assistant Ingress. Access Manager verifies the actual TCP peer against the documented Supervisor proxy address (`172.30.32.2`); forwarding headers cannot grant access. This is the standard Supervisor address, not a reader or installation-specific LAN address.

The Ingress-provided `X-Remote-User-Id` must identify an active, non-system Home Assistant administrator or owner. Privileges are checked through Home Assistant's `config/auth/list` WebSocket command for each request; missing identity or insufficient privileges are rejected with HTTP 403. If that check fails or times out, access is rejected with HTTP 503. No cached administrator grant or direct-port fallback is used.

`X-Fingerprint-Admin: 1` remains a same-origin request marker for mutations and credential-reveal requests, not an authentication credential. Do not expose port 8099 or add a reverse proxy that bypasses Supervisor's Ingress authentication. The app does not enable cross-origin API access.

References: [Ingress network requirements](https://developers.home-assistant.io/docs/apps/presentation/#ingress), [Ingress user identity](https://developers.home-assistant.io/docs/apps/security/#authenticating-a-user-when-using-ingress).

## Temporary Device Builder delegation

Local Device Builder access uses the administrator's existing Home Assistant frontend connection to discover ESPHome and request a temporary Ingress session. The panel never reads a Home Assistant access token. It keeps the returned bearer capability only in JavaScript memory, for at most four minutes before renewal, and discards its cache when hidden/unloaded, disconnected, or rejected. The Supervisor controls the actual session lifetime independently.

Only Device Builder requests carry the capability to Access Manager. The existing trusted-peer and current-human-administrator gate runs first. A separate middleware rejects partial/duplicate/malformed headers, a user identifier different from the verified Ingress identity, and headers on unrelated routes. The capability is scoped with a `ContextVar` to that request and its explicitly spawned jobs, reset in `finally`, and never written to options, databases, keys, logs or public responses. Completed legacy jobs release their transport/session/task references; only non-sensitive status is shared. Other requests and startup tasks cannot borrow a user's session.

Custom headers are not authentication and a bearer capability is not proof of its creator's identity. Supervisor validates the actual Ingress session and its user's privileges. Access Manager additionally rechecks the originating user's current administrator rights before each new remote operation. The browser obtains the selected app's metadata through its authenticated Home Assistant connection; only the bounded, strictly validated app/Ingress fields are delegated, never options or arbitrary URLs. These administrator-supplied fields are not cryptographically attested metadata: the real Supervisor Ingress session and the supported ESPHome protocol remain the upstream checks. The backend sends **no** `supervisor/*` commands through its system-user proxy, including metadata reads, because Supervisor explicitly blocks that entire prefix. The explicit **Start Device Builder** button uses the browser administrator connection instead; it never runs on page load.

Expired or rejected sessions fail closed. No rejected write, compile or install is automatically resent. A job already accepted may continue while the panel is closed, but new remote operations require current authorization; interrupted jobs require review. This mechanism does not enable `hassio_api`, grant manager/admin roles, expose a port, or install another compiler. Its local tests use simulated HA/ESPHome responses, not production credentials; live validation requires a separately approved candidate deployment.

References: [Supervisor app-proxy command restrictions](https://github.com/home-assistant/supervisor/blob/main/supervisor/api/proxy.py), [HA Supervisor WebSocket authorization and session identity](https://github.com/home-assistant/core/blob/2026.10.0/homeassistant/components/hassio/websocket_api.py), [Supervisor Ingress validation](https://github.com/home-assistant/supervisor/blob/main/supervisor/api/ingress.py).

## Person identity and mobile NFC

Home Assistant Person storage IDs and entity IDs are different identifiers. Access Manager stores the stable Person ID and resolves its current `person.*` entity through the state's `id` attribute. A verified entity rename preserves the local identity and updates existing NFC permission references without enabling revoked or suspended permissions.

A different Person reusing an old entity ID does not inherit its permissions. Missing, ambiguous, or unverified associations deny mobile NFC access. An explicit relink to a different Person suspends existing enabled permissions until an administrator confirms them again. Existing links learn their stable ID on the first verified reconciliation; a legacy link already renamed or missing before this migration needs explicit review and relinking.

## Reporting

Never include any of the following in an issue or pull request:

- Home Assistant access or Supervisor tokens
- ESPHome API encryption keys or OTA passwords
- Wi-Fi credentials
- Real keypad codes or tag values
- `/data` databases from a live installation
