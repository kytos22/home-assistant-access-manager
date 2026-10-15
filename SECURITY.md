# Security policy

Please report security issues privately through GitHub's security advisory feature. Do not open a public issue containing credentials, access codes or Home Assistant diagnostics.

Access Manager does not store keypad codes or tags as plaintext. It stores a per-installation keyed HMAC digest and a short masked hint. Fingerprint templates remain in the physical fingerprint sensor.

## Panel authorization

The panel, API, static assets, and health route are only accessible through Home Assistant Ingress. Access Manager verifies the actual TCP peer against the documented Supervisor proxy address (`172.30.32.2`); forwarding headers cannot grant access. This is the standard Supervisor address, not a reader or installation-specific LAN address.

The Ingress-provided `X-Remote-User-Id` must identify an active, non-system Home Assistant administrator or owner. Privileges are checked through Home Assistant's `config/auth/list` WebSocket command for each request; missing identity or insufficient privileges are rejected with HTTP 403. If that check fails or times out, access is rejected with HTTP 503. No cached administrator grant or direct-port fallback is used.

`X-Fingerprint-Admin: 1` remains a same-origin request marker for mutations and credential-reveal requests, not an authentication credential. Do not expose port 8099 or add a reverse proxy that bypasses Supervisor's Ingress authentication. The app does not enable cross-origin API access.

References: [Ingress network requirements](https://developers.home-assistant.io/docs/apps/presentation/#ingress), [Ingress user identity](https://developers.home-assistant.io/docs/apps/security/#authenticating-a-user-when-using-ingress).

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
