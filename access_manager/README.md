# Access Manager

Access Manager is an administrator-only Home Assistant add-on for managing people, doors, fingerprint readers, Zigbee/MQTT keypads and their credentials outside Lovelace.

## Highlights

- Links every local identity to a Home Assistant `person.*` entity.
- Manages several fingerprint readers with independent physical ID spaces.
- Captures keypad credentials as `code/tag + action button` combinations.
- Stores keypad secrets as keyed HMAC digests, never as plaintext.
- Requires each door to reference an actionable Home Assistant entity.
- Emits one normalized `access_manager_credential` event for automations.
- Provides English and Spanish interfaces.
- Applies configurable, time-based log retention and a 10,000-row safety cap.

Fresh installations start empty. No user, reader, door, entity ID, network address or credential is bundled.

Fingerprint templates remain inside each physical sensor. Access Manager stores only identity metadata, reader mappings and protected keypad credential digests in `/data`.

Full installation and configuration documentation is available in the repository root.
