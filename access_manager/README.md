# Access Manager

Access Manager is an administrator-only Home Assistant add-on for managing people, doors, fingerprint readers, Zigbee/MQTT keypads and their credentials outside Lovelace.

## Highlights

- Links every local identity to a Home Assistant `person.*` entity.
- Manages several fingerprint readers with independent physical ID spaces.
- Registers keypad `code/tag` credentials through physical capture or protected manual entry, independently from the requested keypad action.
- Uses keyed HMAC digests for keypad matching and authenticated encryption for recoverable credential display.
- Offers privacy-by-default temporary reveal and a warned administrator-only mode that keeps credentials visible without storing them as plaintext.
- Requires each door to reference an actionable Home Assistant entity.
- Directly executes the capability-checked door action after authorization.
- Supports a per-door default plus fingerprint/keypad `open`, `unlock`, and `lock` requests.
- Emits one normalized `access_manager_credential` event for automations.
- Provides English and Spanish interfaces.
- Shows the installed app version in the header.
- Creates guided native auto-lock, door-left-open, and denied-access rules with one rule of each type per door.
- Exposes `warning`, `info`, and `debug` application log levels in the Home Assistant app configuration; routine HTTP request logging remains disabled.
- Applies configurable, time-based log retention and a 10,000-row safety cap.

Fresh installations start empty. No user, reader, door, entity ID, network address or credential is bundled.

Fingerprint templates remain inside each physical sensor. Access Manager stores identity metadata, reader mappings, protected keypad credential digests, and encrypted recoverable credential values in `/data`.

Full installation, supported-device and configuration documentation is available in the [repository README](https://github.com/kytos22/home-assistant-access-manager#readme).
