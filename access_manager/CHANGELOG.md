# Changelog

## 0.6.0

- Executes a door's configured Home Assistant service directly after successful authentication.
- Adds capability-aware `open`, `unlock`, and `lock` actions for `lock` entities.
- Uses a per-door default action for ordinary fingerprint authentication.
- Lets keypad mappings bind raw action buttons to door actions; credentials remain scoped to `code/tag + button`.
- Accepts an optional action in fingerprint reader events for readers with physical controls or touchscreens.
- Prevents stale access sensor state from operating a door after an add-on restart.
- Reports direct execution success or failure in normalized events and the bounded activity log.

## 0.5.1

- Removes installation-specific users, doors, readers, entity IDs, and credentials from fresh databases.
- Adds a clean first-run path suitable for installations from a public add-on repository.
- Keeps automatic entity discovery only as an explicit compatibility migration for existing installations.
- Adds `aarch64` and `armv7` build targets alongside `amd64`.
- Removes obsolete frontend code and adds automated validation for database migrations and credential handling.

## 0.5.0

- Reorganizes the interface into Users, Fingerprint readers, Keypads, Doors, and Log tabs.
- Uses English by default and adds a persistent English/Spanish language selector.
- Separates physical fingerprint IDs and enrollment controls by reader.
- Treats sleeping Zigbee keypads as configured rather than continuously online.
- Requires every door to reference an actionable Home Assistant entity and open action.
- Adds selectable log retention and a 10,000-entry hard safety limit.
- Links identities to Home Assistant `person.*` entities.
- Stores keypad credentials with keyed HMAC instead of plaintext.
- Emits normalized `access_manager_credential` events for Home Assistant automations.

## 0.4.0

- Adds multiple readers, keypads, doors, and per-reader credential namespaces.
- Persists offline fingerprint deletion requests and retries them after reconnection.
- Stores fingerprint ID, person name, and selected finger locally on compatible ESPHome readers.
- Adds a graphical ten-finger enrollment selector.

## 0.1.0

- Initial administrator panel for fingerprint enrollment, linking, renaming, deletion, and activity history.
