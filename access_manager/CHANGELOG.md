# Changelog

## 0.8.0

- Fixes keypad enrollment for devices that publish code/tag only together with an action by assembling transaction, code, and action before consuming the packet.
- Adds an Automations tab for native Home Assistant auto-lock rules with 5, 10, 15, 20, 30, and 60 minute delays.
- Limits auto-lock rules to `lock.*` door entities and verifies that the lock is still unlocked before calling `lock.lock`.
- Protects unrelated Home Assistant automations with a local registry plus configuration ID, alias, and description ownership checks.
- Adds bilingual automation editors, enable/disable controls, status, deletion confirmation, and bounded activity-log entries.

## 0.7.0

- Replaces native browser dialogs with accessible, validated editors for people, readers, keypads, and doors.
- Redesigns doors as aligned cards and adds capability-aware test actions with an explicit safety confirmation.
- Adds visual keypad button mappings and a 60-second physical button detection mode.
- Keeps identity in Access Manager: each keypad credential links a person to a specific `code/tag + raw button`, while the keypad remains a simple input device.
- Makes the keypad's current button mapping authoritative, so remapping a button changes existing credentials immediately.
- Ignores and logs unmapped keypad buttons without attempting an unknown door action.
- Accepts unauthenticated display actions only for `lock`, executes them through the associated reader and door, and prevents duplicate sequence execution.
- Emits `access_manager_door_action` and records local-lock and administrator-test outcomes in the bounded activity log.

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
