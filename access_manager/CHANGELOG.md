# Changelog

## 0.15.3

- Replaces the drawn finger selector with a photographic pair of real hands while retaining ten keyboard-accessible hit areas; selected and registered overlays are alpha-masked to the exact photographic silhouette of each finger.

## 0.15.2

- Recommends reader firmware 0.6.3, which translates all ten stored finger positions according to the live English/Spanish display selection.
- Points the panel header directly to the structured project documentation and adds documentation coverage checks.

## 0.15.1

- Restores the official multiplexed `/ws` protocol for the current ESPHome Device Builder, fixing `405 Method Not Allowed` when creating or updating a YAML, while retaining the HTTP/process API as an automatic fallback for legacy Dashboard installations.
- Recommends reader firmware 0.6.2, which explicitly publishes its diagnostic version entity during every boot so managed OTA verification no longer remains `unknown`.
- Detects the firmware-version and display-language entities for each configured ESPHome device when the match is unambiguous, so the reader editor no longer leaves the language field empty or cross-links multiple readers.
- Separates reusable ESPHome secret-key names from reader-specific settings, saves those environment defaults only on explicit request, and fixes every Device Builder YAML name to `<device_name>.yaml` in both the read-only panel field and server validation.
- Moves Device Builder and the ESPHome reader configurator beneath the fingerprint-reader controls, keeps Settings focused on general options, and adds a prominent link to the repository documentation.
- Compacts the users-and-credentials list with denser credential badges, concise status rows, two visible credential shortcuts, and an on-demand management menu for less frequent identity actions.

## 0.15.0

- Replaces the obsolete local Ingress WebSocket protocol with the current ESPHome Device Builder API: device and YAML operations use its Ingress HTTP endpoints, while validation, compilation and OTA use its native process WebSockets.
- Keeps the integration local and ephemeral through Home Assistant Supervisor Ingress. Access Manager requests only secret-key names from ESPHome and never reads `secrets.yaml` values.

## 0.14.3

- Fetches the detailed ESPHome Device Builder app record before opening Ingress, so the local connection receives the Supervisor-provided Ingress entrypoint instead of treating the summary listing as incomplete configuration.

## 0.14.2

- Fixes the local Device Builder connection on current Home Assistant releases by using the Supervisor WebSocket `endpoint` field required for app discovery and Ingress sessions.

## 0.14.1

- Connects to the local ESPHome Device Builder automatically through Home Assistant Supervisor and Ingress, without exposing a dashboard port or requesting a URL/token.
- Keeps external Device Builder configuration under advanced settings; a username/password login is used only to obtain an encrypted token and neither credential is retained.
- Adds a two-step managed firmware update that verifies the canonical YAML hash, changes only the immutable Access Manager package `ref`, validates, compiles, installs by OTA, and verifies the reported firmware version after reconnecting.
- Protects custom and newer firmware refs, checks required secret-key metadata without reading secret values, and records restart-safe update jobs, bounded diagnostics, and firmware audit events.

## 0.14.0

- Removes the experimental bundled ESPHome compiler and writable shared-configuration mapping.
- Adds an optional authenticated Device Builder `/ws` connection with encrypted-at-rest bearer tokens.
- Maps each reader to its exact Device Builder configuration, blocks device-name/filename collisions, and requires version history plus explicit overwrite confirmation.
- Persists remote compile/install operations and follows Device Builder job progress while retaining manual YAML generation and import.
- Stores a per-reader firmware profile and lets each installation choose its existing ESPHome secret key names without exposing their values.
- Maintains the ESPHome reader source under this repository's `esphome/` directory and pins generated wrappers to unambiguous `firmware-vX.Y.Z` tags.

## 0.13.1

- Makes firmware creation and OTA updates work immediately with the standard ESPHome add-on, without exposing a dashboard port or configuring a URL.
- Uses a bundled ESPHome compiler with the shared Home Assistant ESPHome directory, preserving all secret values in ESPHome's existing `secrets.yaml`.
- Keeps the dashboard URL as an optional advanced override for external ESPHome installations.

## 0.13.0

- Shows whether each fingerprint reader has a display and sensor or only a sensor.
- Changes compatible display readers between English and Spanish from the panel.
- Creates and compiles managed reader configurations directly in ESPHome Device Builder.
- Adds confirmed one-button OTA firmware updates with live progress and errors.
- Keeps Wi-Fi, API-encryption, and OTA secret values inside ESPHome.

## 0.12.2

- Updates generated reader configurations to Fingerprint Access Reader 0.5.2, which publishes its installed version during boot.
- Distinguishes a configured firmware sensor that has not reported yet from a reader without firmware-version configuration.

## 0.12.1

- Updates generated ESPHome reader configurations and firmware status to Fingerprint Access Reader 0.5.1, which fixes fresh compilation of the release-pinned display profile.

## 0.12.0

- Adds clear Home Assistant Person link health, explicit unlink and relink controls, and guided repair when a linked Person is missing or unavailable.
- Adds staged identity deletion with a dependency preview, immediate credential revocation, per-reader fingerprint cleanup, restart recovery, progress, and blocker visibility.
- Protects mobile NFC access during identity changes by suspending affected permissions until an administrator explicitly confirms them again.
- Makes the administration panel phone-friendly with compact section navigation, touch-sized controls, responsive table cards, and usable mobile confirmations and modals.

## 0.11.0

- Adds reader-scoped shared keypad codes and tags with encrypted storage, privacy-aware reveal, physical or manual capture, duplicate prevention, revocation, and clear audit labels.
- Replaces the mobile NFC permission matrix with a compact active-permissions list, guided user/tag assignment, door filtering, and direct revocation.
- Expands the ESPHome configurator with separate new-device and existing-device update guidance, safer credential-preservation instructions, and a documented recovery path.
- Strengthens administration-panel update recovery with version-verified cache busting, fresh document responses without file validators, and retryable stale-build replacement.

## 0.10.0

- Adds a bilingual ESPHome configurator for the reference display terminal and generic ESP32 fingerprint-reader-only installations, using release-pinned packages without collecting Wi-Fi, API or OTA secrets.
- Adds reader firmware version reporting and installed-versus-recommended status in the fingerprint-reader list.
- Prevents stale administration panels with explicit no-cache document responses, no-store API requests and a build-version reload guard.
- Records both opening and closing transitions for configured locks and physical door sensors, including changes made manually or by Home Assistant automations.
- Replaces ambiguous activity details with structured door, entity, transition and source labels.
- Moves mobile NFC authorization to Users & credentials, where fixed door tags are assigned to allowed users while preserving authenticated Home Assistant identity checks.

## 0.9.0

- Adds Home Assistant mobile-app NFC door access using its registered Tag list, with tag-to-door mapping, explicit person-to-door permissions, authenticated user and scanner resolution, activity logging, duplicate-scan protection, and a responsive administration view.
- Adds optional door-assignment and display-event entities for compatible fingerprint readers, with door-scoped feedback for successful opens, keypad capture, and denied keypad credentials.
- Assigns an optional Home Assistant door contact sensor directly to each door and reuses it as the default in managed automations.
- Records lock openings and physical door openings even when they happen outside Access Manager, with structured door, entity, state transition, and source fields.
- Correlates recent Access Manager lock commands with Home Assistant state changes so they are not mislabeled as external activity.

## 0.8.3

- Captures short-lived keypad transaction, code/tag and action entity updates before Zigbee2MQTT clears them to empty or unknown states.
- Adds guided native Home Assistant automations for door-left-open and denied-access alerts alongside auto-lock.
- Allows one automation of each type per door, with configurable delays, denied-attempt thresholds and time windows.
- Sends alerts through a selected Home Assistant `notify.*` entity or a persistent notification that requires no additional setup.

## 0.8.2

- Treats a keypad code or tag as the credential and keeps the accompanying semantic action separate, so one credential works with every mapped keypad action.
- Adds protected manual code/tag entry while preserving leading zeroes and opaque tag values such as `+0A1B2C3`.
- Keeps existing action-scoped keypad credentials working until they are replaced with the new credential format.
- Encrypts recoverable keypad credentials at rest and adds privacy-by-default temporary reveal plus a warned no-privacy panel mode that keeps them visible to administrators.

## 0.8.1

- Lets managed auto-lock rules use an optional door contact sensor: closing it starts the delay, and the door locks only if it remains closed and unlocked afterwards.
- Shows the installed build version in the Access Manager header.
- Reduces panel polling, pauses it while the page is hidden, and serves cached WebSocket state instead of requesting every Home Assistant state on each refresh.
- Disables noisy HTTP access logs by default and adds a translated Home Assistant app option for `warning`, `info`, or `debug` application logging.
- Migrates the app image to the current Home Assistant BuildKit-compatible Dockerfile format and updates `aiohttp` to 3.14.1.
- Only offers `binary_sensor` entities whose Home Assistant device class is `door` for closed-door automations.
- Adds one-click repository installation and clarifies Home Assistant OS updates and the exact reference hardware without claiming model-specific keypad compatibility.

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
