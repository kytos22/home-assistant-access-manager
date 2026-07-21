# Access Manager documentation

This page is the complete operator and project guide for Home Assistant Access Manager. It explains every panel section, the included ESPHome fingerprint-reader firmware, the Home Assistant boundary, credential safety, updates, and troubleshooting.

## Quick navigation

- [System overview](#system-overview)
- [Installation](#installation)
- [First-run checklist](#first-run-checklist)
- [Panel guide](#panel-guide)
  - [Users and credentials](#users-and-credentials)
  - [Fingerprint readers](#fingerprint-readers)
  - [Keypads](#keypads)
  - [Doors](#doors)
  - [Automations](#automations)
  - [Settings](#settings)
  - [Log](#log)
- [Fingerprint-reader firmware](#fingerprint-reader-firmware)
- [Home Assistant integration](#home-assistant-integration)
- [Security and data](#security-and-data)
- [Backups and recovery](#backups-and-recovery)
- [Troubleshooting](#troubleshooting)
- [Development and releases](#development-and-releases)

## System overview

Access Manager is an administrator-only Home Assistant app. It does not connect directly to door hardware, fingerprint sensors, or keypads. Every device must first exist in Home Assistant as one or more entities.

| Part | Responsibility | Where it runs |
| --- | --- | --- |
| Access Manager | Identities, credential ownership, authorization, door actions, audit history, and guided automations | Home Assistant app container |
| Home Assistant | Entity state, People identities, tags, service calls, events, Supervisor access, and app lifecycle | Home Assistant OS |
| ESPHome Device Builder | Validation, firmware compilation, first installation, and OTA | Separate Home Assistant app or external host |
| Display reader firmware | Fingerprint sensor, local name cache, bilingual display, local lock request, and Access Manager event bridge | ESP32 display terminal |
| Reader-only firmware | Fingerprint sensor and Access Manager event bridge without a screen | ESPHome-supported ESP32 |
| Zigbee/MQTT keypad | Emits transaction, code/tag, and action entities | Existing Home Assistant integration |
| Door actuator | Executes the configured `open`, `unlock`, `lock`, `turn_on`, `press`, or `open_cover` action | Existing Home Assistant integration |

The normal credential flow is:

1. A reader reports a fingerprint, code/tag, or mobile tag scan to Home Assistant.
2. Access Manager resolves the reader, credential owner, assigned door, and requested action.
3. The app authorizes or denies the attempt.
4. An authorized attempt calls the configured Home Assistant entity service directly.
5. Access Manager records the result and emits a normalized Home Assistant event.

No separate Home Assistant automation is required to open a configured door.

## Installation

### Requirements

- Home Assistant OS with app support.
- An administrator account.
- Door and reader entities already available in Home Assistant.
- ESPHome Device Builder for the included fingerprint-reader firmware.

### Install the app

1. Open **Settings → Apps → Install app** in Home Assistant.
2. Open the app-store menu and select **Repositories**.
3. Add `https://github.com/kytos22/home-assistant-access-manager`.
4. Install **Access Manager**.
5. Start it and enable **Show in sidebar**.
6. Open **Access** from the sidebar.

Supported architectures are `amd64`, `aarch64`, and `armv7`.

### App-level configuration

The Home Assistant app configuration page exposes `warning`, `info`, and `debug` log levels. Restart the app after changing the level. This setting controls the Home Assistant app log; activity-history retention is configured independently in the Access Manager panel.

## First-run checklist

1. Add or link an identity under **Users & credentials**.
2. Add a door under **Doors** and select its Home Assistant actuator entity.
3. Optionally select a door contact sensor.
4. Add a fingerprint reader or keypad and assign it to the door.
5. Enroll or link credentials.
6. Test the door action from the administrator panel with the physical door in view.
7. Optionally add auto-lock or alert rules under **Automations**.
8. Configure log retention and verify that backups include the app data.

Disable older automations that act on the same credential event and door, otherwise the door may receive duplicate commands.

## Panel guide

### Users and credentials

This section owns Access Manager identities and the credentials assigned to them.

#### Identity lifecycle

- **Linked** identities reference an existing Home Assistant `person.*` entity and can receive credentials and mobile NFC permissions.
- **Not linked** identities exist only in Access Manager. Link them before granting access.
- **Person missing** means the former Home Assistant Person no longer exists. Existing physical credentials remain visible and active, while mobile NFC access is suspended until the link is repaired.
- **Link not verified** means Home Assistant could not confirm the relationship. The same safe suspension applies to mobile NFC permissions.
- **Deletion pending** keeps the identity visible until every fingerprint reader confirms template removal.

The compact user row keeps **Add fingerprint** and **Add code/tag** visible. Rename, link/relink, unlink, and deletion actions are grouped under **Manage**.

#### Fingerprint credentials

A fingerprint is identified by reader and physical sensor slot. Different readers may reuse the same numeric slot. Access Manager also stores the selected finger position so the display can show the correct hand and finger in its active language.

- **Enroll new** creates a new sensor template.
- **Link existing ID** attaches an already stored physical slot without rewriting its biometric template.
- Deletion remains pending until the reader reports confirmation.

Fingerprint templates never enter Access Manager; they remain inside the fingerprint sensor.

#### Personal keypad credentials

Codes and tags belong to one identity and one keypad. They can be captured from the physical keypad or entered manually. Values are opaque strings, so leading zeroes and tag formats such as `+0A1B2C3` are preserved.

#### Shared keypad credentials

Use a shared credential for visitors, contractors, household-wide codes, or another named purpose that should not belong to one person. The audit label identifies its use without exposing the code or tag.

#### Mobile NFC permissions

A fixed Home Assistant tag identifies a door, while the authenticated Home Assistant mobile-app account identifies the person. Permissions are granted per person and door. Missing or unverified Home Assistant Person links suspend these permissions without deleting them.

### Fingerprint readers

This section contains reader registration, physical fingerprint slots, Device Builder connectivity, and firmware configuration.

#### Reader registry

Each reader has:

- A stable Access Manager ID and visible name.
- A display or reader-only hardware profile.
- An assigned door.
- Required fingerprint control and event entities.
- Optional availability, capacity, firmware-version, display-language, assigned-door, and display-event entities.
- Its exact canonical ESPHome Device Builder YAML filename.

The firmware column compares the version reported by Home Assistant with the immutable firmware version recommended by the installed Access Manager release.

#### Physical fingerprint IDs

Select a reader to inspect only that device's physical slots. Enroll, link, assign a finger, or request deletion from this reader-specific view. The photographic two-hand selector keeps every finger as an independent keyboard-accessible control and marks positions already registered for that person.

#### ESPHome Device Builder

The normal connection is automatic. Access Manager discovers the installed Device Builder through the authenticated Home Assistant Supervisor API and opens a short-lived Ingress session. It does not expose port `6052`, store an Ingress cookie, or bundle its own compiler.

The connection card reports detecting, not installed, stopped, starting, Ingress unavailable, incompatible, connected, or error states. Starting a stopped Device Builder always requires an explicit administrator action.

An external Device Builder can be configured under **Advanced configuration**. A submitted password is used once to obtain a token and is never saved. The returned token is encrypted in the app's private data directory.

#### ESPHome reader configurator

**Common environment values** stores only the names of reusable ESPHome secret keys, never their values. For example, an installation may deliberately use `wifi_ssid2` instead of `wifi_ssid`.

**Reader configuration** belongs to the selected device:

- New or existing installation.
- Display or reader-only profile.
- Linked Access Manager reader.
- Device name and friendly name.
- Display language for the display profile.
- Board and UART pins for a reader-only profile.

The configuration filename is always derived as `<device_name>.yaml` and cannot be edited independently. This prevents one reader from overwriting another reader's canonical YAML.

**Create and compile in ESPHome** writes the managed wrapper through Device Builder and starts compilation. **Preview configuration** and **Download YAML** remain available as a manual fallback.

#### Managed firmware updates

For an existing linked reader, Access Manager reads its canonical YAML, verifies its SHA-256, and proposes changing only the immutable managed package `ref`. Board, pins, device name, secret names, custom substitutions, and other YAML content are preserved.

After confirmation, Device Builder validates, compiles, and installs by OTA. Access Manager follows the persistent jobs, waits for the reader to reconnect, and verifies the reported firmware version. See [Firmware delivery and credential safety](../FIRMWARE_DELIVERY.md) for refusal conditions and recovery behavior.

#### Live display language

Display firmware provides an ESPHome `select` entity with `English` and `Español`. Changing it from Access Manager or Home Assistant:

- Does not require compilation, OTA, or USB flashing.
- Refreshes the screen immediately.
- Persists across device restarts.
- Applies to idle, lock confirmation, access granted, denial, invalid scan, finger repositioning, enrollment, cancellation, deletion, offline status, door feedback, keypad feedback, action prompts, and all ten left/right finger labels.

Adding a language or changing the compiled wording does require a new firmware build.

### Keypads

Access Manager supports keypads by entity contract rather than model whitelist. A keypad supplies:

- A transaction entity.
- A code/tag entity.
- A semantic action entity.

The action mapping translates raw values such as `disarm` or `arm_all_zones` into `open`, `unlock`, `lock`, or ignore. Changing a mapping immediately changes the requested action for every credential on that keypad.

Keypad packets may arrive a few milliseconds apart. Access Manager waits briefly for transaction, code/tag, and action to settle, and consumes the transaction only when the complete packet is available.

### Doors

A door combines a stable Access Manager ID with an existing Home Assistant actuator entity.

| Entity domain | Supported action |
| --- | --- |
| `lock` | `open` when advertised, `unlock`, `lock` |
| `switch` | `turn_on` |
| `button` | `press` |
| `input_button` | `press` |
| `cover` | `open_cover` |

The default action is used when a credential does not request another mapped action. An optional `binary_sensor.*` with device class `door` records physical opening/closing and can be reused by managed automations.

Administrator tests show the exact action and require confirmation before sending a real command.

The same section manages fixed Home Assistant NFC tags. A tag is assigned to a door; user permission is managed separately under **Users & credentials**.

### Automations

Access Manager creates guided, native Home Assistant automations. It allows one automation of each type per door:

- **Auto-lock** for `lock.*` doors, optionally waiting for the contact sensor to close.
- **Door left open** alerts after the contact remains open for the selected time.
- **Denied access** alerts after a configured number of denied attempts within a time window.

Alerts can use persistent Home Assistant notifications or compatible `notify.*` entities. Access Manager records ownership markers and refuses to edit or delete unrelated automations.

### Settings

The Settings tab contains general app behavior.

#### Privacy mode

Privacy mode is enabled by default. Recoverable keypad values are encrypted at rest in either mode.

- With privacy enabled, values are masked and can be revealed to an administrator for 15 seconds.
- With privacy disabled, recoverable values remain encrypted in storage but are continuously visible to panel administrators.
- Legacy HMAC-only credentials cannot be recovered and remain masked until registered again.

Decrypted values are never written to application or activity logs.

### Log

The activity log records credential attempts, enrollment and deletion progress, door actions, automation changes, mobile NFC decisions, firmware operations, and door state transitions.

Retention is configurable. A hard 10,000-entry safety limit always applies. Door records distinguish lock state from physical contact state and identify whether a correlated change came from Access Manager or an external source.

## Fingerprint-reader firmware

### Hardware profiles

| Profile | File | Intended hardware |
| --- | --- | --- |
| Display reader | [`esphome/access-reader.yaml`](../esphome/access-reader.yaml) | Waveshare ESP32-C6-Touch-LCD-1.47 plus Grow-compatible UART fingerprint sensor |
| Reader only | [`esphome/reader-only.yaml`](../esphome/reader-only.yaml) | ESPHome-supported ESP32 plus Grow-compatible UART fingerprint sensor |

Both profiles publish project metadata, firmware version, fingerprint controls, management events, access events, and the local name registry. The display profile additionally provides the language selector, assigned-door text, display-event text, and local touch behavior.

### Display behavior

Internal event states remain language-neutral so changing the display language never changes authorization or Home Assistant contracts. Translation occurs only when the screen renders. Personal names are displayed as stored, while standardized finger-position codes are translated at render time.

The compatible display supports a two-tap local lock request. The first tap arms the request and shows confirmation; the second requests only `lock`. Unauthenticated local `open` and `unlock` requests are rejected by Access Manager.

### Entity contract

The firmware and Access Manager communicate through Home Assistant entities. Important payload contracts include:

- Access event: `matched|sequence|id|confidence|action`.
- Local display action: `local_action|sequence|lock`.
- Name synchronization: `set|id|name|finger`.
- Template deletion: `delete|id`.

See [ESPHome integration](../esphome/INTEGRATION.md) and the [shared integration contract](../INTEGRATION.md) for the full entity list and lifecycle.

### Secrets and generated wrappers

Generated YAML files are small release-pinned package wrappers. Secret values stay in Device Builder's `secrets.yaml`; Access Manager handles only administrator-supplied key names. Each device may use different names.

Never expose Device Builder with `leave_front_door_open`, and do not publish `secrets.yaml` or device-specific wrappers containing private values.

## Home Assistant integration

### People

Access Manager stores an explicit relationship to `person.*`. It does not silently recreate or transfer identities when a Home Assistant Person disappears.

### Normalized credential event

Every authorized or denied attempt emits `access_manager_credential`. The event includes reader, door, person when known, credential type, requested action, authorization result, execution result, and error information. Keypad code/tag values are never included.

### Door-action event

Administrator tests and local display lock requests emit `access_manager_door_action`, including the source, requested action, execution result, and error.

### Mobile tags

Access Manager consumes Home Assistant's `tag_scanned` event. The physical tag selects the door and the authenticated Home Assistant `user_id` selects the linked identity. Duplicate, unidentified, unauthorized, and invalid-origin scans are rejected and recorded.

## Security and data

- The panel and mutation endpoints require a Home Assistant administrator session.
- Keypad matching uses a random installation-local keyed HMAC.
- Recoverable keypad values use authenticated encryption with a separate installation-local key.
- Keys and the SQLite database remain in the app's private `/data` directory.
- Fingerprint templates remain in the physical sensor.
- Device Builder tokens are encrypted at rest and are not returned to the browser.
- Secret values remain in ESPHome and are never requested by Access Manager.
- Routine HTTP access logging is disabled.

Fresh installations contain no users, entity IDs, network addresses, access codes, or device credentials.

## Backups and recovery

Home Assistant app backups include `/data`, which contains identities, mappings, credential digests, encrypted recoverable values, encryption keys, activity records, and managed-operation state. Protect backups accordingly.

Before updating:

1. Create a Home Assistant backup.
2. Ensure Device Builder version history is enabled before replacing an existing canonical YAML.
3. Verify the reader's exact configuration filename and device name.
4. Keep the device powered during OTA.

Deleting app data removes local identity and credential records but does not erase templates held by fingerprint sensors.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Device Builder shows `405 Method Not Allowed` | Update Access Manager; current releases use Device Builder's multiplexed `/ws` protocol with a legacy fallback. |
| Device Builder is incompatible | Confirm the official ESPHome Device Builder is installed and current, then reconnect from **Fingerprint readers**. |
| Firmware version is `unknown` | Map the reader's firmware-version sensor and install firmware 0.6.2 or newer, which explicitly publishes it at boot. |
| Display language control is missing | Confirm the reader uses the display profile and map its `select.*display_language` entity. |
| Language changes but a finger stays in English | Install firmware 0.6.3 or newer; standardized finger positions are translated at render time. |
| Existing YAML is not selected | Link the Access Manager reader and ensure its device name matches the canonical `<device_name>.yaml`. |
| OTA update is refused | Review custom/newer refs, configuration ownership, version history, secret-key metadata, and the preflight SHA-256 result. |
| Reader is offline during identity deletion | The identity remains deletion-pending until the physical reader confirms removal. |
| Mobile NFC is suspended | Repair the Home Assistant Person link, then explicitly confirm the permission. |
| Door receives duplicate commands | Disable older automations that also act on the same credential event. |

## Development and releases

Local validation:

```bash
python -m pip install aiohttp==3.14.1 cryptography==49.0.0 pyyaml
python -m unittest discover -s tests -v
node tests/check_ui.mjs
```

Access Manager uses `vX.Y.Z` release tags. Reader firmware uses independent immutable `firmware-vX.Y.Z` tags. The full process is documented in [RELEASING.md](../RELEASING.md).

Additional technical references:

- [Shared integration contract](../INTEGRATION.md)
- [Firmware delivery and credential safety](../FIRMWARE_DELIVERY.md)
- [ESPHome package reference](../esphome/README.md)
- [ESPHome integration details](../esphome/INTEGRATION.md)
- [Access Manager changelog](../access_manager/CHANGELOG.md)
- [Reader firmware changelog](../esphome/CHANGELOG.md)
