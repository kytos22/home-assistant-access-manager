# Home Assistant Access Manager

Access Manager is an administrator-only Home Assistant add-on for managing identities and access credentials outside Lovelace.

It connects Home Assistant People to fingerprint IDs and Zigbee/MQTT keypad credentials, associates readers with doors, directly controls the configured door after authorization, and emits a normalized event for observability and optional automations.

## Supported devices

Access Manager does not connect directly to physical hardware. Every reader, keypad, contact sensor and door actuator must already be available as Home Assistant entities.

| Device type | Support level | Requirements |
| --- | --- | --- |
| Fingerprint terminal | Reference hardware | [ESPHome Fingerprint Access Reader](https://github.com/kytos22/esphome-fingerprint-access-reader) on a Waveshare ESP32-C6-Touch-LCD-1.47 with a Grow-compatible UART fingerprint sensor. |
| Zigbee/MQTT keypad | Protocol compatible | Three Home Assistant entities that expose transaction, code/tag and semantic action. There is no model whitelist. |
| Door contact | Optional for auto-lock | A `binary_sensor.*` entity whose Home Assistant device class is `door`. |
| Door actuator | Entity compatible | A supported `lock`, `switch`, `button`, `input_button` or `cover` entity. |

<p align="center">
  <a href="https://www.waveshare.com/product/esp32-c6-touch-lcd-1.47.htm">
    <img src="https://www.waveshare.com/img/devkit/ESP32-C6-Touch-LCD-1.47/ESP32-C6-Touch-LCD-1.47-1_460.jpg" width="460" alt="Waveshare ESP32-C6-Touch-LCD-1.47 reference board">
  </a><br>
  <sub>Reference display/controller board. Product image and specifications: Waveshare.</sub>
</p>

The image identifies the exact display/controller used by the reference firmware. Keypads are intentionally not pictured because support depends on their Home Assistant entities, not on a certified hardware model.

## Features

- English and Spanish interface.
- Explicit links to Home Assistant `person.*` entities.
- Multiple fingerprint readers with independent physical ID spaces.
- Per-person keypad credentials identified by `code/tag`, with physical capture or protected manual entry; the keypad itself does not know users.
- Debounced keypad packet assembly that waits for transaction, code/tag, and action before consuming an attempt.
- Keyed HMAC storage for keypad credentials; plaintext secrets are never persisted.
- Doors backed by an existing Home Assistant `lock`, `switch`, `button`, `input_button` or `cover` entity.
- Capability-aware direct door actions after successful authentication.
- Per-door default action plus centrally managed keypad button mappings.
- Capability-aware administrator door tests with an explicit confirmation step.
- Two-tap local display lock requests from compatible readers; unauthenticated local open/unlock requests are rejected.
- Configurable log retention with a 10,000-row hard safety limit.
- Native Home Assistant app log-level configuration while routine HTTP request logging remains disabled.
- Native Home Assistant auto-lock automations with 5, 10, 15, 20, 30, or 60 minute delays and an optional closed-door sensor check.
- Strict automation ownership checks: Access Manager never edits or deletes unrelated Home Assistant automations.
- Persistent SQLite data stored in the add-on `/data` directory.
- Normalized `access_manager_credential` and `access_manager_door_action` Home Assistant events.

Fresh installations start empty. This repository contains no users, entity IDs, network addresses, access codes or device credentials.

## Installation

Access Manager is distributed as a Home Assistant app and therefore requires [Home Assistant OS](https://www.home-assistant.io/apps/).

[![Open your Home Assistant instance and add the Access Manager app repository.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fkytos22%2Fhome-assistant-access-manager)

Select the button above to open your Home Assistant instance with the Access Manager repository URL already filled in. Then install **Access Manager** from the app store.

Alternatively, add the repository manually:

1. In Home Assistant, open **Settings → Apps** and select **Install app**.
2. Open the three-dot menu in the app store and choose **Repositories**.
3. Add the repository URL:

   ```text
   https://github.com/kytos22/home-assistant-access-manager
   ```

4. Close the repository dialog. Reload the app store if **Access Manager** does not appear immediately.
5. Select **Access Manager** and choose **Install**.
6. Start the app and enable **Show in sidebar** if Home Assistant does not do so automatically.
7. Open **Access** from the Home Assistant sidebar.

The header inside Access Manager shows the version of the installed build. A source checkout used outside an app build displays `development` instead.

Supported architectures: `amd64`, `aarch64`, and `armv7`.

### App configuration

The Home Assistant app configuration page provides a **Log level** option:

- `info` is the recommended default for normal operation.
- `warning` only reports conditions that may need attention.
- `debug` adds diagnostic detail when investigating a problem.

Changing this option requires restarting the app. It controls the application log shown by Home Assistant, not the activity-history retention configured inside Access Manager. Routine HTTP requests are not written to the app log.

### Panel settings

The administrator-only **Settings** tab provides **Privacy mode**, enabled by default:

- Every newly registered code and tag is encrypted at rest, independently from the privacy display setting. Keyed HMAC remains the authentication mechanism.
- With privacy enabled, credentials are masked and an administrator can reveal one for 15 seconds with the view button.
- Before disabling privacy, Access Manager warns how many current encrypted credentials will become continuously visible, how many legacy HMAC-only credentials cannot be revealed, and that future credentials will also be shown automatically.
- With privacy disabled, recoverable credentials remain encrypted in storage but are continuously visible to panel administrators.

The panel never writes decrypted values to application or activity logs. A value must exist briefly in the administrator's browser memory and page when it is displayed.

### Updating

Create a Home Assistant backup before updating. Then open **Settings → Apps → Access Manager** and select **Update** when a new version is offered. Existing identities, mappings, credentials and managed automation records remain in the app's `/data` volume. After the restart, verify the installed version in the Access Manager header.

## First-run setup

Access Manager intentionally starts with an empty database.

1. Add or link users in **Users & credentials**.
2. Add a door in **Doors** and choose an existing Home Assistant entity plus its default authentication action.
3. Add fingerprint readers or keypads and assign each one to a door.
4. Enroll or link credentials.
5. Optionally add native auto-lock rules in **Automations** and select a door contact sensor when the delay should start after the physical door closes.

No Home Assistant automation is required to operate the door. Access Manager calls the configured entity service directly after an authorized credential. Disable older automations that also open the same door to avoid duplicate commands.

### Door actions

| Entity domain | Supported action |
| --- | --- |
| `lock` | `open` when supported, `unlock`, `lock` |
| `switch` | `turn_on` |
| `button` | `press` |
| `input_button` | `press` |
| `cover` | `open_cover` |

## Home Assistant event

Authorized and denied credential attempts emit `access_manager_credential`:

```yaml
event_type: access_manager_credential
data:
  event_id: front_reader:123
  door_id: front_door
  door_entity_id: lock.front_door
  door_default_action: open
  door_open_action: open
  reader_id: front_reader
  reader_type: fingerprint
  person_id: 1
  person_name: Example Person
  ha_person_entity_id: person.example_person
  credential_type: fingerprint
  credential_id: "7"
  requested_action: default
  action: open
  authorized: true
  action_executed: true
  action_error: null
```

Example failure-notification automation:

```yaml
alias: Report Access Manager door failures
triggers:
  - trigger: event
    event_type: access_manager_credential
conditions:
  - condition: template
    value_template: >-
      {{ trigger.event.data.authorized
         and not trigger.event.data.action_executed }}
actions:
  - action: persistent_notification.create
    data:
      title: Access Manager door action failed
      message: "{{ trigger.event.data.action_error }}"
```

Fingerprint readers use the door default unless their event requests `open`, `unlock` or `lock`. A keypad code or tag is enrolled once per keypad. The separate keypad action determines whether Access Manager requests `open`, `unlock`, `lock`, or ignores the attempt according to the current action mapping.

### Dumb keypad model

The keypad reports a transaction, a code/tag, and a semantic action such as `disarm` or `arm_all_zones`. It never stores or resolves an Access Manager user. Access Manager stores a keyed HMAC for the `reader + code/tag` combination and links that credential to a person. At authentication time the code/tag identifies the person, while the keypad reader's current action mapping determines the requested door action. Changing `disarm` from `open` to `lock`, for example, immediately changes the behavior of every credential on that keypad.

Codes and tags can be captured from the physical keypad or entered manually from the user credential dialog. Values are treated as opaque strings, preserving leading zeroes in PINs and supporting tag values such as `+0A1B2C3`. Access Manager does not impose a four-digit PIN limit; the physical keypad and Zigbee/MQTT integration determine which PIN lengths they can emit.

Actions with no current mapping are ignored and logged. They never fall through to an arbitrary Home Assistant service.

The three Home Assistant entities may update a few milliseconds apart. Access Manager listens to all three, waits briefly for the packet to settle, and only marks a transaction as consumed after transaction, code/tag, and action are all present.

## Managed Home Assistant automations

The **Automations** tab creates ordinary Home Assistant automations for doors backed by `lock.*` entities. Without a contact sensor, an auto-lock rule waits until the lock has remained `unlocked` for the selected delay, verifies that it is still unlocked, and then calls `lock.lock`. When a `binary_sensor.*` with the `door` device class is selected, closing the contact starts the delay; at the end, the rule locks only if the lock is still unlocked and the door is still closed.

Access Manager records every automation it creates and gives it a dedicated `access_manager_*` configuration ID, an `[Access Manager]` alias, and an ownership description. Update and delete operations require the local record and those Home Assistant ownership markers to agree. The panel does not list, import, edit, or delete automations outside that scope.

### Door action event

Local display lock requests and administrator door tests emit `access_manager_door_action`:

```yaml
event_type: access_manager_door_action
data:
  event_id: front_reader:124
  door_id: front_door
  door_entity_id: lock.front_door
  reader_id: front_reader
  reader_type: fingerprint
  source: display
  action: lock
  action_executed: true
  action_error: null
```

For `source: display`, Access Manager accepts only `lock`. Door tests are restricted to the administrator panel and checked against the entity's advertised capabilities.

## Fingerprint reader firmware

Fingerprint templates remain in the sensor. A compatible ESPHome example that stores the local ID/name/finger mapping in ESP memory is maintained separately:

<https://github.com/kytos22/esphome-fingerprint-access-reader>

The shared entity contract and setup sequence are documented in [INTEGRATION.md](INTEGRATION.md).

## Data and backups

The add-on stores its SQLite database in `/data`, which is included in Home Assistant add-on backups. Keypad credential matching uses a random installation-local HMAC key. Recoverable credential values are stored only as authenticated ciphertext, using a separate installation-local encryption key with restrictive file permissions. Both keys are held in `/data` so backups can restore the installation; protect Home Assistant backups accordingly.

Deleting the add-on data also deletes identity mappings, credential digests, encrypted values, and the encryption key. It does not delete templates held by fingerprint sensors.

## Development

```bash
python -m pip install aiohttp==3.14.1 cryptography==49.0.0 pyyaml
python -m unittest discover -s tests -v
node tests/check_ui.mjs
```

Versions follow semantic versioning and are published as GitHub releases matching the add-on version.
The complete release checklist is in [RELEASING.md](RELEASING.md).

## License

MIT
