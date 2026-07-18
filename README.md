# Home Assistant Access Manager

Access Manager is an administrator-only Home Assistant add-on for managing identities and access credentials outside Lovelace.

It connects Home Assistant People to fingerprint IDs and Zigbee/MQTT keypad credentials, associates readers with doors, directly controls the configured door after authorization, and emits a normalized event for observability and optional automations.

## Supported devices

Access Manager does not connect directly to physical hardware. Every reader, keypad, contact sensor and door actuator must already be available as Home Assistant entities.

| Device type | Support level | Requirements |
| --- | --- | --- |
| Fingerprint terminal | Reference hardware | [ESPHome Fingerprint Access Reader](https://github.com/kytos22/esphome-fingerprint-access-reader) on a Waveshare ESP32-C6-Touch-LCD-1.47 with a Grow-compatible UART fingerprint sensor. |
| Zigbee/MQTT keypad | Protocol compatible | Three Home Assistant entities that expose transaction, code/tag and semantic action. There is no model whitelist. |
| Door contact | Optional for auto-lock; required for open-door alerts | A `binary_sensor.*` entity whose Home Assistant device class is `door`. |
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
- Reader-scoped shared keypad codes or tags for visitors, contractors, or household-wide credentials, with a clear audit label and the same encrypted storage and privacy controls as personal credentials.
- Debounced keypad packet assembly that preserves transient transaction, code/tag, and action events before Home Assistant clears their states.
- Keyed HMAC storage for keypad credentials; plaintext secrets are never persisted.
- Doors backed by an existing Home Assistant `lock`, `switch`, `button`, `input_button` or `cover` entity.
- Optional per-door contact sensors for recording physical openings and reusing the same entity in managed automations.
- Capability-aware direct door actions after successful authentication.
- Per-door default action plus centrally managed keypad button mappings.
- Capability-aware administrator door tests with an explicit confirmation step.
- Two-tap local display lock requests from compatible readers; unauthenticated local open/unlock requests are rejected.
- Door-scoped display feedback for successful opening actions, keypad credential capture, and denied keypad codes on compatible ESPHome readers.
- Configurable log retention with a 10,000-row hard safety limit.
- Structured activity records for lock and physical-door opening/closing transitions, including the door, entity and whether the change came from Access Manager or elsewhere.
- Door-mounted NFC tags scanned by the Home Assistant mobile app, assigned to allowed users from **Users & credentials**.
- Ready-to-paste ESPHome configuration generation for the reference display terminal and reader-only installations on ESPHome-supported ESP32 boards.
- Installed-versus-recommended firmware status for compatible fingerprint readers.
- Native Home Assistant app log-level configuration while routine HTTP request logging remains disabled.
- Guided native Home Assistant automations for auto-lock, door-left-open alerts, and denied-access alerts.
- One automation of each type per door, with optional `notify.*` delivery or persistent Home Assistant notifications for alerts.
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

The same tab includes the **ESPHome reader configurator**. Choose the reference display terminal or a reader-only profile, then select whether this is a new device or an update of an existing one. The downloaded file is intentionally small: it is a release-pinned ESPHome package wrapper, and ESPHome retrieves and compiles the complete firmware during validation or installation.

For a new device, import the downloaded file with **ESPHome Device Builder → New device → Import from file**, add the four named keys to ESPHome's `secrets.yaml`, validate, and install. The first installation normally uses USB; later updates can use OTA.

For an existing device, create a backup first, enter its exact current ESPHome device name, and keep the existing `wifi_ssid`, `wifi_password`, `api_encryption_key`, and `ota_password` values unchanged. Validate before using OTA. Changing the device name or either authentication secret can make Home Assistant adoption or OTA updates require manual recovery. Access Manager only names these secret keys; it never requests, receives, embeds, or stores their values. See [Firmware delivery and credential safety](FIRMWARE_DELIVERY.md) for the evaluated delivery options and recovery notes.

### Updating

Create a Home Assistant backup before updating. Then open **Settings → Apps → Access Manager** and select **Update** when a new version is offered. Existing identities, mappings, credentials and managed automation records remain in the app's `/data` volume. After the restart, verify the installed version in the Access Manager header.

## First-run setup

Access Manager intentionally starts with an empty database.

1. Add or link users in **Users & credentials**.
2. Add a door in **Doors** and choose an existing Home Assistant entity, its default authentication action, and optionally its contact sensor.
3. Add fingerprint readers or keypads and assign each one to a door.
4. Enroll or link credentials.
5. Optionally add native auto-lock, door-left-open, or denied-access rules in **Automations**. Alerts can use a persistent Home Assistant notification or an available `notify.*` entity.

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

For a shared keypad credential, `credential_type` is `shared_keypad`, `person_id` and `person_name` are `null`, and `credential_label` contains the administrator-defined audit label. The code or tag value is never included in the event.

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

Fingerprint readers use the door default unless their event requests `open`, `unlock` or `lock`. A personal or shared keypad code/tag is enrolled once per keypad. The separate keypad action determines whether Access Manager requests `open`, `unlock`, `lock`, or ignores the attempt according to the current action mapping.

### Dumb keypad model

The keypad reports a transaction, a code/tag, and a semantic action such as `disarm` or `arm_all_zones`. It never stores or resolves an Access Manager user. Access Manager stores a keyed HMAC for the `reader + code/tag` combination and links the credential either to a person or to a named shared purpose. At authentication time the code/tag identifies its owner, while the keypad reader's current action mapping determines the requested door action. Changing `disarm` from `open` to `lock`, for example, immediately changes the behavior of every credential on that keypad.

Personal and shared codes/tags can be captured from the physical keypad or entered manually. Use **Add shared code/tag** when the credential should carry an audit label instead of belonging to one person. Shared credentials are scoped to the selected keypad and therefore inherit that keypad's assigned door and current action mapping. Values are treated as opaque strings, preserving leading zeroes in PINs and supporting tag values such as `+0A1B2C3`. Access Manager does not impose a four-digit PIN limit; the physical keypad and Zigbee/MQTT integration determine which PIN lengths they can emit.

Actions with no current mapping are ignored and logged. They never fall through to an arbitrary Home Assistant service.

The three Home Assistant entities may update a few milliseconds apart. Access Manager listens to all three, waits briefly for the packet to settle, and only marks a transaction as consumed after transaction, code/tag, and action are all present.

## Mobile-app NFC door access

Home Assistant tags can be assigned to a door from the **Doors** tab. The physical tag identifies only the door; it is not a personal credential. The authenticated `user_id` in Home Assistant's `tag_scanned` event is resolved to a linked Access Manager person.

The selector reads the registered Home Assistant Tag list and refreshes it through a bounded background cache. Tag IDs do not need to be copied into Access Manager manually.

Mobile NFC access is denied by default. In **Users & credentials**, assign each fixed door tag to the users allowed to scan it. Internally the authorization remains person-to-door, so multiple physical tags for the same door share the same permission. A successful scan must include the Home Assistant scanner `device_id`, uses the door's normal default action, and emits the same `access_manager_credential` event flow as other credentials with `credential_type: mobile_nfc`. Unidentified users, missing or invalid scanner origins, missing permissions, action failures, and duplicate scans are rejected and recorded. Keypad-scanned personal NFC credentials remain a separate feature.

## Managed Home Assistant automations

The **Automations** tab creates guided, ordinary Home Assistant automations. Select the type first, then the door and its settings. Access Manager allows one rule of each type per door:

- **Auto-lock** is available for doors backed by `lock.*`. Without a contact sensor it locks after the entity has remained `unlocked` for the selected delay. With a `binary_sensor.*` whose device class is `door`, closing the contact starts the delay and the final action verifies that the lock remains unlocked and the contact remains closed.
- **Door left open** requires a door contact sensor and sends an alert after the contact has remained open for the selected delay.
- **Denied access** listens for Access Manager credential events for that door and sends an alert after the selected number of denied attempts occurs within the configured time window.

The automation editor defaults to the contact sensor assigned to the door. Saving an older managed automation that already contains a contact sensor also associates that sensor with the door, preserving existing installations.

Alert rules default to a persistent Home Assistant notification, which needs no additional setup. If Home Assistant exposes compatible `notify.*` entities, the editor also offers them as delivery targets.

Access Manager records every automation it creates and gives it a dedicated `access_manager_*` configuration ID, an `[Access Manager]` alias, and an ownership description. Update and delete operations require the local record and those Home Assistant ownership markers to agree. The panel does not list, import, edit, or delete automations outside that scope.

## Door activity records

Access Manager listens to Home Assistant state changes for every configured door. The activity log records four distinct events:

- **Door lock opened** when a configured `lock.*` changes from a closed state to `unlocked` or `open`.
- **Door lock closed** when it changes to `locked`.
- **Door physically opened** when the door's contact sensor changes from `off` (closed) to `on` (open).
- **Door physically closed** when that contact changes from `on` to `off`.

Each record stores `door_id`, `entity_id`, `previous_state`, `new_state`, and `source`. Lock changes that follow a successful Access Manager service call within the correlation window use `source: access_manager`; other changes use `source: external`. Initial, unavailable, and unknown states are ignored so an app restart does not create false activity.

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

Fingerprint templates remain in the sensor. The **Settings** configurator generates a small release-pinned package wrapper for either the reference display terminal or a generic reader-only ESP32. ESPHome downloads and compiles the compatible firmware project, which is maintained separately:

<https://github.com/kytos22/esphome-fingerprint-access-reader>

The shared entity contract and setup sequence are documented in [INTEGRATION.md](INTEGRATION.md). Delivery choices, credential-preservation rules, and recovery guidance are documented in [FIRMWARE_DELIVERY.md](FIRMWARE_DELIVERY.md).

Firmware 0.5.0 exposes ESPHome project metadata and a `Fingerprint reader firmware version` diagnostic sensor. Map that sensor in the reader editor to see the installed and recommended versions. Compatible display firmware also exposes optional `Access Manager door ID` and `Access Manager display event` text entities. Add both to enable panel feedback. Access Manager synchronizes the assigned door ID and sends only door-matching, credential-free display messages; readers without these entities continue to work without display feedback.

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
