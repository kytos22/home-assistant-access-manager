# Home Assistant Access Manager

Access Manager is an administrator-only Home Assistant app for managing identities, fingerprint credentials, keypad codes/tags, mobile NFC permissions, readers, doors, and guided access automations.

It links Home Assistant People to physical credentials, authorizes each attempt, directly calls the configured door entity, records the result, and emits normalized Home Assistant events. Fingerprint templates remain inside the sensor, while ESPHome compilation and OTA remain the responsibility of ESPHome Device Builder.

[Installation](#installation) · [Complete documentation](docs/index.md) · [Integration contract](INTEGRATION.md) · [Firmware delivery](FIRMWARE_DELIVERY.md) · [Release process](RELEASING.md)

## Highlights

- Explicit Home Assistant `person.*` relationships and safe missing-person lifecycle handling.
- Multiple display or reader-only fingerprint terminals with independent physical slot spaces.
- Runtime English/Spanish display switching without reflashing.
- Personal and shared keypad codes/tags with reader-scoped action mapping.
- Home Assistant mobile-app NFC permissions by linked person and door.
- Existing `lock`, `switch`, `button`, `input_button`, or `cover` entities as door actuators.
- Optional door contact sensors for physical-state records and managed automations.
- Native auto-lock, door-left-open, and denied-access Home Assistant automations.
- Automatic authenticated connection to the installed ESPHome Device Builder through Supervisor Ingress.
- Managed, release-pinned firmware creation and OTA with exact YAML ownership and hash checks.
- Encrypted recoverable keypad values, keyed HMAC matching, privacy controls, and bounded activity retention.
- Persistent SQLite data in the app's private `/data` directory.

Fresh installations start empty. The repository contains no users, entity IDs, network addresses, access codes, or device credentials.

## Project structure

| Path | Purpose |
| --- | --- |
| [`access_manager/`](access_manager/) | Home Assistant app, administrator panel, backend, and app changelog |
| [`esphome/`](esphome/) | Display and reader-only ESPHome firmware packages, custom component, examples, and firmware changelog |
| [`docs/index.md`](docs/index.md) | Complete guide to every panel and project section |
| [`INTEGRATION.md`](INTEGRATION.md) | Shared Home Assistant entity and event contracts |
| [`FIRMWARE_DELIVERY.md`](FIRMWARE_DELIVERY.md) | Device Builder, managed OTA, secret boundary, and recovery behavior |
| [`RELEASING.md`](RELEASING.md) | Validation, tag, and release checklist |
| [`tests/`](tests/) | Backend, UI, firmware-contract, and documentation checks |

Access Manager and the reader firmware are released from this repository but run independently. Their only runtime connection is through Home Assistant entities and events.

## Supported devices

Access Manager does not connect directly to physical hardware. Every reader, keypad, contact sensor, and door actuator must already be available as Home Assistant entities.

| Device type | Support level | Requirements |
| --- | --- | --- |
| Fingerprint terminal | Reference hardware | Included ESPHome firmware on a Waveshare ESP32-C6-Touch-LCD-1.47 with a Grow-compatible UART fingerprint sensor |
| Reader-only fingerprint device | ESPHome profile | An ESPHome-supported ESP32 and Grow-compatible UART fingerprint sensor |
| Zigbee/MQTT keypad | Protocol compatible | Home Assistant transaction, code/tag, and semantic-action entities; no model whitelist |
| Door contact | Optional or automation-dependent | A `binary_sensor.*` entity with Home Assistant device class `door` |
| Door actuator | Entity compatible | A supported `lock`, `switch`, `button`, `input_button`, or `cover` entity |

<p align="center">
  <a href="https://www.waveshare.com/product/esp32-c6-touch-lcd-1.47.htm">
    <img src="https://www.waveshare.com/img/devkit/ESP32-C6-Touch-LCD-1.47/ESP32-C6-Touch-LCD-1.47-1_460.jpg" width="460" alt="Waveshare ESP32-C6-Touch-LCD-1.47 reference board">
  </a><br>
  <sub>Reference display/controller board. Product image and specifications: Waveshare.</sub>
</p>

Keypads are intentionally not pictured because compatibility depends on their Home Assistant entity contract rather than a certified hardware model.

## Installation

Access Manager requires [Home Assistant OS](https://www.home-assistant.io/apps/).

**ESPHome Device Builder and the Home Assistant ESPHome integration are required dependencies for fingerprint readers.** Install and start Device Builder before using Access Manager to create, validate, compile, install, or update either the display terminal or the reader-only firmware profile. After installing the firmware, add the device to the ESPHome integration so Home Assistant exposes its fingerprint sensors, controls, diagnostic entities, and events to Access Manager. Access Manager connects to the existing Device Builder through Supervisor Ingress and communicates with readers through their Home Assistant entities; it does not bundle an ESPHome compiler or connect directly to the hardware. These dependencies are not required when Access Manager is used only with existing Home Assistant keypads, NFC tags, and door entities.

[![Open your Home Assistant instance and add the Access Manager app repository.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fkytos22%2Fhome-assistant-access-manager)

Use the button above, or install manually:

1. In Home Assistant, open **Settings → Apps** and select **Install app**.
2. Open the app-store menu and choose **Repositories**.
3. Add `https://github.com/kytos22/home-assistant-access-manager`.
4. If you will create a fingerprint reader or display terminal, install and start **ESPHome Device Builder**.
5. After installing the reader firmware, add the device to Home Assistant's **ESPHome integration**.
6. Install and start **Access Manager**.
7. Enable **Show in sidebar**, then open **Access**.

Supported architectures are `amd64`, `aarch64`, and `armv7`.

## First setup

1. Add or link an identity under **Users & credentials**.
2. Add a door and select its Home Assistant actuator entity and default action.
3. Add a fingerprint reader or keypad and assign it to the door.
4. Enroll or link credentials.
5. Optionally assign mobile NFC permissions and create guided automations.
6. Test the configured door action with the physical door in view.

No Home Assistant automation is required for normal door operation. Disable older automations that respond to the same credential and also operate the door, otherwise duplicate commands may occur.

The [complete documentation](docs/index.md) explains every panel section, firmware profile, Device Builder workflow, entity contract, security boundary, backup procedure, and troubleshooting path.

## Firmware and Device Builder

The **Fingerprint readers** tab contains the Device Builder connection and ESPHome reader configurator. Generated configurations are small wrappers pinned to immutable `firmware-vX.Y.Z` tags. The existing ESPHome Device Builder downloads, validates, compiles, and installs the complete package.

Access Manager stores only the administrator-provided names of Wi-Fi, API-encryption, and OTA secret keys. Their values remain in Device Builder's `secrets.yaml` and never enter Access Manager.

The display profile supports live English/Spanish switching through its Home Assistant `select` entity. The choice refreshes immediately and persists across restarts; adding or changing compiled translations requires a firmware update.

See [Firmware delivery and credential safety](FIRMWARE_DELIVERY.md) before replacing an existing canonical YAML or performing managed OTA.

## Security and backups

- Mutation endpoints and the panel require a Home Assistant administrator session.
- Keypad matching uses an installation-local keyed HMAC.
- Recoverable values use authenticated encryption with a separate installation-local key.
- Fingerprint templates remain in the physical sensor.
- Device Builder tokens are encrypted at rest.
- ESPHome secret values are never requested or stored.
- The SQLite database and cryptographic keys live in `/data` and are included in Home Assistant app backups.

Protect Home Assistant backups. Deleting the app data removes local identities, mappings, credential records, and keys, but does not erase fingerprint templates held by sensors.

## Updating

Create a Home Assistant backup, then open **Settings → Apps → Access Manager** and select **Update**. Existing data remains in `/data`. After restart, verify the installed version shown in the Access Manager header.

Reader firmware uses independent `firmware-vX.Y.Z` releases. A linked reader can be updated from **Fingerprint readers** after reviewing the exact managed package reference change. Manual YAML download remains available as a fallback.

## Development

```bash
python -m pip install aiohttp==3.14.1 cryptography==49.0.0 pyyaml
python -m unittest discover -s tests -v
node tests/check_ui.mjs
```

Access Manager follows semantic versioning with `vX.Y.Z` tags. Reader firmware uses independent immutable `firmware-vX.Y.Z` tags. See [RELEASING.md](RELEASING.md) for the complete checklist.

## License

MIT
