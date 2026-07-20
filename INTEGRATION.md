# ESPHome Fingerprint Access Reader integration

This app integrates with the [included ESPHome Fingerprint Access Reader](esphome/README.md) through entities discovered by Home Assistant from ESPHome. Both sources live in this repository, but the running app and reader still communicate only through Home Assistant entities and do not share credentials.

## Version compatibility

The current Access Manager source recommends ESPHome Fingerprint Access Reader 0.6.2. The panel can generate release-pinned ESPHome YAML for the reference display terminal or a reader-only installation on any ESPHome-supported ESP32 board. The reader explicitly publishes its installed version during every boot.

Access Manager 0.9.0 and reader firmware 0.4.0 remain the first coordinated releases to implement the `v1` display-feedback contract described below. Older reader firmware remains usable for fingerprint access, but version status requires the optional firmware-version sensor and panel feedback requires the two optional display entities.

## Configuration

1. Optionally connect Access Manager to an authenticated, separately reachable ESPHome Device Builder endpoint. The manual flow remains available without a connection.
2. Open **Settings → ESPHome reader configurator**, choose the hardware profile and select **New device** or **Existing device update**.
3. Enter the ESPHome device name. For an update it must exactly match the current name, and the selected configuration must be that reader's canonical Device Builder YAML filename. Configure the board and UART pins for a reader-only device.
4. Review the release-pinned wrapper. Create/compile it through the connected Device Builder, or download and import it manually.
5. Enter the existing Wi-Fi, API-encryption, and OTA secret key names. Access Manager saves those names in the linked reader's firmware profile and generates the complete wrapper, but their values are never entered into Access Manager. On an existing device, preserve both the selected names and current values.
6. Validate the configuration. Install a new device over USB first, then adopt it in Home Assistant. For an existing device, enable Device Builder version history and confirm the exact filename before OTA.
7. Create a **Fingerprint** reader in Access Manager and link its exact Device Builder configuration filename.
8. Assign its entities, associate it with a door, and manage users and fingerprints from Access Manager.

Changing an existing device name can create a second ESPHome/Home Assistant identity. Changing the selected API-encryption secret value breaks the existing Home Assistant API relationship until the integration is updated or re-adopted. Changing the selected OTA secret value prevents updates that still use the old password and can require a USB recovery flash. A missing or incorrectly selected secret key name stops validation before anything is installed. Access Manager deliberately does not read or write the ESPHome configuration directory and never handles these credential values. See [FIRMWARE_DELIVERY.md](FIRMWARE_DELIVERY.md) for the delivery rationale and recovery checklist.

## Event contract

The firmware publishes the following values through its access-event entity:

```text
matched|<sequence>|<fingerprint id>|<confidence>|<requested action>
local_action|<sequence>|lock
```

`requested action` can only be `default`, `open`, `unlock`, or `lock`. Local display controls can only request `lock`. Before executing an action, Access Manager verifies the reader-to-door association, the capabilities reported by the door entity, and the fingerprint identity mapping.

Access Manager writes the following commands to the name-registry entity so the reader can display local identity information:

```text
set|<id>|<person name>|<finger key>
delete|<id>
```

## Display feedback contract

Compatible firmware exposes two optional Home Assistant `text.*` entities:

- `Access Manager door ID` stores the door currently assigned to that fingerprint reader.
- `Access Manager display event` receives short-lived panel feedback.

Access Manager synchronizes the first entity whenever the reader assignment is loaded or changed. It sends a display command only to enabled fingerprint readers associated with the same door. The firmware independently compares the event `door_id` with its stored assignment before showing it.

Display commands use this versioned format:

```text
v1|<event id>|<door id>|<event kind>|<detail>
```

Supported event kinds are:

- `door_opened`: an authorized door-opening action completed successfully;
- `credential_captured`: a keypad code or tag was registered successfully;
- `keypad_denied`: an unknown keypad credential was denied.

The detail contains a person or reader display name, never the keypad code or tag. Event IDs allow the firmware to ignore duplicates. The reference firmware shows each message for four seconds and then returns to its normal screen. Readers that do not expose both optional entities remain compatible but do not receive panel feedback.

## Home Assistant mobile-app NFC

Access Manager subscribes to Home Assistant's `tag_scanned` event. A tag registered in Home Assistant can be assigned to one Access Manager door. The tag identifies the door, while the event context's authenticated `user_id` identifies the Home Assistant account.

Available tags are loaded from Home Assistant's Tag registry through the `tag/list` WebSocket command and cached with bounded refreshes for the administration panel.

Access is granted only when the event includes a scanner `device_id`, that account resolves to a Home Assistant Person linked to an active Access Manager person, and an explicit mobile-NFC permission exists for the same door. Permissions default to disabled. Successful and denied scans use the normal `access_manager_credential` event flow with `credential_type: mobile_nfc`; the result is also written to the Access Manager activity log. Event-ID claiming and a short per-user/tag cooldown prevent duplicate opens.

Shared keypad credentials use the same event flow with `credential_type: shared_keypad`. They have no person identity; `credential_label` provides the audit attribution, and the secret code/tag is never emitted.

Incompatible changes to these entity mappings or event formats require coordinated versions of both projects.
