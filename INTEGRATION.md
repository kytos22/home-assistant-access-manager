# ESPHome Fingerprint Access Reader integration

This app integrates with [ESPHome Fingerprint Access Reader](https://github.com/kytos22/esphome-fingerprint-access-reader) through entities discovered by Home Assistant from ESPHome. The two projects do not use a direct IP connection or shared secrets.

## Version compatibility

Access Manager 0.10.0 recommends ESPHome Fingerprint Access Reader 0.5.0. The panel can generate release-pinned ESPHome YAML for the reference display terminal or a reader-only installation on any ESPHome-supported ESP32 board. Firmware 0.5.0 also publishes its project version so Access Manager can show whether each configured reader is current.

Access Manager 0.9.0 and reader firmware 0.4.0 remain the first coordinated releases to implement the `v1` display-feedback contract described below. Older reader firmware remains usable for fingerprint access, but version status requires the optional firmware-version sensor and panel feedback requires the two optional display entities.

## Configuration

1. In Access Manager, open **Settings → ESPHome reader configurator**, choose the hardware profile, and download the generated YAML.
2. Ensure `wifi_ssid`, `wifi_password`, `api_encryption_key`, and `ota_password` exist in ESPHome's `secrets.yaml`. Their values are never entered into Access Manager.
3. Install and adopt the firmware in Home Assistant.
4. Create a **Fingerprint** reader in Access Manager.
5. Assign the reader entities: access event, management event, name registry, enrollment/deletion controls, the firmware-version sensor, and optionally the two Access Manager display text entities.
6. Associate the reader with a door and manage users and fingerprints from Access Manager.

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

Incompatible changes to these entity mappings or event formats require coordinated versions of both projects.
