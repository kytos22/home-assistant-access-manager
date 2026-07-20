# Home Assistant Access Manager integration

This firmware integrates with [Home Assistant Access Manager](https://github.com/kytos22/home-assistant-access-manager) only through ESPHome entities exposed in Home Assistant. It does not require an add-on IP address, MQTT, or additional credentials.

## Version compatibility

ESPHome Fingerprint Access Reader 0.6.2 explicitly publishes its diagnostic version entity during every boot. Reader 0.6.1 added per-device secret-key mapping for Access Manager generated wrappers. Reader 0.5.0 and Access Manager 0.10.0 introduced release-pinned configuration generation and reader version reporting. Both firmware profiles publish ESPHome project version metadata and a `Fingerprint reader firmware version` diagnostic sensor.

Reader 0.4.0 and Access Manager 0.9.0 remain the first coordinated releases to implement the `v1` display-feedback contract described below. Reader 0.4.0 remains compatible with older Access Manager versions for fingerprint access, but it will not receive panel feedback until the manager exposes and configures the two optional display entities.

## Configuration

1. Generate the YAML in **Access Manager → Settings → ESPHome reader configurator**, selecting the profile and **New device** or **Existing device update**.
2. Import the YAML through **ESPHome Device Builder → New device → Import from file**. ESPHome downloads and compiles the complete release-pinned package.
3. Enter the existing secret key names for Wi-Fi, API encryption, and OTA. Defaults are `wifi_ssid`, `wifi_password`, `api_encryption_key`, and `ota_password`, but each reader profile can use different names such as `wifi_ssid2`. Access Manager stores only these names; the corresponding values remain in ESPHome's `secrets.yaml`.
4. Validate before installation. Use USB for the first installation and OTA only after an existing configuration validates. Adopt the device in Home Assistant.
5. Create a **Fingerprint** reader in Access Manager.
6. Select this device's access event, management event, name registry, fingerprint controls, and firmware-version sensor. For the display profile, also select `Access Manager door ID` and `Access Manager display event`.
7. Associate the reader with a door. Access Manager authorizes fingerprints, executes the configured door action, and synchronizes that door ID to the reader.

Access Manager never reads or stores ESPHome credential values. A missing secret stops ESPHome validation; a changed API encryption key can require Home Assistant re-adoption; a changed OTA password can require USB recovery; and an unintended device-name change can create a second device identity. Keep a backup of the known-working YAML before an update.

## Reader-to-panel contract

The `Fingerprint access event` entity publishes scan and local-action events:

```text
matched|<sequence>|<fingerprint id>|<confidence>|<requested action>
local_action|<sequence>|lock
```

The `Fingerprint name registry` entity accepts commands that store the local person and finger mapping:

```text
set|<id>|<person name>|<finger key>
delete|<id>
```

## Panel-to-display contract

Access Manager writes the assigned door ID to `Access Manager door ID`. It writes short-lived feedback to `Access Manager display event` using:

```text
v1|<event id>|<door id>|<event kind>|<detail>
```

Supported kinds are `door_opened`, `credential_captured`, and `keypad_denied`. The detail contains a person or reader display name and never includes a keypad code or tag.

Access Manager sends a command only to enabled fingerprint readers associated with the event's door. The firmware independently requires the payload door ID to match its stored assignment, rejects duplicate event IDs and unknown kinds, displays valid feedback for four seconds, and then restores the normal screen.

Keep these formats and required entities stable when evolving either project. Any incompatible change requires coordinated Access Manager and firmware releases.
