# ESPHome Fingerprint Access Reader

Reference firmware for local fingerprint access terminals built with ESPHome. It is maintained in the `esphome/` directory of the Home Assistant Access Manager repository and includes the 172 x 320 touch-display terminal on a Waveshare ESP32-C6-Touch-LCD-1.47 and a display-free profile for Grow-compatible UART sensors on ESPHome-supported ESP32 boards.

The sensor keeps fingerprint templates internally. This firmware also stores up to 50 mappings of fingerprint ID, person name, and finger in ESP non-volatile memory, so a successful access screen can show the person's name without a live Home Assistant lookup.

## Hardware profile

The included configuration targets the hardware below:

- ESP32-C6 DevKitC-1 using ESP-IDF.
- Grow-compatible fingerprint sensor at 57,600 baud.
- 172 x 320 MIPI SPI display using the included custom initialization sequence.
- PWM-controlled display backlight.
- AXS5106L capacitive touchscreen on a dedicated I2C bus.

Default pins are substitutions at the top of `access-reader.yaml`:

| Function | Default pin |
| --- | --- |
| SPI clock | GPIO1 |
| SPI MOSI | GPIO2 |
| Fingerprint UART TX | GPIO6 |
| Fingerprint UART RX | GPIO7 |
| Display DC | GPIO15 |
| Display CS | GPIO14 |
| Display reset | GPIO22 |
| Backlight | GPIO23 |
| Touch I2C SDA | GPIO18 |
| Touch I2C SCL | GPIO19 |
| Touch reset | GPIO20 |
| Touch interrupt | GPIO21 |

Review the pinout, voltage levels, display controller, and initialization sequence before powering different hardware. The Grow sensor and ESP board must share ground, and the sensor voltage must match its data sheet.

## Installation

The easiest route is **Access Manager → Fingerprint readers → ESPHome reader configurator**. Choose the reference display or reader-only profile and whether this is a new device or an existing-device update. The setup stores a profile for the selected Access Manager reader ID, including its ESPHome device name, canonical configuration filename, hardware, language, and the installation's secret key names. The downloaded YAML is a release-pinned package wrapper, not an incomplete firmware file: ESPHome retrieves the `esphome/` package from this repository at a `firmware-vX.Y.Z` tag, combines it with the wrapper substitutions and local secrets, and compiles the complete firmware.

For a new device, import the YAML with **ESPHome Device Builder → New device → Import from file**, provide the required keys in `secrets.yaml`, validate it, and perform the first installation, normally over USB. For an existing device, back up the working YAML, use its exact current device name, keep the current secret values, validate, and then update over OTA. Changing the API encryption key, OTA password, or device name can require re-adoption or USB recovery. Wi-Fi, API-encryption and OTA credential values are never entered into Access Manager.

For a manual source checkout:

1. Copy `display-reader.example.yaml` and `access-reader.yaml` into your ESPHome configuration directory. The former is the installation-owned wrapper; the latter is the reusable package.
2. Copy `secrets.example.yaml` to `secrets.yaml` if those keys do not already exist.
3. Replace every placeholder in `secrets.yaml`.
4. Adjust the wrapper substitutions and display settings for your hardware. The four `*_value` substitutions may point to any existing secret key names; the names in `secrets.example.yaml` are only defaults.
5. Validate the configuration:

   ```bash
   esphome config display-reader.example.yaml
   ```

6. Install it using the ESPHome dashboard or CLI.

For a reader without a display, use `reader-only.example.yaml` with `reader-only.yaml`. Set its `board`, `fingerprint_tx_pin`, and `fingerprint_rx_pin` substitutions for the target board. The board must be supported by ESPHome and the selected pins must be free, UART-capable pins for that board. The ESP and fingerprint sensor must share ground.

Generate a Home Assistant API encryption key with ESPHome's wizard/dashboard, or with:

```bash
openssl rand -base64 32
```

Never commit `secrets.yaml`, build output, device API keys, or OTA passwords.

There is no single safe universal precompiled image for the reader-only profile because the ESP32 board and UART pins are installation-specific. The package-wrapper workflow keeps compilation in ESPHome, preserves per-installation credentials, and supports both fixed reference hardware and configurable reader-only devices without granting Access Manager access to ESPHome's configuration directory.

## Home Assistant entities

After the device is adopted, Home Assistant exposes controls and diagnostics including:

- Fingerprint ID.
- Enroll, cancel enrollment, delete selected, and delete all controls.
- Fingerprint access and management event sensors.
- Fingerprint name registry.
- Access Manager door assignment and short-lived display-event inputs.
- Door action for the next successful scan: Default, Open, Unlock, or Lock.
- Stored fingerprint count, reader capacity, status, and connection state.
- Firmware version, also published as native ESPHome project metadata.

The companion [Home Assistant Access Manager](https://github.com/kytos22/home-assistant-access-manager) lets an administrator map these entities to a reader, enroll a person and one of ten fingers, synchronize the local name mapping, associate the reader with a door, and directly run the configured action after authorization.

The shared entity contract and setup sequence are documented in [INTEGRATION.md](INTEGRATION.md).

### Display language

The display profile exposes a persistent `Display language` select with `English` and `Español`. Changing it from Home Assistant or Access Manager refreshes the screen immediately and does not require a reflash. Firmware 0.6.3 translates all fixed interface states and the ten standardized left/right finger labels at render time. Personal names remain unchanged.

Access Manager 0.11.0 remains compatible with reader firmware 0.5.0. Access Manager 0.10.0 and reader firmware 0.5.0 added guided configuration and firmware-version status, while Access Manager 0.9.0 and reader firmware 0.4.0 remain the first coordinated versions with door-scoped panel feedback. Fingerprint access remains compatible with older Access Manager versions; only the optional feedback and version-status features require their corresponding entity mappings.

## Door action protocol

A successful fingerprint event has the format:

```text
matched|<sequence>|<fingerprint id>|<confidence>|<requested action>
```

The requested action is `default`, `open`, `unlock`, or `lock`. Access Manager checks it against the associated Home Assistant entity before calling any service. `default` uses the action selected for the door.

The `Door action for next scan` select can be changed from Home Assistant before scanning and resets to `Default` after a successful match.

The AXS5106L uses the field-tested `axs5106` ESPHome external component pinned to an exact revision for reproducible builds. Its driver uses the STOP-separated register selection, settling delay, raw I2C read, and pulled-up GPIO21 interrupt required by this controller. The built-in touch flow is deliberately narrow: a first tap wakes the display and shows a large `LOCK DOOR` confirmation for six seconds. A second tap inside that button publishes:

```text
local_action|<sequence>|lock
```

Touching elsewhere cancels. Local `open` and `unlock` are never emitted without authentication. Access Manager associates the reader with its configured door, executes the lock service, logs the outcome, and emits `access_manager_door_action`. Touch is ignored while fingerprint or management operations are active.

The pinned component reads the controller at I2C address `0x63`. Its register layout, reset timing, and rotation follow the [Waveshare board documentation](https://docs.waveshare.com/ESP32-C6-Touch-LCD-1.47), [schematic](https://files.waveshare.com/wiki/ESP32-C6-Touch-LCD-1.47/ESP32-C6-Touch-LCD-1.47-Schematic.pdf), and reference demo. The exact third-party source revision is declared directly in the YAML for audit and review.

## Local name protocol

The `Fingerprint name registry` text entity accepts:

```text
set|<id>|<person name>|<finger key>
delete|<id>
```

IDs are restricted to 1-50. Names are limited to 48 bytes and finger keys to 24 bytes. The companion add-on sends these commands automatically.

## Access Manager display feedback

The firmware exposes `Access Manager door ID` and `Access Manager display event` text entities. Configure both on the matching fingerprint reader in Access Manager. The add-on synchronizes the reader's assigned door and can then show these panel outcomes:

- a successful door opening;
- a keypad code or tag captured successfully;
- an invalid or denied keypad credential.

The display command format is:

```text
v1|<event id>|<door id>|<event kind>|<detail>
```

The firmware rejects malformed commands, unsupported event kinds, duplicate event IDs, and events whose door ID differs from its stored assignment. Messages remain visible for four seconds before the normal screen is restored. The detail is limited to a person or reader display name; codes and tags are never sent to the display.

## Security model

- Biometric templates remain inside the fingerprint sensor and are not published by this firmware.
- Names and finger labels are stored locally on the ESP; they are personal data, but not biometric templates.
- Home Assistant API traffic is encrypted with the installation-specific key in `secrets.yaml`.
- The fallback Wi-Fi access point is intentionally disabled.
- Deleting an ESPHome entity or an add-on record does not necessarily erase a template from an offline sensor. Confirm deletion after the reader reconnects.

## Development

CI compiles both complete firmware profiles against placeholder secrets. Hardware flashing and the custom display initialization sequence must still be tested on the target device.

## License

MIT
