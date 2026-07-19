# Firmware delivery and credential safety

Access Manager generates a small ESPHome YAML wrapper instead of a universal binary. The wrapper pins a tested release of the separate fingerprint-reader repository. ESPHome Device Builder downloads that package, combines it with the selected substitutions and installation-local secrets, validates it, and compiles firmware for the target board.

Access Manager 0.13.0 can send that wrapper directly to a configured ESPHome Device Builder URL, compile it there, and install existing devices over OTA. ESPHome remains responsible for compilation and keeps all secret values in its own `secrets.yaml`; Access Manager only sends the generated wrapper containing `!secret` references.

Set `esphome_dashboard_url` in the Access Manager add-on options to the reachable ESPHome Device Builder address. If the standard ESPHome add-on is used, expose its dashboard port only on a trusted network. New devices are compiled from the panel but still need their first USB installation from ESPHome.

The generated file uses a dedicated `-access-manager.yaml` suffix, so Access Manager does not overwrite an existing hand-maintained device file.

## Recommended workflow

### New device

1. Generate the YAML in **Settings → ESPHome reader configurator** using **New device**.
2. Import the downloaded file into ESPHome Device Builder with **New device → Import from file**.
3. Add `wifi_ssid`, `wifi_password`, `api_encryption_key`, and `ota_password` to ESPHome's `secrets.yaml` if they do not already exist.
4. Validate the configuration.
5. Perform the first installation over USB, adopt the device in Home Assistant, and map its entities in Access Manager.

### Existing device update

1. Create a Home Assistant/ESPHome backup and keep a copy of the working YAML.
2. Generate the wrapper using **Existing device update** and the exact current ESPHome device name.
3. Keep all four existing secret values unchanged.
4. Import or merge the wrapper, validate it, and only then install it over OTA.
5. Confirm that the device reconnects to ESPHome and Home Assistant before removing the previous YAML backup.

## Credential failure modes

| Change or problem | Result | Recovery |
| --- | --- | --- |
| A required secret key is missing or named differently | ESPHome validation fails before compilation | Add the exact key name to `secrets.yaml`; do not paste the value into Access Manager |
| `api_encryption_key` changes | Home Assistant can no longer authenticate the device API with the previous key | Restore the old value or update/re-adopt the ESPHome integration with the new key |
| `ota_password` changes unexpectedly | The next OTA upload cannot authenticate with the previous password | Restore the old value; if unavailable, perform a local USB flash |
| `device_name` changes | ESPHome and Home Assistant may treat the reader as a different device | Restore the original name, or deliberately adopt and remap the replacement |
| Board or UART pins are wrong | Validation may fail, the device may not boot correctly, or the sensor will remain offline | Restore the working board/pins and use USB recovery if OTA is unavailable |

Access Manager never asks for, receives, embeds, logs, or stores Wi-Fi, API-encryption, or OTA secret values. It does not request access to ESPHome's configuration directory or Supervisor manager privileges.

## Delivery options evaluated

The release-pinned wrapper plus ESPHome **Import from file** is the current recommended balance: it is short, reviewable, works with device-specific secrets, supports the reference display and configurable reader-only boards, and uses ESPHome's normal validation, compilation, adoption, and OTA paths.

A single precompiled image is not currently appropriate for every reader-only ESP32 because board selection and UART pins vary. Precompiled installation also needs a secure provisioning and recovery design for Wi-Fi, API encryption, and OTA authentication. ESPHome project import metadata can improve discovery for a fixed hardware product, but templates must not contain installation secrets and it does not remove the need to preserve credentials on upgrades.

Directly writing files into `/config/esphome` remains rejected. The guided installer instead uses ESPHome's own authenticated dashboard API at the explicitly configured URL, serializes firmware jobs, shows bounded logs, and requires confirmation before OTA installation.
