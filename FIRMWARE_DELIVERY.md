# Firmware delivery and credential safety

Access Manager and ESPHome Fingerprint Access Reader are maintained in this single repository. They remain separate runtime components: Access Manager generates a small release-pinned YAML wrapper, while the existing ESPHome Device Builder owns each device configuration, validates it, compiles it, installs it, and remains the normal recovery path. Firmware packages live under `esphome/` and use `firmware-vX.Y.Z` tags so they cannot be confused with app releases.

Access Manager does not bundle ESPHome, write to Home Assistant's shared ESPHome directory, or read a device YAML or `secrets.yaml`. Wi-Fi, API-encryption, and OTA secret values stay exclusively in Device Builder.

## Supported connection

The optional connection in **Settings → ESPHome Device Builder connection** uses Device Builder's multiplexed `/ws` API and an optional bearer token. The token is encrypted at rest in the add-on's private `/data` volume and is never returned to the browser after saving.

Access Manager can list Device Builder configurations, create a new wrapper, update the exact configuration selected for a reader, start a remote compile or OTA installation, and follow its persistent job. Existing files are updated only after all of these checks pass:

- the exact `configuration` filename exists and belongs to the expected `esphome.name`;
- no other configuration advertises the same device name;
- Device Builder version history is enabled;
- the administrator previews the generated YAML and confirms the exact filename.

Access Manager never creates a second `*-access-manager.yaml` file for an existing device.

## Home Assistant add-on boundary

Device Builder's Home Assistant trusted-ingress endpoint rejects requests from other add-ons by design. Do not expose port 6052 with `leave_front_door_open`: that disables dashboard authentication. Until Device Builder provides a supported authenticated inter-add-on route, automatic control requires a separately reachable authenticated Device Builder endpoint.

The connection is optional. YAML generation, copy, download, manual import, validation, logs, compilation, OTA, and recovery remain available through Device Builder without connecting it to Access Manager.

## Installation portability

No Device Builder URL, token, device name, board, pin, configuration filename, or Home Assistant entity is built into Access Manager. Each installation stores its own mappings in the existing SQLite database. Schema additions are created idempotently during startup, so upgrades keep existing readers and credentials.

The initial reader setup stores a firmware profile under the Access Manager `reader_id`: ESPHome device name, friendly name, exact Device Builder configuration filename, hardware profile, language, and the four secret key names selected by the administrator. The generated wrapper maps those names into package substitutions. Secret values remain exclusively in Device Builder's `secrets.yaml` and may use installation-specific names such as `wifi_ssid2`.

The Device Builder bearer token is encrypted with an installation-local key. The database and that key both live in the add-on's private `/data` volume and are therefore restored together by a Home Assistant add-on backup. A restored installation can replace or remove the connection without affecting YAML generation.

**Test connection** verifies the read-only device, preferences, and persistent-job APIs before saving. An incompatible, unreachable, or unauthenticated Device Builder is reported as a connection error; Access Manager does not fall back to a hidden compiler or shared-directory write.

Access Manager assumes that the selected Device Builder can already compile the target firmware independently. A standalone Device Builder host must provide the operating-system libraries required by its ESPHome/ESP-IDF toolchain; for example, the isolated Ubuntu 24.04 compile test required `libusb-1.0-0` so ESP-IDF could run OpenOCD. Those compiler dependencies belong to Device Builder and are deliberately not added to the Access Manager image.

## Recommended workflow

### New device

1. Generate and review the wrapper in Access Manager.
2. Either create it through a connected Device Builder or download and import it manually.
3. Select the secret key names used by this installation and ensure those keys exist in Device Builder's `secrets.yaml`.
4. Validate the configuration and perform the first installation over USB.
5. Adopt the device in Home Assistant, create its Access Manager reader, map the entities, and link the exact Device Builder configuration filename.

### Existing device update

1. Confirm the canonical Device Builder filename and enable its version history.
2. Link that exact filename to the Access Manager reader.
3. Keep the existing device name and secret values unchanged.
4. Review the generated wrapper and confirm the exact overwrite.
5. Compile/install through Device Builder and confirm that the reader reconnects. Device Builder remains available for logs and recovery.

## Credential failure modes

| Change or problem | Result | Recovery |
| --- | --- | --- |
| Required secret key is missing | Validation fails before compilation | Add the key to Device Builder's `secrets.yaml` |
| `api_encryption_key` changes | Home Assistant cannot authenticate the existing device API | Restore the old value or deliberately re-adopt the device |
| `ota_password` changes | The next OTA upload cannot authenticate | Restore it or recover over USB |
| `device_name` changes | ESPHome/Home Assistant may create a different identity | Restore the original name or deliberately remap the replacement |
| Board or UART pins are wrong | Validation, boot, or sensor communication fails | Restore the working settings and use USB recovery if needed |

The reader-only profile remains configurable because ESP32 board and UART choices vary. A universal precompiled image would need a separate secure provisioning and recovery design, so it is not used here.
