# Managed ESPHome firmware delivery

Access Manager and the ESPHome Fingerprint Access Reader are maintained in this repository, but they run independently. Access Manager never compiles ESPHome firmware. Every validation, compile, and OTA installation is performed by the user's ESPHome Device Builder with that device's canonical YAML.

Firmware packages live under `esphome/` and are pinned to immutable tags such as `firmware-v0.6.1`. The included Access Manager release is the only version source:

```python
READER_FIRMWARE_VERSION = "0.6.1"
READER_FIRMWARE_REF = f"firmware-v{READER_FIRMWARE_VERSION}"
```

It does not query GitHub at runtime and never follows a moving `main` or `stable` branch.

## Device Builder connection

The normal connection is automatic: **Settings → ESPHome Device Builder** discovers the local Stable, Beta, or Dev Device Builder through Home Assistant's authenticated Supervisor WebSocket and opens a short-lived Ingress session. No URL, bearer token, Ingress token, cookie, or public port is requested from the administrator or stored by Access Manager.

The panel reports whether Device Builder is detecting, not installed, stopped, starting, Ingress-unavailable, incompatible, connected, or in error. Starting a stopped add-on is always an explicit button action.

**Advanced configuration → External Device Builder** is only for a Device Builder on another host. It supports URL, username/password login, and an existing token. A password is used only for `auth/login` and is immediately discarded; only a returned token is retained, encrypted in the add-on's private `/data` storage. Access Manager never returns that token to the browser.

Do not expose port 6052 or enable `leave_front_door_open`. The managed local connection deliberately uses Home Assistant Ingress instead.

## What an update changes

For a linked reader, Access Manager first reads the canonical YAML from Device Builder and verifies that it contains exactly one supported managed package, for example:

```yaml
packages:
  fingerprint_access_reader:
    url: https://github.com/kytos22/home-assistant-access-manager
    ref: firmware-v0.6.0
    files:
      - esphome/access-reader.yaml
```

The two-step panel flow presents the configuration filename, installed and target versions, SHA-256 of the YAML checked, and the exact proposed line change. Applying the update rechecks that hash under a per-configuration lock, then changes only:

```diff
-    ref: firmware-v0.6.0
+    ref: firmware-v0.6.1
```

All other YAML bytes are preserved: board, framework, pins, display, substitutions, package additions, secret names, network settings, and manual customizations. Access Manager never rewrites the complete YAML for a normal update and never reads secret values or `secrets.yaml`; it checks only the required secret-key names through Device Builder metadata before validation.

The update is refused if the YAML does not contain one recognized package, has several recognized packages, uses a custom ref, belongs to a different project/profile, or is already newer than the firmware bundled with Access Manager. A custom ref is never silently overwritten and a newer firmware is never automatically downgraded.

## Update lifecycle

1. The administrator selects **Update firmware** (or **Recompile firmware** when the installed version is unknown).
2. Access Manager prepares the single-line patch and displays it for confirmation.
3. It rechecks the canonical YAML SHA-256, checks required secret-key names, applies the patch if needed, and asks Device Builder to validate it.
4. Device Builder compiles the canonical configuration and performs OTA.
5. Access Manager follows the persistent Device Builder jobs, waits for Home Assistant to see the reader reconnect, and verifies the configured firmware-version sensor against the target version.

The persistent job status distinguishes validation/compile/upload failure, waiting for a device, version unconfirmed, a reconnection timeout, and completed-and-verified. If validation or compilation fails before OTA begins, Access Manager restores the original YAML only when it had changed the managed ref. It never rolls back after OTA has started, since doing so cannot undo a device already flashed.

Operations and bounded diagnostic lines are stored in the Access Manager database and resume tracking after a restart. Audit events identify the reader and configuration only; they do not include YAML content, secrets, tokens, cookies, or authorization headers.

## Version states

The configured `firmware_version_entity` provides the installed version. Comparison accepts a leading `v`, variable-length numeric versions, prerelease identifiers, and build metadata.

| Installed version | Panel state | Action |
| --- | --- | --- |
| Lower than the bundled target | Update available | Managed update is offered |
| Equal to target | Up to date | No update is offered |
| Higher than target | Newer than supported | No automatic downgrade |
| Missing, unavailable, or invalid | Unknown | Manual recompile is available; no update claim |

## Initial setup and portability

The initial reader setup stores the reader ID, Device Builder configuration filename, hardware/display profile, language, and the administrator's four secret **names**. This makes one Access Manager installation portable without assuming that every site calls its Wi-Fi secret `wifi_ssid`; `wifi_ssid2` and other valid names are supported.

The generated YAML wrapper is for an initial import or an explicit administrator-chosen full replacement. It is not used by the normal managed-update path. First flashes normally require USB; subsequent validated updates can use OTA.

No Device Builder URL, token, board, pin, configuration filename, Home Assistant entity, or secret value is baked into the image. Existing database schema upgrades are idempotent, and external tokens are encrypted with an installation-local key in `/data`.
