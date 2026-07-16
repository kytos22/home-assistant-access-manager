# Home Assistant Access Manager

Access Manager is an administrator-only Home Assistant add-on for managing identities and access credentials outside Lovelace.

It connects Home Assistant People to fingerprint IDs and Zigbee/MQTT keypad credentials, associates readers with doors, directly controls the configured door after authorization, and emits a normalized event for observability and optional automations.

## Features

- English and Spanish interface.
- Explicit links to Home Assistant `person.*` entities.
- Multiple fingerprint readers with independent physical ID spaces.
- Per-person keypad capture using `code/tag + physical action button`; the keypad itself does not know users.
- Keyed HMAC storage for keypad credentials; plaintext secrets are never persisted.
- Doors backed by an existing Home Assistant `lock`, `switch`, `button`, `input_button` or `cover` entity.
- Capability-aware direct door actions after successful authentication.
- Per-door default action plus centrally managed keypad button mappings.
- Capability-aware administrator door tests with an explicit confirmation step.
- Two-tap local display lock requests from compatible readers; unauthenticated local open/unlock requests are rejected.
- Configurable log retention with a 10,000-row hard safety limit.
- Persistent SQLite data stored in the add-on `/data` directory.
- Normalized `access_manager_credential` and `access_manager_door_action` Home Assistant events.

Fresh installations start empty. This repository contains no users, entity IDs, network addresses, access codes or device credentials.

## Installation

1. In Home Assistant, open **Settings → Apps → App store**.
2. Open the app-store menu and choose **Repositories**.
3. Add:

   ```text
   https://github.com/kytos22/home-assistant-access-manager
   ```

4. Install **Access Manager**.
5. Start the add-on and enable its sidebar entry if Home Assistant does not do so automatically.
6. Open **Access** from the Home Assistant sidebar.

Supported architectures: `amd64`, `aarch64`, and `armv7`.

## First-run setup

Access Manager intentionally starts with an empty database.

1. Add or link users in **Users & credentials**.
2. Add a door in **Doors** and choose an existing Home Assistant entity plus its default authentication action.
3. Add fingerprint readers or keypads and assign each one to a door.
4. Enroll or link credentials.
5. Optionally create Home Assistant automations that consume the normalized event for notifications or auditing.

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

Fingerprint readers use the door default unless their event requests `open`, `unlock` or `lock`. Keypad credentials retain the specific code/tag and raw action-button combination captured during enrollment, so the same code may be enrolled separately with an unlock/open button and a lock button.

### Dumb keypad model

The keypad only reports a transaction, a code/tag, and the raw button value. It never stores or resolves a user. Access Manager stores a keyed HMAC for the `reader + code/tag + raw button` combination and links that credential to a person. At authentication time the credential identifies the person, while the keypad reader's current button mapping determines the requested door action. Changing `disarm` from `open` to `lock`, for example, immediately changes the behavior of credentials already captured with that button.

Buttons with no current mapping are ignored and logged. They never fall through to an arbitrary Home Assistant service.

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

## Data and backups

The add-on stores its SQLite database in `/data`, which is included in Home Assistant add-on backups. Keypad credential matching uses a random installation-local HMAC key stored in that same data directory.

Deleting the add-on data also deletes identity mappings and keypad credential digests. It does not delete templates held by fingerprint sensors.

## Development

```bash
python -m pip install aiohttp==3.12.15 pyyaml
python -m unittest discover -s tests -v
node tests/check_ui.mjs
```

Versions follow semantic versioning and are published as GitHub releases matching the add-on version.

## License

MIT
