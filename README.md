# Home Assistant Access Manager

Access Manager is an administrator-only Home Assistant add-on for managing identities and access credentials outside Lovelace.

It connects Home Assistant People to fingerprint IDs and Zigbee/MQTT keypad credentials, associates readers with doors, and emits a normalized event for automations.

## Features

- English and Spanish interface.
- Explicit links to Home Assistant `person.*` entities.
- Multiple fingerprint readers with independent physical ID spaces.
- Keypad capture using `code/tag + action button`.
- Keyed HMAC storage for keypad credentials; plaintext secrets are never persisted.
- Doors backed by an existing Home Assistant `lock`, `switch`, `button`, `input_button` or `cover` entity.
- Configurable log retention with a 10,000-row hard safety limit.
- Persistent SQLite data stored in the add-on `/data` directory.
- Normalized `access_manager_credential` Home Assistant events.

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
2. Add a door in **Doors** and choose an existing Home Assistant entity plus its open action.
3. Add fingerprint readers or keypads and assign each one to a door.
4. Enroll or link credentials.
5. Create Home Assistant automations that consume the normalized event.

### Door actions

| Entity domain | Supported action |
| --- | --- |
| `lock` | `open`, `unlock` |
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
  door_open_action: open
  reader_id: front_reader
  reader_type: fingerprint
  person_id: 1
  person_name: Example Person
  ha_person_entity_id: person.example_person
  credential_type: fingerprint
  credential_id: "7"
  action: open
  authorized: true
```

Example automation:

```yaml
alias: Open front door from Access Manager
triggers:
  - trigger: event
    event_type: access_manager_credential
conditions:
  - condition: template
    value_template: >-
      {{ trigger.event.data.authorized
         and trigger.event.data.door_id == 'front_door'
         and trigger.event.data.action == 'open' }}
actions:
  - action: lock.open
    target:
      entity_id: "{{ trigger.event.data.door_entity_id }}"
```

Review the action and entity for your lock before enabling an automation. Some locks support `unlock` but not `open`.

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
