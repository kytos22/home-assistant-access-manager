# ESPHome Fingerprint Access Reader integration

This app integrates with [ESPHome Fingerprint Access Reader](https://github.com/kytos22/esphome-fingerprint-access-reader) through entities discovered by Home Assistant from ESPHome. The two projects do not use a direct IP connection or shared secrets.

## Configuration

1. Install and adopt the firmware in Home Assistant.
2. Create a **Fingerprint** reader in Access Manager.
3. Assign the reader entities: access event, management event, name registry, and enrollment/deletion controls.
4. Associate the reader with a door and manage users and fingerprints from Access Manager.

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

Incompatible changes to these entity mappings or event formats require coordinated versions of both projects.
