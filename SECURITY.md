# Security policy

Please report security issues privately through GitHub's security advisory feature. Do not open a public issue containing credentials, access codes or Home Assistant diagnostics.

Access Manager does not store keypad codes or tags as plaintext. It stores a per-installation keyed HMAC digest and a short masked hint. Fingerprint templates remain in the physical fingerprint sensor.

Never include any of the following in an issue or pull request:

- Home Assistant access or Supervisor tokens
- ESPHome API encryption keys or OTA passwords
- Wi-Fi credentials
- Real keypad codes or tag values
- `/data` databases from a live installation
