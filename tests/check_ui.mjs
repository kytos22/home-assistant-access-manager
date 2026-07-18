import { readFile } from "node:fs/promises";

const html = await readFile(new URL("../access_manager/app/index.html", import.meta.url), "utf8");
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];

if (scripts.length !== 1) {
  throw new Error(`Expected one executable script, found ${scripts.length}`);
}

new Function(scripts[0][1]);

for (const marker of [
  'id="language"',
  'id="app-version"',
  'data-tab="people"',
  'data-tab="fingerprints"',
  'data-tab="keypads"',
  'data-tab="doors"',
  'data-tab="automations"',
  'data-tab="settings"',
  'data-tab="logs"',
  'default_action',
  'id="editor-modal"',
  'id="confirm-modal"',
  'startKeypadLearning',
  'id="keypad-manual-code"',
  'id="privacy-status"',
  'data.privacy_mode !== false',
  'keypad/credentials',
  'revealKeypadCredential',
  'revealedCredentials.clear()',
  'disable_privacy_warning',
  'openDoorTest',
  'openAutomationEditor',
  'door_open_alert',
  'denied_access_alert',
  'door_open:"door-open"',
  'denied_access:"denied-access"',
  'notification_entity',
  'door_sensor_entity',
  'door.door_sensor_entity',
  'door_lock_opened',
  'door_physically_opened',
  'assigned_door_entity',
  'display_event_entity',
  'id="mobile-nfc-tags-body"',
  'id="mobile-nfc-permissions-body"',
  'openMobileNfcTagEditor',
  'mobile-nfc/permissions',
  'mobile-nfc-table',
  'door_sensor_hint',
  'visibilitychange',
  'REFRESH_INTERVAL_MS = 10000',
]) {
  if (!html.includes(marker)) throw new Error(`Missing UI marker: ${marker}`);
}

for (const forbidden of ['prompt(', 'confirm(']) {
  if (html.includes(forbidden)) throw new Error(`Native dialog is forbidden: ${forbidden}`);
}

console.log("UI script and tab structure are valid");
