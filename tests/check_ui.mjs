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
  'class="mobile-tabs"',
  'id="mobile-tab-select"',
  'responsive-table',
  'enhanceResponsiveTables',
  'min-height: 44px',
  'overflow-x: hidden',
  'ha_link_state',
  'ha_link_status',
  'deletion_pending',
  'openHaPersonLinkEditor',
  'unlinkHaPerson',
  'people/${id}/ha-person',
  'people/${id}/deletion-preview',
  'mutate(`people/${id}`,"DELETE")',
  'nfc_permission_suspended',
  'mobile_nfc_permission_records',
  'personIsDeleting',
  'personCanReceiveCredentials',
  'credential_link_required',
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
  'door_lock_closed',
  'door_physically_closed',
  'assigned_door_entity',
  'display_event_entity',
  'id="mobile-nfc-tags-body"',
  'id="mobile-nfc-permissions-body"',
  'id="mobile-nfc-permission-person"',
  'id="mobile-nfc-permission-tag"',
  'id="mobile-nfc-door-filter"',
  'id="add-mobile-nfc-permission"',
  'openMobileNfcTagEditor',
  'mobile-nfc/permissions',
  'mobile-nfc-table',
  'id="esphome-profile"',
  'id="esphome-install-mode"',
  'esphome/config',
  'id="esphome-base-url"',
  'id="esphome-token"',
  'esphome/connection/test',
  'esphome/preview',
  'id="esphome-configuration"',
  'id="esphome-reader-link"',
  'id="esphome-wifi-ssid-secret"',
  'id="esphome-api-key-secret"',
  'loadLinkedEsphomeProfile',
  'confirm_overwrite',
  'install:false',
  'id="add-shared-keypad"',
  'id="shared-keypad-credentials-body"',
  'keypad/shared-credentials',
  'recoverPanelBuild',
  'firmware_version_entity',
  'firmware_not_configured',
  'PANEL_BUILD_VERSION = "0.15.0"',
  'door_sensor_hint',
  'visibilitychange',
  'REFRESH_INTERVAL_MS = 10000',
]) {
  if (!html.includes(marker)) throw new Error(`Missing UI marker: ${marker}`);
}

for (const forbidden of ['prompt(', 'confirm(']) {
  if (html.includes(forbidden)) throw new Error(`Native dialog is forbidden: ${forbidden}`);
}

const desktopNavStart = html.indexOf('<nav class="tabs"');
const desktopNavEnd = html.indexOf('</nav>', desktopNavStart);
const mobileTabsStart = html.indexOf('<div class="mobile-tabs">', desktopNavEnd);
const peopleStart = html.indexOf('id="tab-people"');
const fingerprintStart = html.indexOf('id="tab-fingerprints"');
const doorsStart = html.indexOf('id="tab-doors"');
const automationsStart = html.indexOf('id="tab-automations"');
const permissionTable = html.indexOf('id="mobile-nfc-permissions-body"');
const tagTable = html.indexOf('id="mobile-nfc-tags-body"');
if (!(desktopNavStart < desktopNavEnd && desktopNavEnd < mobileTabsStart && mobileTabsStart < peopleStart)) {
  throw new Error("The mobile section selector must appear between desktop navigation and the first tab panel");
}
const mobileNavigation = html.slice(mobileTabsStart, peopleStart);
for (const tab of ["people", "fingerprints", "keypads", "doors", "automations", "settings", "logs"]) {
  if (!mobileNavigation.includes(`<option value="${tab}"`)) {
    throw new Error(`Missing mobile navigation option: ${tab}`);
  }
}
if (!(peopleStart < permissionTable && permissionTable < fingerprintStart)) {
  throw new Error("Mobile NFC permissions must live in Users & credentials");
}
if (!(doorsStart < tagTable && tagTable < automationsStart)) {
  throw new Error("Fixed mobile NFC door tags must live in Doors");
}

console.log("UI script and tab structure are valid");
