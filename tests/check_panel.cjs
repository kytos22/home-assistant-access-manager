/* Browser checks use synthetic state and intercept every request. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { chromium } = require('playwright');

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'access_manager/app/index.html'), 'utf8');
const appVersion = fs.readFileSync(path.join(root, 'access_manager/config.yaml'), 'utf8').match(/^version:\s*["']?(\d+\.\d+\.\d+)["']?\s*$/m)?.[1];
assert.ok(appVersion, 'Missing application manifest version');
const screenshotDir = process.argv.includes('--screenshots')
  ? fs.mkdtempSync(path.join(os.tmpdir(), 'access-manager-panel-')) : null;

function fixture() {
  const people = ['Alex Morgan', 'Sam Rivera', 'Jordan Lee', 'Taylor Quinn', 'Casey Parker'].map((name, i) => ({
    id: i + 1, name, status: 'active', ha_person_entity_id: `person.test_${i}`,
    ha_link_state: i === 4 ? 'missing' : 'linked',
    credentials: [{ id: `fingerprint:front:${i + 1}`, type: 'fingerprint', reader_id: 'front', slot: i + 1, finger: 'left_index', status: 'active' },
      { id: `keypad:${i + 1}`, type: 'keypad', reader_id: 'keypad', code_hint: 'Code ••42', revealable: true }],
  }));
  return {
    version: appVersion, reader_firmware_version: '0.6.3', connected: true,
    privacy_mode: true, ready: true, reader_online: true, missing: [], reader: {}, people,
    users: people.map((p, i) => ({ reader_id: 'front', slot: i + 1, name: p.name, finger: 'left_index', status: 'active', updated_at: '2026-10-15T12:00:00Z' })),
    access_readers: [
      { id: 'front', name: 'Front entrance', reader_type: 'fingerprint', enabled: true, door_id: 'front', availability: 'available', available: true, ready: true,
        fingerprint_count: 5, capacity: 50, physical_capacity: 240, hardware_profile: 'display', firmware_version: '0.6.3', latest_firmware_version: '0.6.3', firmware_update_state: 'up_to_date', display_language: 'English',
        config: { device_name: 'front-reader', firmware_version_entity: 'sensor.test_version', display_language_entity: 'select.test_language', esphome_configuration: 'front-reader.yaml' } },
      { id: 'keypad', name: 'Entry keypad', reader_type: 'keypad', enabled: true, door_id: 'front', availability: 'configured', config: { transaction_entity: 'sensor.test_transaction', action_map: { disarm: 'open' } } },
    ],
    doors: [{ id: 'front', name: 'Front door', entity_id: 'lock.test_door', default_action: 'open', open_action: 'open', state: 'locked', config: {} }],
    door_entities: [{ entity_id: 'lock.test_door', name: 'Front door', actions: ['open', 'unlock', 'lock'], state: 'locked' }],
    door_sensors: [], notification_entities: [], ha_people: people.map(p => ({ entity_id: p.ha_person_entity_id, name: p.name })), ha_people_api_ready: true, ha_tags_api_ready: true,
    ha_tags: [], mobile_nfc_tags: [], mobile_nfc_permissions: [], mobile_nfc_permission_records: [], shared_keypad_credentials: [], managed_automations: [],
    captures: [], keypad_action_learning: [], last_keypad_actions: {}, management_message: '',
    esphome_configured: false, esphome_connection: { mode: 'manual', status: 'not_configured' }, esphome_devices: [], esphome_secret_keys: {},
    log_retention_days: 30, log_retention_options: [1, 7, 14, 30, 90], auto_lock_delays: [5, 10, 30], door_open_delays: [10, 30], denied_attempt_thresholds: [3], denied_attempt_windows: [5],
    events: [
      { id: 1, occurred_at: '2026-10-15T12:00:00Z', event_type: 'access_granted', slot: 1, confidence: 92, detail: 'Alex Morgan', door_id: 'front', source: 'access_manager' },
      { id: 2, occurred_at: '2026-10-15T11:00:00Z', event_type: 'keypad_denied', detail: 'Unknown credential', door_id: 'front', source: 'access_manager' },
    ],
  };
}

async function openPage(browser, viewport, language = 'en') {
  const context = await browser.newContext({ viewport, reducedMotion: 'reduce' });
  await context.addInitScript(value => {
    if (value === null) Object.defineProperty(window, 'localStorage', { get() { throw new Error('Storage unavailable'); } });
    else localStorage.setItem('access-manager-language', value);
  }, language);
  const page = await context.newPage();
  const errors = [];
  const writes = [];
  const state = fixture();
  const control = { response: 'ok' };
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', async route => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.hostname !== 'access-manager.test') return route.abort();
    if (url.pathname.endsWith('/api/state')) {
      if (control.response === 'failed') return route.fulfill({ status: 503, json: { ok: false, error: 'Synthetic connection failure' } });
      if (control.response === 'invalid') return route.fulfill({ body: 'null', contentType: 'application/json' });
      return route.fulfill({ json: state });
    }
    if (url.pathname.includes('/api/')) {
      writes.push({ path: url.pathname, method: request.method(), payload: request.postDataJSON() });
      if (url.pathname.endsWith('/esphome/config')) {
        const payload = request.postDataJSON();
        return route.fulfill({json:{yaml:'esphome:\n  name: front-reader\n',firmware_profile:payload.save_profile ? {...payload,hardware_profile:payload.profile,secret_keys:{wifi_ssid_secret:payload.wifi_ssid_secret}} : null}});
      }
      return route.fulfill({ json: { ok: true, ...(url.pathname.endsWith('/reveal') ? { value: 'synthetic-visible-code' } : {}) } });
    }
    const asset = url.pathname.indexOf('/assets/');
    if (asset >= 0) {
      const filename = path.join(root, 'access_manager/app', url.pathname.slice(asset + 1));
      if (!filename.startsWith(path.join(root, 'access_manager/app/assets') + path.sep)) return route.abort();
      return route.fulfill({ body: fs.readFileSync(filename), contentType: filename.endsWith('.js') ? 'application/javascript' : filename.endsWith('.png') ? 'image/png' : 'image/jpeg' });
    }
    return route.fulfill({ body: html, contentType: 'text/html' });
  });
  await page.goto('http://access-manager.test/ingress/test/');
  await page.locator('#person-count').filter({ hasText: '5' }).waitFor();
  return { context, page, errors, writes, state, control };
}

(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.ACCESS_MANAGER_BROWSER_CHANNEL ? { channel: process.env.ACCESS_MANAGER_BROWSER_CHANNEL } : {}) });
  try {
    for (const [name, viewport] of [['desktop', { width: 1440, height: 1000 }], ['tablet', { width: 900, height: 1000 }], ['mobile', { width: 390, height: 844 }], ['mobile-small', { width: 320, height: 740 }]]) {
      const { context, page, errors, writes, state, control } = await openPage(browser, viewport);
      const mobile = viewport.width <= 840;
      assert.equal(await page.locator('#people-body tr').count(), 5);
      await page.fill('#people-search', 'alex');
      assert.equal(await page.locator('#people-body tr[data-person-id]').count(), 1);
      await page.fill('#people-search', 'no matching person');
      assert.equal(await page.locator('#people-body td.empty').count(), 1);
      await page.fill('#people-search', '');
      await page.selectOption('#people-filter', 'attention');
      assert.equal(await page.locator('#people-body tr[data-person-id]').count(), 1);
      await page.selectOption('#people-filter', 'linked');
      assert.equal(await page.locator('#people-body tr[data-person-id]').count(), 4);
      await page.selectOption('#people-filter', 'all');
      const refresh = async () => {
        await page.locator('#refresh-panel').click();
        await page.waitForFunction(() => !document.querySelector('#refresh-panel').disabled);
      };
      if (mobile) {
        assert.equal(await page.locator('#person-credentials-1').isVisible(), false);
        await page.locator('[data-person-id="1"] .credential-toggle').click();
        assert.equal(await page.locator('#person-credentials-1').isVisible(), true);
        await page.locator('[data-person-id="1"] .credential-toggle').click();
      }
      await page.locator('[data-person-id="1"] details[data-menu="manage"] summary').click();
      const menuPoll = page.waitForResponse(response => response.url().endsWith('/api/state'));
      await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
      await menuPoll;
      await page.waitForFunction(() => !document.querySelector('#refresh-panel').disabled);
      assert.equal(await page.locator('[data-person-id="1"] details[data-menu="manage"]').getAttribute('open'), '');
      await page.keyboard.press('Escape');
      if (name === 'desktop') {
        for (let i = 6; i <= 30; i++) state.people.push({ ...state.people[0], id: i, name: `Synthetic person ${i}`, credentials: [] });
        await refresh();
        assert.equal(await page.locator('#people-body tr[data-person-id]').count(), 10);
        await page.locator('#people-next').click();
        assert.match(await page.locator('#people-results').textContent(), /11–20/);
        await page.selectOption('#people-page-size', '25');
        assert.equal(await page.locator('#people-body tr[data-person-id]').count(), 25);
        state.people.splice(5);
        await page.selectOption('#people-page-size', '10');
        await refresh();
        await page.locator('.tab-button[data-tab="people"]').focus();
        await page.keyboard.press('ArrowRight');
        assert.equal(await page.locator('.tab-button[data-tab="fingerprints"]').getAttribute('aria-selected'), 'true');
      }
      for (const tab of ['fingerprints', 'keypads', 'doors', 'automations', 'settings', 'logs', 'people']) {
        if (mobile) await page.selectOption('#mobile-tab-select', tab);
        else await page.locator(`.tab-button[data-tab="${tab}"]`).click();
        await page.locator(`#tab-${tab}`).waitFor({ state: 'visible' });
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1), false, `${tab} overflows ${name}`);
        if (screenshotDir && name === 'desktop' && ['fingerprints', 'doors', 'logs'].includes(tab)) await page.screenshot({ path: path.join(screenshotDir, `${name}-${tab}.png`), fullPage: true });
      }
      if (mobile) await page.selectOption('#mobile-tab-select', 'logs');
      else await page.locator('.tab-button[data-tab="logs"]').click();
      await page.fill('#log-search', 'Alex');
      assert.equal(await page.locator('#events-body tr').count(), 1);
      await page.fill('#log-search', '');
      await page.selectOption('#log-event-filter', 'keypad_denied');
      assert.equal(await page.locator('#events-body tr').count(), 1);
      await page.selectOption('#log-event-filter', '');
      if (mobile) await page.selectOption('#mobile-tab-select', 'people');
      else await page.locator('.tab-button[data-tab="people"]').click();
      await page.locator('#add-person').click();
      await page.locator('#editor-modal').waitFor({ state: 'visible' });
      await page.waitForFunction(() => document.querySelector('#editor-modal').contains(document.activeElement));
      await page.fill('#editor-fields input[name="name"]', 'Unsaved person');
      const nextState = page.waitForResponse(response => response.url().endsWith('/api/state'));
      await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
      await nextState;
      assert.equal(await page.locator('#editor-fields input[name="name"]').inputValue(), 'Unsaved person');
      await page.locator('#editor-save').focus();
      await page.keyboard.press('Tab');
      assert.equal(await page.locator('#editor-close').evaluate(element => document.activeElement === element), true);
      await page.keyboard.press('Escape');
      await page.locator('#editor-modal').waitFor({ state: 'hidden' });
      await page.waitForFunction(() => document.activeElement.id === 'add-person');
      assert.deepEqual(errors, [], `Browser errors in ${name}`);
      assert.deepEqual(writes, [], `Browsing must not perform mutations in ${name}`);
      state.people.push({ ...state.people[0], id: 99, name: '<img src=x onerror="window.panelXss = true">' });
      await refresh();
      assert.match(await page.locator('[data-person-id="99"] strong').first().textContent(), /<img/);
      assert.equal(await page.evaluate(() => window.panelXss), undefined);
      state.people.pop();
      await refresh();
      if (mobile) await page.locator('[data-person-id="1"] .credential-toggle').click();
      await page.locator('[data-person-id="1"] button[onclick="revealKeypadCredential(1)"]').click();
      await page.locator('#credential-value-1').filter({ hasText: 'synthetic-visible-code' }).waitFor();
      await page.evaluate(() => { Object.defineProperty(document, 'hidden', { configurable: true, value: true }); document.dispatchEvent(new Event('visibilitychange')); });
      assert.equal((await page.locator('#credential-value-1').textContent()).includes('synthetic-visible-code'), false);
      await page.evaluate(() => Object.defineProperty(document, 'hidden', { configurable: true, value: false }));
      if (mobile) await page.locator('[data-person-id="1"] .credential-toggle').click();
      control.response = 'failed';
      await refresh();
      assert.equal(await page.locator('#connection').evaluate(element => element.classList.contains('online')), false);
      assert.match(await page.locator('#sync-status').textContent(), /Connection lost/);
      assert.equal(await page.locator('#people-body tr[data-person-id]').count(), 5);
      control.response = 'invalid';
      await refresh();
      assert.match(await page.locator('#notice').textContent(), /unexpected response/);
      control.response = 'ok';
      await refresh();
      assert.equal(await page.locator('#notice').isVisible(), false);
      assert.equal(await page.locator('#connection').evaluate(element => element.classList.contains('online')), true);
      await page.locator('[data-person-id="1"] details[data-menu="credentials"] summary').click();
      await page.locator('[data-person-id="1"] .person-primary-actions button').first().click();
      assert.equal(await page.locator('#slot').inputValue(), '6');
      await page.fill('#slot', '9');
      await refresh();
      assert.equal(await page.locator('#slot').inputValue(), '9', 'Polling must preserve an available chosen slot');
      await page.locator('#enroll').click();
      await page.locator('#finger-modal').waitFor({ state: 'visible' });
      assert.equal(await page.locator('.hand-finger[data-finger="left_index"]').getAttribute('aria-disabled'), 'true');
      await page.locator('.hand-finger[data-finger="right_index"]').click();
      assert.equal(await page.locator('#finger-confirm').isEnabled(), true);
      if (screenshotDir && name === 'desktop') await page.screenshot({ path: path.join(screenshotDir, 'finger-selector.png') });
      await page.locator('#finger-confirm').click();
      await page.locator('#finger-modal').waitFor({ state: 'hidden' });
      assert.equal(await page.locator('#enroll').isEnabled(), true, 'Enrollment controls recover after a mutation');
      assert.match(writes.at(-1).path, /\/users\/enroll$/);
      assert.deepEqual(writes.at(-1).payload, { reader_id: 'front', slot: 9, name: 'Alex Morgan', finger: 'right_index' });
      assert.equal(writes.length, 2, 'Only the explicitly requested reveal and enrollment may be sent');
      if (mobile) await page.selectOption('#mobile-tab-select', 'people');
      else await page.locator('.tab-button[data-tab="people"]').click();
      await page.selectOption('#language', 'es');
      assert.equal(await page.locator('html').getAttribute('lang'), 'es');
      assert.equal(await page.locator('#add-person').textContent(), 'Añadir usuario');
      state.esphome_connection = { mode: 'local_ingress', configured: true, status: 'unauthorized' };
      await refresh();
      assert.equal(await page.locator('#esphome-connection-status').textContent(), 'Autorización denegada');
      assert.equal(await page.locator('#esphome-connection-status').evaluate(element => element.classList.contains('deleting')), true);
      await page.selectOption('#language', 'en');
      assert.equal(await page.locator('#esphome-connection-status').textContent(), 'Authorization denied');
      await page.selectOption('#language', 'es');
      if (screenshotDir) { await page.evaluate(() => scrollTo(0, 0)); await page.screenshot({ path: path.join(screenshotDir, `${name}.png`), fullPage: true }); }
      assert.deepEqual(errors, [], `Browser errors after interactions in ${name}`);
      await context.close();
    }
    // Preview, copy and download never opt into a linked-reader profile write.
    {
      const {context,page,errors,writes} = await openPage(browser,{width:390,height:844},'es');
      await page.selectOption('#mobile-tab-select','fingerprints');
      assert.equal(await page.locator('#save-esphome-profile').isEnabled(),false);
      assert.equal(await page.locator('#generate-esphome').textContent(),'Previsualizar configuración');
      await page.selectOption('#esphome-reader-link','front');
      assert.equal(await page.locator('#save-esphome-profile').isEnabled(),true);
      await page.locator('#generate-esphome').click();
      await page.locator('#generated-esphome').waitFor({state:'visible'});
      assert.equal(writes.length,1);
      assert.equal(writes[0].payload.save_profile,false);
      assert.equal(writes[0].payload.reader_id,'front');
      await page.locator('#copy-esphome').click();
      const download = page.waitForEvent('download');
      await page.locator('#download-esphome').click();
      assert.equal((await download).suggestedFilename(),'front-reader.yaml');
      assert.equal(writes.length,1,'Copy/download must not save or contact Device Builder');
      await page.locator('#save-esphome-profile').click();
      await page.locator('#save-esphome-profile').filter({hasText:'Perfil del lector guardado'}).waitFor();
      assert.equal(writes.length,2);
      assert.equal(writes[1].payload.save_profile,true);
      assert.ok(writes.every(item=>item.path.endsWith('/esphome/config')));
      await page.selectOption('#language','en');
      assert.equal(await page.locator('#generate-esphome').textContent(),'Preview configuration');
      assert.deepEqual(errors,[]);
      await context.close();
    }
    // Real same-origin iframe/parent discovery, but every HA/API call is synthetic.
    {
      const context = await browser.newContext({viewport:{width:1440,height:1000}});
      const page = await context.newPage();
      const state = fixture();
      state.esphome_connection = {mode:'local_ingress',configured:true,status:'session_required'};
      const delegated = [], errors = [], unexpectedWrites = [];
      let denyNext = false;
      page.on('pageerror', error => errors.push(error.message));
      await page.route('**/*', async route => {
        const request = route.request(), url = new URL(request.url());
        if (url.hostname !== 'access-manager.test') return route.abort();
        if (url.pathname === '/ha-host') return route.fulfill({contentType:'text/html',body:`<!doctype html>
          <home-assistant></home-assistant><script>
          window.haCalls=[];document.querySelector('home-assistant').hass={user:{id:'admin-a',is_admin:true},
          async callWS(command){window.haCalls.push(command);return command.endpoint==='/addons'
          ?{addons:[{slug:'custom_esphome',name:'ESPHome Device Builder',state:'started'}]}
          :command.endpoint.endsWith('/info')?{name:'ESPHome Device Builder',state:'started',ingress:true,ingress_entry:'/api/hassio_ingress/synthetic_ingress'}
          :{session:'synthetic_session_'+window.haCalls.length};}};
          </script><iframe style="width:100%;height:1100px" src="/ingress/test/"></iframe>`});
        if (url.pathname.endsWith('/api/state')) return route.fulfill({json:state});
        if (/\/api\/esphome\/(devices|connection)$/.test(url.pathname)) {
          delegated.push({path:url.pathname,method:request.method(),headers:request.headers()});
          if (denyNext) {denyNext=false;return route.fulfill({status:502,json:{ok:false,error:'Synthetic expired session',code:'unauthorized'}});}
          state.esphome_connection = {mode:'local_ingress',configured:true,status:'connected'};
          return route.fulfill({json:{ok:true,connection:state.esphome_connection,devices:[]}});
        }
        if (url.pathname.includes('/api/')) {unexpectedWrites.push(url.pathname);return route.abort();}
        const asset = url.pathname.indexOf('/assets/');
        if (asset >= 0) {
          const filename = path.join(root,'access_manager/app',url.pathname.slice(asset+1));
          if (!filename.startsWith(path.join(root,'access_manager/app/assets')+path.sep)) return route.abort();
          return route.fulfill({body:fs.readFileSync(filename),contentType:filename.endsWith('.js')?'application/javascript':'image/png'});
        }
        return route.fulfill({body:html,contentType:'text/html'});
      });
      await page.goto('http://access-manager.test/ha-host');
      const panel = page.frameLocator('iframe');
      await panel.locator('#esphome-connection-status').filter({hasText:'Connected'}).waitFor({state:'attached'});
      assert.equal(delegated.length,1);
      assert.equal(delegated[0].headers['x-device-builder-user'],'admin-a');
      const firstSession = delegated[0].headers['x-device-builder-session'];
      await panel.locator('.tab-button[data-tab="fingerprints"]').click();
      await page.evaluate(() => document.querySelector('home-assistant').hass.user.id='admin-b');
      await panel.locator('#reconnect-local-esphome').click();
      await panel.locator('#esphome-connection-result').filter({hasText:'Connection successful'}).waitFor();
      assert.equal(delegated.at(-1).headers['x-device-builder-user'],'admin-b');
      assert.notEqual(delegated.at(-1).headers['x-device-builder-session'],firstSession);
      denyNext = true;
      const beforeDenied = delegated.length;
      await panel.locator('#reconnect-local-esphome').click();
      await panel.locator('#esphome-connection-result').filter({hasText:'Synthetic expired session'}).waitFor();
      assert.equal(delegated.length,beforeDenied+1,'A denied write must not be replayed');
      await page.evaluate(() => document.querySelector('home-assistant').hass.user.is_admin=false);
      await panel.locator('#reconnect-local-esphome').click();
      await panel.locator('#esphome-connection-result').filter({hasText:'Open this panel in Home Assistant'}).waitFor();
      assert.equal(delegated.length,beforeDenied+1,'Revoked users cannot reuse a capability');
      assert.equal(await page.evaluate(() => JSON.stringify({local:{...localStorage},session:{...sessionStorage}}).includes('synthetic_session')),false);
      assert.equal((await panel.locator('body').textContent()).includes(firstSession),false);
      assert.deepEqual(unexpectedWrites,[]);
      assert.deepEqual(errors,[]);
      const haCommands = await page.evaluate(() => window.haCalls.map(call=>[call.method,call.endpoint]));
      assert.ok(haCommands.every(([method,endpoint]) => (method==='GET'&&['/addons','/addons/custom_esphome/info'].includes(endpoint)) || (method==='POST'&&endpoint==='/ingress/session')));
      assert.equal(JSON.parse(delegated[0].headers['x-device-builder-info']).ingress_token,'synthetic_ingress');
      await context.close();
    }
    for (const language of ['unsupported-language', null]) {
      const { context, page, errors } = await openPage(browser, { width: 1280, height: 900 }, language);
      assert.equal(await page.locator('html').getAttribute('lang'), 'en');
      assert.deepEqual(errors, []);
      await context.close();
    }
    console.log(JSON.stringify({ result: 'passed', viewports: ['1440x1000', '900x1000', '390x844', '320x740'], sections: 7,
      checks: ['search', 'filters', 'pagination', 'menus survive polling', 'mobile credential expansion', 'keyboard tabs', 'modal focus trap and restore', 'unsaved form preservation', 'API failure/recovery', 'invalid response', 'escaped person names', 'credential hiding when backgrounded', 'free fingerprint slots', 'approved hand selector', 'enrollment payload and control recovery', 'English/Spanish', 'Device Builder authorization error', 'HA parent iframe delegation', 'user isolation and revocation', 'expired session does not replay writes', 'no persistent capabilities', 'unavailable storage'], screenshots: screenshotDir }));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
