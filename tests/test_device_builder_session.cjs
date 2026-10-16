const {test} = require('node:test');
const assert = require('node:assert/strict');
const Session = require('../access_manager/app/assets/device-builder-session.js');
const metadata = () => ({name:'ESPHome Device Builder',state:'started',ingress:true,ingress_entry:'/api/hassio_ingress/synthetic_ingress'});

function fixture() {
  const calls = [];
  let time = 0;
  const hass = {user:{id:'admin-a', is_admin:true}, async callWS(command) {
    calls.push(command);
    return command.endpoint === '/addons'
      ? {addons:[{slug:'custom_esphome', name:'ESPHome Device Builder', state:'started'}]}
      : command.endpoint.endsWith('/info') ? metadata() : {session:`synthetic_session_${calls.length}`};
  }};
  const session = new Session(() => hass, () => time);
  return {session, hass, calls, tick:() => {time += 240001;}};
}

test('concurrent requests share one handshake; cache expires and is memory-only', async () => {
  const {session, calls, tick} = fixture();
  const [a,b] = await Promise.all([session.headers(), session.headers()]);
  assert.deepEqual(a,b);
  assert.equal(calls.length,3);
  a['X-Device-Builder-Session'] = 'caller-modified';
  assert.notEqual((await session.headers())['X-Device-Builder-Session'], 'caller-modified');
  tick();
  assert.notDeepEqual(await session.headers(),b);
  assert.equal(calls.length,6);
  assert.deepEqual(calls.map(c => c.endpoint), ['/addons','/addons/custom_esphome/info','/ingress/session','/addons','/addons/custom_esphome/info','/ingress/session']);
  assert.equal(JSON.parse(b['X-Device-Builder-Info']).ingress_token,'synthetic_ingress');
});

test('changed user never receives an earlier user capability', async () => {
  const {session,hass} = fixture();
  const a = await session.headers();
  hass.user = {id:'admin-b', is_admin:true};
  const b = await session.headers();
  assert.equal(b['X-Device-Builder-User'],'admin-b');
  assert.notEqual(a['X-Device-Builder-Session'],b['X-Device-Builder-Session']);
});

test('revocation or missing HA parent denies access even with a cached session', async () => {
  const {session,hass} = fixture();
  await session.headers();
  hass.user.is_admin = false;
  await assert.rejects(session.headers(), {code:'session_required'});
  assert.equal(session.cached,null);
  await assert.rejects(new Session(() => null).headers(), {code:'session_required'});
});

test('identity switch during discovery does not create a session', async () => {
  const {session,hass,calls} = fixture();
  const old = hass.callWS;
  hass.callWS = async command => {const result = await old(command); hass.user.id='admin-b'; return result;};
  await assert.rejects(session.headers(), {code:'session_required'});
  assert.equal(calls.length,1);
});

test('invalidation discards an in-flight handshake', async () => {
  const {session,hass} = fixture();
  const old = hass.callWS;
  hass.callWS = async command => {const result = await old(command); if(command.endpoint==='/ingress/session') session.invalidate(); return result;};
  await assert.rejects(session.headers(), {code:'session_required'});
  assert.equal(session.cached,null);
});

test('upstream errors do not expose private paths or leave a cached grant', async () => {
  const {session,hass} = fixture();
  hass.callWS = async () => {throw new Error('synthetic-private-url');};
  await assert.rejects(session.headers(), error => error.code==='supervisor_error' && !error.message.includes('private'));
  assert.equal(session.cached,null);
  assert.equal(session.pending,null);
});

test('stopped or absent builders are never started during connection', async () => {
  for(const apps of [[], [{slug:'custom_esphome',name:'ESPHome Device Builder',state:'stopped'}]]) {
    const {session,hass,calls} = fixture();
    hass.callWS = async command => {calls.push(command); return {addons:apps};};
    await assert.rejects(session.headers(), {code:apps.length?'stopped':'not_installed'});
    assert.equal(calls.length,1);
  }
});

test('malformed session cookie is rejected', async () => {
  const {session,hass} = fixture();
  const old = hass.callWS;
  hass.callWS = async command => command.endpoint==='/ingress/session' ? {session:'bad;Cookie=1'} : old(command);
  await assert.rejects(session.headers(), {code:'ingress_unavailable'});
  assert.equal(session.cached,null);
});

test('start is explicit and targets only the selected ESPHome app', async () => {
  const {session,hass,calls} = fixture();
  hass.callWS = async command => {calls.push(command); return command.endpoint==='/addons'
    ? {addons:[{slug:'custom_esphome',name:'ESPHome Device Builder',state:'stopped'}]} : {};};
  await session.start();
  assert.deepEqual(calls.map(c=>[c.method,c.endpoint]), [['GET','/addons'],['POST','/addons/custom_esphome/start']]);
  assert.equal(session.cached,null);
});

test('an unresponsive HA bridge has a bounded wait', async t => {
  t.mock.timers.enable({apis:['setTimeout']});
  const {session,hass} = fixture();
  hass.callWS = () => new Promise(() => {});
  const result = session.headers();
  t.mock.timers.tick(20001);
  await assert.rejects(result, {code:'request_timeout'});
  assert.equal(session.pending,null);
  assert.equal(session.cached,null);
});

test('concurrent handshakes for different users cannot exchange capabilities', async () => {
  const {session,hass} = fixture();
  let release;
  let sessions = 0;
  hass.callWS = async command => command.endpoint==='/addons'
    ? {addons:[{slug:'custom_esphome',name:'ESPHome Device Builder',state:'started'}]}
    : command.endpoint.endsWith('/info') ? metadata()
    : (++sessions===1 ? new Promise(resolve => {release=resolve;}) : {session:'synthetic_session_b'});
  const a = session.headers();
  await new Promise(resolve => setImmediate(resolve));
  hass.user.id='admin-b';
  const b = await session.headers();
  release({session:'synthetic_session_a'});
  await assert.rejects(a, {code:'session_required'});
  assert.equal(b['X-Device-Builder-User'],'admin-b');
  assert.equal(b['X-Device-Builder-Session'],'synthetic_session_b');
});

test('identity switch before explicit start prevents the management action', async () => {
  const {session,hass,calls} = fixture();
  hass.callWS = async command => {calls.push(command);hass.user.id='admin-b';return {
    addons:[{slug:'custom_esphome',name:'ESPHome Device Builder',state:'stopped'}]};};
  await assert.rejects(session.start(), {code:'session_required'});
  assert.equal(calls.length,1);
});

test('missing or malformed app metadata never creates a session', async () => {
  for(const details of [{...metadata(),ingress:false},{...metadata(),ingress_entry:'/bad;Cookie=1'}]) {
    const {session,hass,calls}=fixture();
    const old=hass.callWS;
    hass.callWS=async command => command.endpoint.endsWith('/info') ? details : old(command);
    await assert.rejects(session.headers(),{code:'ingress_unavailable'});
    assert.equal(calls.some(c=>c.endpoint==='/ingress/session'),false);
  }
});

test('unicode names are encoded safely in the metadata header', async () => {
  const {session,hass}=fixture();
  const old=hass.callWS;
  hass.callWS=async command => command.endpoint.endsWith('/info') ? {...metadata(),name:'ESPHome Device Builder · 日本語'} : old(command);
  const headers=await session.headers();
  assert.match(headers['X-Device-Builder-Info'],/^[\x20-\x7e]+$/);
  assert.equal(JSON.parse(headers['X-Device-Builder-Info']).name,'ESPHome Device Builder · 日本語');
});
