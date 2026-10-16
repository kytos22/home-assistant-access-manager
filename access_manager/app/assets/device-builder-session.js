/* Browser-only Ingress delegation. Never read/store HA access tokens. */
(() => {
  function findHomeAssistant() {
    let frame = window;
    for (let depth = 0; depth < 8; depth++) {
      try {
        const hass = frame.document.querySelector('home-assistant')?.hass;
        if (hass?.callWS) return hass;
        if (frame.parent === frame) break;
        frame = frame.parent;
      } catch { break; } // An external/cross-origin parent is not trusted.
    }
    return null;
  }

  class DeviceBuilderSession {
    constructor(getHass = findHomeAssistant, now = Date.now) {
      this.getHass = getHass;
      this.now = now;
      this.cached = null;
      this.pending = null;
      this.generation = 0;
    }

    error(code) { return Object.assign(new Error(code), {code}); }

    administrator(expectedUser) {
      const hass = this.getHass();
      if (!hass?.callWS || hass.user?.is_admin !== true || typeof hass.user.id !== 'string' ||
          !hass.user.id || (expectedUser && hass.user.id !== expectedUser)) {
        this.invalidate();
        throw this.error('session_required');
      }
      return hass;
    }

    async call(hass, method, endpoint, data) {
      let timer;
      try {
        return await Promise.race([
          hass.callWS({type:'supervisor/api', method, endpoint,
            ...(data === undefined ? {} : {data})}),
          new Promise((_, reject) => { timer = setTimeout(() => reject(this.error('request_timeout')), 20000); }),
        ]);
      } catch (error) {
        // Do not display an upstream error that could contain a private URL.
        throw this.error(error?.code === 'request_timeout' ? 'request_timeout' : 'supervisor_error');
      } finally { clearTimeout(timer); }
    }

    async discover(hass) {
      const result = await this.call(hass, 'GET', '/addons');
      const apps = (result?.data || result)?.addons;
      if (!Array.isArray(apps)) throw this.error('supervisor_error');
      const supported = apps.filter(app => {
        if (!app || typeof app !== 'object') return false;
        const slug = String(app.slug || '');
        const name = String(app.name || '').toLowerCase();
        return /^[a-z0-9_-]{1,128}$/.test(slug) &&
          (['a0d7b954_esphome', 'esphome', 'esphome_beta', 'esphome_dev'].includes(slug) ||
          ((slug.includes('esphome') || name.includes('esphome')) &&
          (name.includes('device builder') || String(app.repository || '').toLowerCase().includes('esphome'))));
      });
      const app = supported.find(app => app.state === 'started') || supported[0];
      if (!app) throw this.error('not_installed');
      return app;
    }

    async headers() {
      const hass = this.administrator();
      const user = hass.user.id;
      if (this.cached?.user === user && this.cached.expires > this.now()) return {...this.cached.headers};
      if (this.pending?.user === user) return {...await this.pending.promise};
      const generation = this.generation;
      const promise = (async () => {
        const app = await this.discover(hass);
        this.administrator(user);
        if (app.state !== 'started') throw this.error('stopped');
        const infoResult = await this.call(hass, 'GET', `/addons/${app.slug}/info`);
        const info = infoResult?.data || infoResult;
        this.administrator(user);
        if (info?.state !== 'started') throw this.error('stopped');
        if (info.ingress !== true) throw this.error('ingress_unavailable');
        const entry = String(info.ingress_entry || info.ingress_url || '');
        let token = String(info.ingress_token || '');
        if (!token) {
          try { token = new URL(entry, 'http://supervisor').pathname.split('/').filter(Boolean).at(-1) || ''; }
          catch { throw this.error('ingress_unavailable'); }
        }
        if (!/^[A-Za-z0-9_-]{8,512}$/.test(token)) throw this.error('ingress_unavailable');
        const metadata = {slug:app.slug, name:String(info.name || app.name || '').slice(0,512),
          repository:String(info.repository || app.repository || '').slice(0,512),
          state:'started', ingress:true, ingress_token:token,
          version:String(info.version || '').slice(0,512), stage:String(info.stage || app.stage || '').slice(0,512)};
        const encodedInfo = JSON.stringify(metadata).replace(/[^\x20-\x7e]/g, c => '\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));
        if (encodedInfo.length > 4096) throw this.error('ingress_unavailable');
        const result = await this.call(hass, 'POST', '/ingress/session', {});
        const session = (result?.data || result)?.session;
        if (typeof session !== 'string' || !/^[A-Za-z0-9_-]{8,512}$/.test(session)) throw this.error('ingress_unavailable');
        this.administrator(user);
        if (generation !== this.generation) throw this.error('session_required');
        const headers = {'X-Device-Builder-Addon':app.slug,
          'X-Device-Builder-Session':session, 'X-Device-Builder-User':user,
          'X-Device-Builder-Info':encodedInfo};
        this.cached = {user, expires:this.now() + 240000, headers};
        return headers;
      })();
      this.pending = {user, promise};
      try { return {...await promise}; }
      finally { if (this.pending?.promise === promise) this.pending = null; }
    }

    invalidate() { this.cached = null; this.pending = null; this.generation++; }

    async start() {
      const hass = this.administrator();
      const user = hass.user.id;
      const app = await this.discover(hass);
      this.administrator(user);
      if (app.state !== 'started') await this.call(hass, 'POST', `/addons/${app.slug}/start`, {});
      this.invalidate();
    }
  }

  if (typeof module !== 'undefined' && module.exports) module.exports = DeviceBuilderSession;
  else window.AccessManagerDeviceBuilderSession = DeviceBuilderSession;
})();
