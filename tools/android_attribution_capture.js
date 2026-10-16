// Reviewed against base.apk SHA256 c82a4429bee57e59f45709d358314950e2220191c2c9d774a443242df13cdad8.
// Snapshot an already running 4.26.5 (699) guest process. No login, attribution
// HTTP, transfer, Intent or application launch is invoked. Local APK builders
// can initialize process caches. CK values are observed from natural calls only:
// util.h.b itself emits statistics, so this observer never calls it to generate CK.
rpc.exports = {
  collect(options) {
    options = options || {};
    return new Promise((resolve, reject) => Java.perform(() => {
      const text = value => value === null || value === undefined ? null : String(value);
      const cleanup = [];
      const ck = {};
      const ckAt = {};
      const ckStatus = {hy: 'not_observed', native: 'not_observed'};
      let settling = false;
      const finish = (value, error) => {
        if (settling) return;
        settling = true;
        Java.perform(() => {
          for (const undo of cleanup) { try { undo(); } catch (_) {} }
          if (error) reject(new Error(error)); else resolve(value);
        });
      };
      const field = (cls, name) => {
        const f = cls.class.getDeclaredField(name);
        f.setAccessible(true);
        return f.get(null);
      };
      const baseSHA256 = app => {
        const digest = Java.use('java.security.MessageDigest').getInstance('SHA-256');
        const stream = Java.use('java.io.FileInputStream').$new(String(app.getApplicationInfo().sourceDir.value));
        try {
          const buffer = Java.array('byte', new Array(65536).fill(0));
          let count;
          while ((count = stream.read.overload('[B').call(stream, buffer)) !== -1) {
            if (count > 0) digest.update.overload('[B', 'int', 'int').call(digest, buffer, 0, count);
          }
          const result = digest.digest();
          let hex = '';
          for (let i = 0; i < result.length; i++) hex += (Number(result[i]) & 255).toString(16).padStart(2, '0');
          return hex;
        } finally { stream.close(); }
      };
      const mapQuery = (url, nullKeys) => {
        const result = {};
        const names = url.queryParameterNames().iterator();
        while (names.hasNext()) {
          const key = String(names.next());
          const values = url.queryParameterValues(key);
          if (values.size() !== 1) throw new Error('ambiguous common query');
          const value = text(values.get(0));
          if (value === null) {
            // The current guest Retrofit builder emits a bare rand. The Go
            // transport handles that nullable key itself; no null becomes "null".
            if (key !== 'rand') throw new Error('unsupported nullable common field');
            nullKeys.push(key);
          } else result[key] = value;
        }
        return result;
      };
      const javaMap = map => {
        if (map === null) throw new Error('null CK map');
        const result = {};
        const entries = map.entrySet().iterator();
        while (entries.hasNext()) {
          const entry = Java.cast(entries.next(), Java.use('java.util.Map$Entry'));
          const key = text(entry.getKey()), value = text(entry.getValue());
          if (!key || value === null || Object.prototype.hasOwnProperty.call(result, key))
            throw new Error('invalid CK entry');
          result[key] = value;
        }
        return result;
      };
      const hook = (overload, callback, kind) => {
        // Preserve another observer's hook if the process is already instrumented.
        if (overload.implementation !== null) { ckStatus[kind] = 'unavailable'; return; }
        overload.implementation = function (...args) {
          const result = overload.call(this, ...args);
          try { callback(args, result); } catch (_) { ckStatus[kind] = 'invalid_observation'; }
          return result;
        };
        cleanup.push(() => { overload.implementation = null; });
      };
      const observeCK = () => {
        if (!options.observe_ck_ms) return;
        try {
          // classes14.dex util.f.____ (0x386d04): native transfer getter.
          hook(Java.use('com.dubox.drive.util.f').____.overload(), (_args, result) => {
            ck.native = javaMap(result); ckStatus.native = 'observed'; ckAt.native = Date.now();
          }, 'native');
        } catch (_) { ckStatus.native = 'unavailable'; }
        try {
          // classes10.dex webview.o.___ (0x5a4454) receives the real bridge
          // response, including DevAction.s's switch/ck_tk decisions. No guessed
          // getClientCKInfo "from" context or synthetic token is introduced.
          hook(Java.use('com.dubox.drive.business.widget.webview.o').___.overload(
            'y80.__', 'int', 'java.lang.String', 'org.json.JSONObject'), (args) => {
            if (args[1] !== 0 || args[0] === null || args[3] === null) return;
            const nameField = args[0].getClass().getDeclaredField('___');
            nameField.setAccessible(true);
            if (text(nameField.get(args[0])) !== 'getClientCKInfo') return;
            if (!args[3].has('ck_data')) {
              // DevAction.s returns {} when sd.C8() is disabled. This is an
              // observed empty bridge response, not an invented CK map.
              if (args[3].length() !== 0) throw new Error('unexpected CK bridge response');
              ck.hy = {}; ckStatus.hy = 'observed'; ckAt.hy = Date.now(); return;
            }
            const data = args[3].getJSONObject('ck_data');
            const result = {}, keys = data.keys();
            while (keys.hasNext()) {
              const key = String(keys.next());
              const raw = data.get(key);
              if (raw === null || String(raw.getClass().getName()) !== 'java.lang.String')
                throw new Error('non-string CK bridge value');
              result[key] = String(raw);
            }
            ck.hy = result; ckStatus.hy = 'observed'; ckAt.hy = Date.now();
          }, 'hy');
        } catch (_) { ckStatus.hy = 'unavailable'; }
      };
      const complete = () => {
        const done = () => {
          try {
            const Account = Java.use('com.dubox.drive.account.Account');
            const account = Java.cast(field(Account, '_'), Account);
            if (account.L() || text(account.q()) || text(account.A()) ||
                text(field(Java.use('wu._'), '______')) !== snapshot.capture.device_id) {
              finish(null, 'guest installation changed while observing'); return;
            }
          } catch (_) { finish(null, 'could not revalidate guest installation'); return; }
          snapshot.observation.ck_data_status = ckStatus.hy;
          snapshot.observation.native_ck_data_status = ckStatus.native;
          snapshot.observation.completed_at_ms = Date.now();
          if (ckAt.hy) snapshot.observation.ck_data_observed_at_ms = ckAt.hy;
          if (ckAt.native) snapshot.observation.native_ck_data_observed_at_ms = ckAt.native;
          if (ckStatus.hy === 'observed') snapshot.android_profile.ck_data = ck.hy;
          if (ckStatus.native === 'observed') snapshot.android_profile.native_ck_data = ck.native;
          if (options.require_ck && (ckStatus.hy !== 'observed' || ckStatus.native !== 'observed')) {
            finish(null, 'CK was not naturally observed in both protocol families'); return;
          }
          finish(snapshot);
        };
        if (options.observe_ck_ms > 0) setTimeout(() => Java.perform(done), options.observe_ck_ms);
        else done();
      };
      let snapshot;
      try {
        if (!Number.isSafeInteger(options.observe_ck_ms || 0) || (options.observe_ck_ms || 0) < 0 ||
            (options.observe_ck_ms || 0) > 120000) throw new Error('invalid observation interval');
        const app = Java.use('android.app.ActivityThread').currentApplication();
        if (app === null || String(app.getPackageName()) !== 'com.dubox.drive')
          throw new Error('wrong application');
        const pkg = app.getPackageManager().getPackageInfo(app.getPackageName(), 0);
        if (String(pkg.versionName.value) !== '4.26.5' || Number(pkg.versionCode.value) !== 699)
          throw new Error('unsupported APK version');
        const apkSHA256 = baseSHA256(app);
        if (apkSHA256 !== 'c82a4429bee57e59f45709d358314950e2220191c2c9d774a443242df13cdad8')
          throw new Error('APK differs from the reviewed artifact');
        const account = Java.use('com.dubox.drive.account.Account');
        const instance = Java.cast(field(account, '_'), account);
        if (instance.L() || text(instance.q()) || text(instance.A()))
          throw new Error('a guest installation is required');
        const prefs = Java.use('xu.____').r();
        const getString = prefs.j.overload('java.lang.String', 'java.lang.String');
        const common = Java.use('com.dubox.drive.kernel.architecture.net.RequestCommonParams');
        // Read the pre-existing cache before the builder's getter can initialize it.
        const cache = text(field(common, '____'));
        const storedMedia = text(getString.call(prefs, 'app_install_media_source', null));
        const wu = Java.use('wu._');
        const deviceID = text(field(wu, '______'));
        const firstLaunchSeconds = Number(String(field(wu, 'a')));
        if (!deviceID || !Number.isSafeInteger(firstLaunchSeconds) || firstLaunchSeconds <= 0)
          throw new Error('installation identity is not initialized');
        const ua = String(common.l());
        const channel = String(common.d());
        const builder = Java.use('okhttp3.HttpUrl$Builder').$new()
          .scheme('https').host('www.terabox.com').addPathSegment('api')
          .addPathSegment('srn').addPathSegment('ref');
        const helper = Java.use('com.dubox.drive.network.request._____');
        helper._.overload('okhttp3.HttpUrl$Builder', 'java.lang.String',
          'java.lang.String', 'java.util.Set').call(helper, builder, '', '',
          Java.use('java.util.HashSet').$new());
        const nativeNullKeys = [], legacyNullKeys = [];
        const nativeParams = mapQuery(builder.build(), nativeNullKeys);
        const ev = Java.use('ev.__').$new('https://www.terabox.com/api/shorturlinfo');
        ev.i('GET'); ev.f(true); ev.g('', ''); ev.j(Java.use('ev._').$new());
        const legacy = Java.use('lj.__');
        const rawLegacy = String(legacy.__.overload('ev.__', 'boolean').call(legacy, ev, false).c());
        const legacyURL = Java.use('okhttp3.HttpUrl').get.overload('java.lang.String').call(
          Java.use('okhttp3.HttpUrl'), rawLegacy);
        const locale = Java.use('fv._').___();
        const installTime = Number(String(pkg.firstInstallTime.value));
        const version = String(pkg.versionName.value);
        const capture = {
          device_id: deviceID,
          install: {
            clipboard: '', device_country: String(locale.getCountry()),
            device_lang: String(locale.getLanguage()),
            os_version: String(Java.use('android.os.Build$VERSION').RELEASE.value),
            device: String(Java.use('android.os.Build').MODEL.value),
            install_time: installTime, first_launch_time: firstLaunchSeconds * 1000,
            // aw.q consumes q5.__(), a cached Kotlin Lazy. The underlying MMKV
            // preference may already have been reset by DelayStartupKt.
            is_first_launch: !!Java.use('com.dubox.drive.q5').__()
          },
          native_media_cache: {initialized: cache !== null},
        };
        if (cache !== null) capture.native_media_cache.value = cache;
        if (storedMedia !== null) capture.stored_media_source = storedMedia;
        // Calling AfSpreadHelperKt is intentionally avoided when its method was
        // not separately verified for this build. Unobserved scene stays absent.
        snapshot = {
          android_profile: {
            device_id: deviceID, version, user_agent: ua, native_channel: channel,
            language: nativeParams.lang, page_url: '', client_type: 1,
            native_params: nativeParams, legacy_native_params: mapQuery(legacyURL, legacyNullKeys),
            psign: text(getString.call(prefs, 'server_passport_psign', '')) || ''
          },
          capture,
          observation: {
            package_name: String(app.getPackageName()), version, version_code: 699, base_apk_sha256: apkSHA256,
            observed_at_ms: Date.now(), first_launch_seconds: firstLaunchSeconds,
            native_params_source: 'inert_local_request_builder',
            native_media_cache_source: 'static_field_before_builder',
            first_launch_state_source: 'q5_cached_lazy',
            native_null_query_keys: nativeNullKeys, legacy_null_query_keys: legacyNullKeys,
            play_referrer_status: 'not_requested',
            installation_lifecycle: {
              device_id: deviceID, is_guest: true,
              language: String(locale.getLanguage()),
              time_zone: String(Java.use('java.util.TimeZone').getDefault().getID()),
              date_pattern: String(Java.use('gv.a0')._()),
              observed_today: String(Java.use('gv.____').___.overload('long').call(Java.use('gv.____'), Date.now())),
              last_unlogin_day: text(getString.call(prefs, 'key_report_logout_analytics', '')) || '',
              device_activated: !!getBoolean.call(prefs, 'KEY_IS_ACTIVITED', false)
            }
          }
        };
        if (!Number.isSafeInteger(installTime) || installTime < 0)
          throw new Error('invalid PackageInfo installation time');
        observeCK();
      } catch (_) { finish(null, 'guest snapshot failed; verify APK build and initialized guest process'); return; }

      // Select a real Hy WebView, rather than manufacturing a registration URL.
      Java.scheduleOnMainThread(() => {
        try {
        const pages = [];
        Java.choose('com.dubox.drive.business.widget.webview.DuboxWebView', {
          onMatch(view) {
            try {
              const url = text(view.getUrl());
              if (url && /^https:\/\/([^/]+\.)?terabox\.com\/wap\/hylogin(?:[/?]|$)/.test(url))
                pages.push(url);
            } catch (_) {}
          },
          onComplete() {
            try {
            const unique = Array.from(new Set(pages));
            if (unique.length === 1) snapshot.android_profile.page_url = unique[0];
            if (options.page_url) {
              if (unique.length && !unique.includes(options.page_url)) {
                finish(null, 'supplied page does not match the running Hy view'); return;
              }
              snapshot.android_profile.page_url = options.page_url;
              snapshot.observation.page_url_source = unique.includes(options.page_url)
                ? 'live_webview' : 'operator_observed';
            } else snapshot.observation.page_url_source = 'live_webview';
            if (!snapshot.android_profile.page_url) {
              finish(null, 'open one Hy guest page or supply its observed URL'); return;
            }
            if (!options.read_play) { complete(); return; }
            Java.perform(() => {
              let client, timer, finished = false;
              const finish = status => {
                if (finished) return;
                finished = true;
                if (timer) clearTimeout(timer);
                snapshot.observation.play_referrer_status = status;
                try { if (client) client.endConnection(); } catch (_) {}
                complete();
              };
              try {
                const Listener = Java.registerClass({
                  name: 'com.cfbeg.capture.ReferrerListener' + Date.now(),
                  implements: [Java.use('com.android.installreferrer.api.InstallReferrerStateListener')],
                  methods: {
                    onInstallReferrerSetupFinished(code) {
                      if (finished) return;
                      if (code !== 0) { finish('service_code_' + code); return; }
                      try {
                        const value = client.getInstallReferrer().getInstallReferrer();
                        if (value === null) { finish('unavailable'); return; }
                        snapshot.capture.install_referrer = String(value);
                        snapshot.capture.provenance = 'play_observed';
                        finish('observed');
                      } catch (_) { finish('unavailable'); }
                    },
                    onInstallReferrerServiceDisconnected() { finish('disconnected'); }
                  }
                });
                const app = Java.use('android.app.ActivityThread').currentApplication();
                client = Java.use('com.android.installreferrer.api.InstallReferrerClient')
                  .newBuilder(app.getApplicationContext()).build();
                timer = setTimeout(() => Java.perform(() => finish('timeout')), 15000);
                client.startConnection(Listener.$new());
              } catch (_) { finish('unavailable'); }
            });
            } catch (_) { finish(null, 'could not inspect the existing Hy page'); }
          }
        });
        } catch (_) { finish(null, 'could not inspect the existing Hy page'); }
      });
    }));
  }
};
