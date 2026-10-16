// Execution adapter for the verified APK 4.26.5 DevAction appsflyerReport
// branch. It calls the actual SDKs in the attached process; no HTTP payloads
// or vendor endpoints are recreated here. Attach/load does not send an event.
rpc.exports = {
  execute(request) {
    return new Promise((resolve, reject) => {
      Java.perform(() => {
        try {
          if (request.version !== 1 || request.operation !== 'appsflyerReport' ||
              !/^[a-f0-9]{64}$/.test(request.request_id) ||
              typeof request.device_id !== 'string' || !request.device_id ||
              typeof request.event.key !== 'string' || !request.event.key ||
              request.event.key.length > 128 || /[\r\n\x00]/.test(request.event.key) ||
              typeof request.event.isReportFb !== 'boolean') {
            throw new Error('invalid analytics execution input');
          }
          const Base = Java.use('com.dubox.drive.BaseApplication');
          const app = Base['______']();
          const info = app.getPackageManager().getPackageInfo(app.getPackageName(), 0);
          if (String(app.getPackageName()) !== 'com.dubox.drive' ||
              String(info.versionName.value) !== '4.26.5' || Number(info.versionCode.value) !== 699) {
            throw new Error('unsupported target build');
          }
          const wu = Java.use('wu._');
          const cuidField = wu.class.getDeclaredField('______');
          cuidField.setAccessible(true);
          if (String(cuidField.get(null)) !== request.device_id) {
            throw new Error('runtime belongs to a different installation');
          }
          const digest = Java.use('java.security.MessageDigest').getInstance('SHA-256');
          const stream = Java.use('java.io.FileInputStream').$new(String(app.getApplicationInfo().sourceDir.value));
          let baseHash = '';
          try {
            const buffer = Java.array('byte', new Array(65536).fill(0));
            let count;
            while ((count = stream.read.overload('[B').call(stream, buffer)) !== -1) {
              if (count > 0) digest.update.overload('[B', 'int', 'int').call(digest, buffer, 0, count);
            }
            const result = digest.digest();
            for (let i = 0; i < result.length; i++) baseHash += (Number(result[i]) & 255).toString(16).padStart(2, '0');
          } finally { stream.close(); }
          if (baseHash !== 'c82a4429bee57e59f45709d358314950e2220191c2c9d774a443242df13cdad8') {
            throw new Error('target base APK differs from the inspected artifact');
          }
          const key = request.event.key;
          // DevAction.j(true) creates g40.q(key, new String[0]).__(). q's
          // implementation calls AppsFlyer with an empty LinkedHashMap, then
          // FirebaseAnalytics with an empty Bundle. Calling each SDK directly
          // avoids depending on renamed obfuscated q methods between builds.
          const af = Java.use('com.appsflyer.AppsFlyerLib').getInstance();
          let firebaseCalled = false;
          if (request.event.isReportFb) {
            const params = Java.use('java.util.LinkedHashMap').$new();
            af.logEvent.overload('android.content.Context', 'java.lang.String', 'java.util.Map').call(
              af, app, key, params);
            const firebase = Java.use('com.google.firebase.analytics.FirebaseAnalytics').getInstance(app);
            firebase.logEvent(key, Java.use('android.os.Bundle').$new());
            firebaseCalled = true;
          } else {
            af.logEvent.overload('android.content.Context', 'java.lang.String', 'java.util.Map').call(
              af, app, key, null);
          }
          resolve({version: 1, request_id: request.request_id, key,
            appsflyer_called: true, firebase_called: firebaseCalled,
            environment: 'android-frida-com.dubox.drive-4.26.5-699'});
        } catch (_) {
          // An exception after AppsFlyer's call is a partial/uncertain result.
          // Never return a false success or automatically retry Firebase.
          reject(new Error('native analytics execution failed; it may be partial'));
        }
      });
    });
  }
};
