// Calls the exact native hv.______.__(message) implementation. KeyMaker's key
// derivation stays inside the already running APK; this script performs no HTTP.
rpc.exports = {
  sign(request) {
    return new Promise((resolve, reject) => Java.perform(() => {
      try {
        const app = Java.use('android.app.ActivityThread').currentApplication();
        if (app === null || String(app.getPackageName()) !== 'com.dubox.drive') throw new Error('wrong process');
        const info = app.getPackageManager().getPackageInfo(app.getPackageName(), 0);
        if (String(info.versionName.value) !== '4.26.5' || Number(info.versionCode.value) !== 699) throw new Error('wrong build');
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
        const field = (cls, name) => { const f=cls.class.getDeclaredField(name); f.setAccessible(true); return f.get(null); };
        const accountClass=Java.use('com.dubox.drive.account.Account');
        const account=Java.cast(field(accountClass, '_'), accountClass);
        if (account.L()) throw new Error('guest required');
        const common=Java.use('com.dubox.drive.kernel.architecture.net.RequestCommonParams');
        const deviceID=String(field(Java.use('wu._'), '______'));
        const clientType=Number(String(common.e())), channel=String(common.d());
        if (deviceID !== request.device_id || channel !== request.channel || clientType !== request.clienttype ||
            !Number.isSafeInteger(request.timestamp_ms) || request.timestamp_ms <= 0) throw new Error('installation mismatch');
        const message=String(clientType)+channel+deviceID+String(request.timestamp_ms);
        if (message !== request.message) throw new Error('signing input mismatch');
        const helper=Java.use('hv.______');
        const signature=helper.__.overload('java.lang.String').call(helper, message);
        if (signature === null || String(signature).length === 0) throw new Error('native signing failed');
        resolve({device_id:deviceID,channel,clienttype:clientType,timestamp_ms:request.timestamp_ms,signature:String(signature)});
      } catch (_) { reject(new Error('native device signing failed')); }
    }));
  }
};
