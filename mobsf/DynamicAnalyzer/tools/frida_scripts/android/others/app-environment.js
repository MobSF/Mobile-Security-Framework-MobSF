// Based on https://github.com/sensepost/objection/blob/f8e78d8a29574c6dadd2b953a63207b45a19b1cf/objection/hooks/android/filesystem/environment.js
var ActivityThread = Java.use('android.app.ActivityThread');

var currentApplication = ActivityThread.currentApplication();
var context = currentApplication.getApplicationContext();

var data = {

    filesDirectory: context.getFilesDir().getAbsolutePath().toString(),
    cacheDirectory: context.getCacheDir().getAbsolutePath().toString(),
    externalCacheDirectory: context.getExternalCacheDir().getAbsolutePath().toString(),
    codeCacheDirectory: 'getCodeCacheDir' in context ? context.getCodeCacheDir().getAbsolutePath().toString() : 'n/a',
    obbDir: context.getObbDir().getAbsolutePath().toString(),
    packageCodePath: context.getPackageCodePath().toString()
};


send(JSON.stringify(data, null, 2));
