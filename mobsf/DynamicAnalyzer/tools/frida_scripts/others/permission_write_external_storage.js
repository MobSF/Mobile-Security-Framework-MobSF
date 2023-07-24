Java.perform(function() {
    var checkPermissionScript = function() {
      var ManifestPermission = Java.use('android.Manifest$permission');
      var PackageManagerClass = Java.use('android.content.pm.PackageManager');
      var ProcessClass = Java.use('android.os.Process');
  
      var hasPermission = PackageManagerClass.PERMISSION_GRANTED.value;
  
      var checkPermission = function(permission) {
        var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  
        if (context == null) {
          send('[*] Context is null. Unable to check permission.');
          return;
        }
  
        var permissionStatus = PackageManagerClass.PERMISSION_DENIED.value;
  
        try {
          permissionStatus = context.checkPermission(permission, ProcessClass.myPid(), ProcessClass.myUid());
        } catch (e) {
          send('[*] Error occurred while checking permission: ' + e);
        }
  
        if (permissionStatus === hasPermission) {
          send('[+] Permission ' + permission + ' is used in the application.');
        } else {
          send('[-] Permission ' + permission + ' is NOT used in the application.');
        }
      };
  
      var checkStoragePermission = function() {
        var readExternalStoragePermission = ManifestPermission.READ_EXTERNAL_STORAGE.value;
        var writeExternalStoragePermission = ManifestPermission.WRITE_EXTERNAL_STORAGE.value;
        checkPermission(readExternalStoragePermission);
        checkPermission(writeExternalStoragePermission);
      };
  
      checkStoragePermission();
    };
  
    // Call the function immediately
    checkPermissionScript();
  
    // Then call the function every 5 seconds
    setInterval(checkPermissionScript, 5000);
  });
  