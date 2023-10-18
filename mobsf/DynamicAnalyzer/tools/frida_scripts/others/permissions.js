Java.perform(function() {
  // Permission and Malware Score states
  var permissionList = [];
  var malwareScore = 0;

  // Declare permission malware scoring mapping
  var permissionMap = {
    "READ_SMS" : 'uid1',
    "RECEIVE_SMS" : 'uid2',
    "WRITE_SMS" : 'uid3',
    "SEND_SMS" : 'uid4',
    "READ_CONTACTS" : 'uid5',
    "RECORD_AUDIO" : 'uid6',
    "ACCESS_FINE_LOCATION" : 'uid7',
    "ACCESS_COARSE_LOCATION" : 'uid',
    "CAMERA" : 'uid8',
    "READ_EXTERNAL_STORAGE" : 'uid9',
    "WRITE_EXTERNAL_STORAGE" : 'uid10',
    "SYSTEM_ALERT_WINDOW" : 'uid11',
    "CALL_PHONE" : 'uid12',
    "REQUEST_INSTALL_PACKAGES" : 'uid13',
    // "MANAGE_DEVICE_POLICY_CAMERA" : 100, // under research
  };



  // Dynamically checks permissions
  var checkPermission = function(permission) {
    // Declare android objects
    var ManifestPermission = Java.use('android.Manifest$permission');
    var PackageManagerClass = Java.use('android.content.pm.PackageManager');
    var ProcessClass = Java.use('android.os.Process');
    var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    
    if (context == null) {
      send('[] Context is null. Unable to check permission.');
      return;
    }

    var permissionStatus = PackageManagerClass.PERMISSION_DENIED.value;

    try {
      permissionStatus = context.checkPermission(ManifestPermission[permission].value, ProcessClass.myPid(), ProcessClass.myUid());
    } catch (e) {
      send('[] Error occurred while checking permission: ' + e);
    }

    if (permissionStatus === PackageManagerClass.PERMISSION_GRANTED.value) {
      send('[+] Permission ' + permission + ' is used in the application.');
      // Adds to permission list
      permissionList.push(permission);
    } else {
      send('[-] Permission ' + permission + ' is NOT used in the application.');
    }
  };



  // Adds to malware score based on permission type
  var malwareScoring = function(permissionList) {
      // Iterates list of permissions to add to malware score
      for (var permission in permissionList) {
          if (permissionList[permission] in permissionMap) {
              malwareScore += permissionMap[permissionList[permission]];
          }
      }

      send('[*] Malware score is ' + malwareScore);
      
      if (malwareScore.includes("uid13")){
        send('[*] Dropper or CMC____________');
      }
      if (malwareScore.includes("uid11")){
        send('[*] Ransomeware____________');
      }
      if (malwareScore.includes("uid")){
        send('[*] Dropper or CMC____________');
      }
  };
/*
  var test = function(permissionList) {
    // Iterates list of permissions to add to malware score
    for (var permission in permissionList) {
        if (permissionList[permission] in permissionMap) {
            malwareScore += permissionMap[permissionList[permission]];
        }
    }

    if (malwareScore.includes("uid13")){
      send('[*] Dropper or CMC____________');
    }
};
*/

  // Check for SMS and Contacts permissions
  checkPermission("READ_SMS");
  checkPermission("RECEIVE_SMS");
  checkPermission("WRITE_SMS");
  checkPermission("SEND_SMS");
  checkPermission("READ_CONTACTS");
  // Check for Spyware permissions
  checkPermission("RECORD_AUDIO");
  checkPermission("ACCESS_FINE_LOCATION");
  checkPermission("CAMERA");
  // Check for Disk Access permissions
  checkPermission("READ_EXTERNAL_STORAGE");
  checkPermission("WRITE_EXTERNAL_STORAGE");
  // Check for Super SUS permissions
  checkPermission("SYSTEM_ALERT_WINDOW");
  checkPermission("CALL_PHONE");
  checkPermission("REQUEST_INSTALL_PACKAGES");
  //checkPermission("MANAGE_DEVICE_POLICY_CAMERA"); // under research

  // Get malware score
  malwareScoring(permissionList);
  
});