Java.perform(function () {
  var Activity = Java.use("android.app.Activity");

  Activity.getIntent.overload().implementation = function () {
      var intent = this.getIntent();
      var component = intent.getComponent();
      
      send("[Intent Dumper] Captured Intent for Activity:");
      
      // Component (target package and class)
      if (component) {
          send("  Component:");
          send("    Package: " + component.getPackageName());
          send("    Class: " + component.getClassName());
      } else {
          send("  Component: None");
      }

      // Action
      var action = intent.getAction();
      send("  Action: " + (action ? action : "None"));

      // Data URI
      var dataUri = intent.getDataString();
      send("  Data URI: " + (dataUri ? dataUri : "None"));

      // Flags
      var flags = intent.getFlags();
      send("  Flags: " + flags);

      // Dumping extras in the Intent
      var extras = intent.getExtras();
      if (extras) {
          send("  Extras:");
          var iterator = extras.keySet().iterator();
          while (iterator.hasNext()) {
              var key = iterator.next();
              var value = extras.get(key);
              if (value !== null) {
                  send("    " + key + " (" + value.getClass().getName() + "): " + valueToString(value));
              }
          }
      } else {
          send("  Extras: None");
      }

      return intent;
  };

  // Helper function to convert intent extras to a readable string
  function valueToString(value) {
      var valueType = value.getClass().getName();

      if (valueType === "android.os.Bundle") {
          return bundleToString(Java.cast(value, Java.use("android.os.Bundle")));
      } else if (valueType === "java.lang.String") {
          return '"' + value + '"';
      } else if (valueType === "java.lang.Integer" || valueType === "java.lang.Float" || valueType === "java.lang.Boolean") {
          return value.toString();
      } else if (valueType === "java.util.ArrayList") {
          return arrayListToString(Java.cast(value, Java.use("java.util.ArrayList")));
      } else {
          send("Unsupported extra type for key. Type: " + valueType);
          return value.toString();
      }
  }

  // Function to handle nested Bundles
  function bundleToString(bundle) {
      var result = "{";
      var iterator = bundle.keySet().iterator();
      while (iterator.hasNext()) {
          var key = iterator.next();
          var value = bundle.get(key);
          result += key + ": " + (value !== null ? valueToString(value) : "null") + ", ";
      }
      result = result.slice(0, -2); // Remove trailing comma and space
      result += "}";
      return result;
  }

  // Function to handle ArrayLists (if any)
  function arrayListToString(arrayList) {
      var result = "[";
      for (var i = 0; i < arrayList.size(); i++) {
          var item = arrayList.get(i);
          result += valueToString(item) + ", ";
      }
      result = result.slice(0, -2); // Remove trailing comma and space
      result += "]";
      return result;
  }
});
