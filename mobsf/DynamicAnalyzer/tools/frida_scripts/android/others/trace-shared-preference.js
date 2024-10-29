/************************************************************************
 * Name: SharedPreferences Monitor
 * OS: Android
 * Author: @mobilesecurity_
 * Source: https://github.com/m0bilesecurity
 * Info:
    * android.app.SharedPreferencesImpl
    * android.app.SharedPreferencesImpl$EditorImpl
*************************************************************************/

Java.perform(function () {
    var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
    var SharedPreferencesImpl_EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
  
    SharedPreferencesImpl.contains.implementation = function (key) {
      var value = this.contains.apply(this, arguments);
      print("contains",key,value);
      return value;
    };
  
    SharedPreferencesImpl.getInt.implementation = function (key, defValue) {
      var value = this.getInt.apply(this, arguments);
      print("getInt",key,value);
      return value;
    };
  
    SharedPreferencesImpl.getFloat.implementation = function (key, defValue) {
      var value = this.getFloat.apply(this, arguments);
      print("getFloat",key,value);
      return value;
    };
  
    SharedPreferencesImpl.getLong.implementation = function (key, defValue) {
      var value = this.getLong.apply(this, arguments);
      print("getLong",key,value);
      return value;
    };
  
    SharedPreferencesImpl.getBoolean.implementation = function (key, defValue) {
      var value = this.getBoolean.apply(this, arguments);
      print("getBoolean",key,value);
      return value;
    };
  
    SharedPreferencesImpl.getString.implementation = function (key, defValue) {
      var value = this.getString.apply(this, arguments);
      print("getString",key,value);
      return value;
    };
  
    SharedPreferencesImpl.getStringSet.implementation = function (key, defValue) {
      var value = this.getStringSet.apply(this, arguments);
      print("getStringSet",key,value);
      return value;
    };
  
    SharedPreferencesImpl_EditorImpl.putString.implementation = function (key, value) {
      print("putString",key,value);
      return this.putString.apply(this, arguments);
    };
  
    SharedPreferencesImpl_EditorImpl.putStringSet.implementation = function (key, values) {
      print("putStringSet",key,values);
      return this.putStringSet.apply(this, arguments);
    };
  
    SharedPreferencesImpl_EditorImpl.putInt.implementation = function (key, value) {
      print("putInt",key,value);
      return this.putInt.apply(this, arguments);
    };
  
    SharedPreferencesImpl_EditorImpl.putFloat.implementation = function (key, value) {
      print("putFloat",key,value);
      return this.putFloat.apply(this, arguments);
    };
  
    SharedPreferencesImpl_EditorImpl.putBoolean.implementation = function (key, value) {
      print("putBoolean",key,value);
      return this.putBoolean.apply(this, arguments);
    };
  
    SharedPreferencesImpl_EditorImpl.putLong.implementation = function (key, value) {
      print("putLong",key,value);
      return this.putLong.apply(this, arguments);
    };
  
    SharedPreferencesImpl_EditorImpl.remove.implementation = function (key) {
      print("remove",key,"");
      return this.remove.apply(this, arguments);
    };
  
    function print(method,key,value){
      var mkey = key ? key.toString() : 'null';
      var mvalue = value ? value.toString() : 'null';
  
      send("API Monitor | "+
           "SharedPreferences" + " | " +
           method + " - " +
           "(" + mkey + ":" + mvalue + ")"
          );
    }
  });