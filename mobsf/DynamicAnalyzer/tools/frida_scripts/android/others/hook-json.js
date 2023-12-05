// Source: https://github.com/apkunpacker/FridaScripts
Java.performNow(function() {
    try {
        var JSONO = Java.use("org.json.JSONObject");
        JSONO.optString.overload("java.lang.String").implementation = function(str) {
            var JsonRet = this.optString(str);
            console.log("JsonOptStr : ", str, JsonRet);
            return JsonRet;
        }
        JSONO.optString.overload("java.lang.String", "java.lang.String").implementation = function(str, str2) {
            var JsonRet = this.optString(str, str2);
            console.log("JsonOptStr2 : ", str, str2, JsonRet);
            return JsonRet;
        }
        JSONO.numberToString.overload('java.lang.Number').implementation = function(N) {
            var JsonRet = this.numberToString(N);
            console.log("numberToString : ", N, JsonRet);
            return JsonRet;
        }
        JSONO.getJSONArray.overload('java.lang.String').implementation = function(str) {
            var JsonRet = this.getJSONArray(str);
            console.log("getJSONArray : ", str, JsonRet);
            return JsonRet;
        }
        JSONO.getJSONObject.overload('java.lang.String').implementation = function(str) {
            var JsonRet = this.getJSONObject(str);
            console.log("getJSONObject : ", str, JsonRet);
            return JsonRet;
        }
        JSONO.names.overload().implementation = function() {
            var JsonRet = this.names(str);
            console.log("names : ", JsonRet);
            return JsonRet;
        }
        JSONO.opt.overload('java.lang.String').implementation = function(str) {
            var JsonRet = this.opt(str);
            console.log("opt : ", str, JsonRet);
            return JsonRet;
        }
        JSONO.optJSONArray.overload('java.lang.String').implementation = function(str) {
            var JsonRet = this.optJSONArray(str);
            console.log("optJSONArray : ", str, JsonRet);
            return JsonRet;
        }
        JSONO.optJSONObject.overload('java.lang.String').implementation = function(str) {
            var JsonRet = this.optJSONObject(str);
            console.log("optJSONObject : ", str, JsonRet);
            return JsonRet;
        }
        JSONO.put.overload('java.lang.String', 'double').implementation = function(str, d) {
            var JsonRet = this.put(str, d);
            console.log("put D : ", str, d, JsonRet);
            return JsonRet;
        }
        JSONO.put.overload('java.lang.String', 'int').implementation = function(str, i) {
            var JsonRet = this.put(str, i);
            console.log("put i : ", str, i, JsonRet);
            return JsonRet;
        }
        JSONO.put.overload('java.lang.String', 'long').implementation = function(str, l) {
            var JsonRet = this.put(str, l);
            console.log("put l : ", str, l, JsonRet);
            return JsonRet;
        }
        JSONO.put.overload('java.lang.String', 'java.lang.Object').implementation = function(str, obj) {
            var JsonRet = this.put(str, obj);
            console.log("put Obj : ", str, obj, JsonRet);
            return JsonRet;
        }
        JSONO.put.overload('java.lang.String', 'boolean').implementation = function(str, b) {
            var JsonRet = this.put(str, b);
            console.log("put bool : ", str, b, JsonRet);
            return JsonRet;
        }
        JSONO.putOpt.overload('java.lang.String', 'java.lang.Object').implementation = function(str, ob) {
            var JsonRet = this.putOpt(str, ob);
            console.log("putOpt : ", str, ob, JsonRet);
            return JsonRet;
        }
        JSONO.toJSONArray.overload('org.json.JSONArray').implementation = function(arr) {
            var JsonRet = this.toJSONArray(arr);
            console.log("toJSONArray : ", arr, JsonRet);
            return JsonRet;
        }
        JSONO["toString"].overload('int').implementation = function(i) {
            var JsonRet = this["toString"](i);
            console.log("toString i : ", i, JsonRet);
            return JsonRet;
        }
        JSONO["toString"].overload().implementation = function() {
            var JsonRet = this["toString"]();
            console.log("toString  : ", JsonRet);
            return JsonRet;
        }
    } catch (e) {
        console.error(e);
    }
})
