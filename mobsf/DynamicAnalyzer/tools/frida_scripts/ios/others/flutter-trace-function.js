/* Description: iOS flutter trace function
 * Mode: S+A
 * Version: 1.0
 * Credit: https://gist.github.com/AICDEV/630feed7583561ec9f9421976e836f90
 * Author: @AICDEV
 */
/**
 * run the script to a running app: frida -U "appName" -l flutter_ios.js --no-pause
 * start app direct with the script:  frida -Uf bundleIdentifier -l flutter_ios.js --no-pause
 */
// #############################################
// HELPER SECTION START
var colors = {
    "resetColor": "\x1b[0m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "red": "\x1b[31m"
}

function logSection(message) {
    send("#################################################");
    send(message);
    send("#################################################");
}

function logMessage(message) {
    send("---> " + message);
}

function logError(message) {
    send("---> ERRROR: " + message);
}

function getAllClasses() {
    var classes = [];
    for (var cl in ObjC.classes) {
        classes.push(cl);
    }
    return classes;
}

function filterFlutterClass() {
    var matchClasses = [];
    var classes = getAllClasses();

    for (var i = 0; i < classes.length; i++) {
        if (classes[i].toString().toLowerCase().includes('flu')) {
            matchClasses.push(classes[i]);
        }
    }

    return matchClasses;
}


function getAllMethodsFromClass(cl) {
    return ObjC.classes[cl].$ownMethods;
}

function listAllMethodsFromClasses(classes) {
    for (var i = 0; i < classes.length; i++) {
        var methods = getAllMethodsFromClass(classes[i]);
        for (var a = 0; a < methods.length; a++) {
            logMessage("class: " + classes[i] + " --> method: " + methods[a]);
        }
    }
}

function blindCallDetection(classes) {
    for (var i = 0; i < classes.length; i++) {
        var methods = getAllMethodsFromClass(classes[i]);
        for (var a = 0; a < methods.length; a++) {
            var hook = ObjC.classes[classes[i]][methods[a]];
            try {
                Interceptor.attach(hook.implementation, {
                    onEnter: function (args) {
                        this.className = ObjC.Object(args[0]).toString();
                        this.methodName = ObjC.selectorAsString(args[1]);
                        logMessage("detect call to: " + this.className + ":" + this.methodName);
                    }
                })
            } catch (err) {
                logError("error in trace blindCallDetection");
                logError(err);
            }
        }
    }
}

function singleBlindTracer(className, methodName) {
    try {
        var hook = ObjC.classes[className][methodName];
        Interceptor.attach(hook.implementation, {
            onEnter: function (args) {
                this.className = ObjC.Object(args[0]).toString();
                this.methodName = ObjC.selectorAsString(args[1]);
                logMessage("detect call to: " + this.className + ":" + this.methodName);
            }
        })
    } catch (err) {
        logError("error in trace singleBlindTracer");
        logError(err);
    }
}

// #############################################
//HELPER SECTION END
// #############################################
// BEGIN FLUTTER SECTION
// #############################################
function listAllFlutterClassesAndMethods() {
    var flutterClasses = filterFlutterClass();
    for (var i = 0; i < flutterClasses.length; i++) {
        var methods = getAllMethodsFromClass(flutterClasses[i]);
        for (var a = 0; a < methods.length; a++) {
            logMessage("class: " + flutterClasses[i] + " --> method: " + methods[a]);
        }
    }
}
// https://api.flutter.dev/objcdoc/Classes/FlutterMethodCall.html#/c:objc(cs)FlutterMethodCall(cm)methodCallWithMethodName:arguments:
function traceFlutterMethodCall() {
    var className = "FlutterMethodCall"
    var methodName = "+ methodCallWithMethodName:arguments:"
    var hook = ObjC.classes[className][methodName];

    try {
        Interceptor.attach(hook.implementation, {
            onEnter: function (args) {

                this.className = ObjC.Object(args[0]).toString();
                this.methodName = ObjC.selectorAsString(args[1]);
                logMessage(this.className + ":" + this.methodName);
                logMessage("method: " + ObjC.Object(args[2]).toString());
                logMessage("args: " + ObjC.Object(args[3]).toString());
            }
        })
    } catch (err) {
        logError("error in trace FlutterMethodCall");
        logError(err);
    }
}

// https://api.flutter.dev/objcdoc/Classes/FlutterMethodChannel.html#/c:objc(cs)FlutterMethodChannel(im)invokeMethod:arguments:
function traceFlutterMethodChannel() {
    var className = "FlutterMethodChannel"
    var methodName = "- setMethodCallHandler:"
    var hook = ObjC.classes[className][methodName];

    try {
        Interceptor.attach(hook.implementation, {
            onEnter: function (args) {
                this.className = ObjC.Object(args[0]).toString();
                this.methodName = ObjC.selectorAsString(args[1]);
                logMessage(this.className + ":" + this.methodName);
                logMessage("method: " + ObjC.Object(args[2]).toString());
            }
        })
    } catch (err) {
        logError("error in trace FlutterMethodChannel");
        logError(err);
    }
}

// enum function from defined classes
function inspectInteresingFlutterClasses(classes) {
    logSection("START BLIND TRACE FOR SPECIFIED METHODS");
    for (var i = 0; i < classes.length; i++) {
        logMessage("inspect all methods from: " + classes[i]);
        var methods = getAllMethodsFromClass(classes[i]);
        for (var a = 0; a < methods.length; a++) {
            logMessage("method --> " + methods[a]);
            blindTraceWithPayload(classes[i], methods[a]);
        }
    }
}

function blindTraceWithPayload(className, methodName) {
    try {
        var hook = ObjC.classes[className][methodName];
        Interceptor.attach(hook.implementation, {
            onEnter: function (args) {
                this.className = ObjC.Object(args[0]).toString();
                this.methodName = ObjC.selectorAsString(args[1]);
                logMessage(this.className + ":" + this.methodName);
                logMessage("payload: " + ObjC.Object(args[2]).toString());
            },
        })
    } catch (err) {
        logError("error in blind trace");
        logError(err);
    }
}

// #############################################
// END FLUTTER SECTION
// #############################################
/**
 * check if a method in the specified class get called
 */
logSection("BLIND TRACE NATIVE FUNCTION");
var blindCallClasses = [
    "FlutterStringCodec",
]
blindCallDetection(blindCallClasses);

/**
 * List found flutter classes and there methods
 */
logSection("SEARCH ALL FLUTTER CLASSES AND METHODS");
listAllFlutterClassesAndMethods();


/**
 * define custom class for further investigation. be careful: it calls blindTraceWithPayload logMessage("payload: " + ObjC.Object(args[2]).toString());
 * If you are not sure if the arg[2] is present read the function docs or do some try catch
 */
var interestingFlutterClasses = [
    //https://api.flutter.dev/objcdoc/Protocols/FlutterMessageCodec.html#/c:objc(pl)FlutterMessageCodec(im)encode:
    "FlutterJSONMessageCodec",
    //https://api.flutter.dev/objcdoc/Protocols/FlutterMethodCodec.html
    "FlutterJSONMethodCodec",
    "FlutterStandardReader",
    //https://api.flutter.dev/objcdoc/Classes/FlutterEventChannel.html
    "FlutterEventChannel",
    //https://api.flutter.dev/objcdoc/Classes/FlutterViewController.html
    //"FlutterViewController",
    //https://api.flutter.dev/objcdoc/Classes/FlutterBasicMessageChannel.html
    "FlutterBasicMessageChannel",
]

inspectInteresingFlutterClasses(interestingFlutterClasses)

/**
 * trace implementation for
 * https://api.flutter.dev/objcdoc/Classes/FlutterMethodCall.html
 * https://api.flutter.dev/objcdoc/Classes/FlutterMethodChannel.html
 */
logSection("TRACING FLUTTER BEHAVIOUR");
traceFlutterMethodCall();
traceFlutterMethodChannel();


logSection("SINGLE BLIND TRACING");
singleBlindTracer("FlutterObservatoryPublisher","- url")
