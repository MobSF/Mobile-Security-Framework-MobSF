// Based on https://github.com/iddoeldor/frida-snippets#device-properties
  
var UIDevice = ObjC.classes.UIDevice.currentDevice();
UIDevice.$ownMethods
  .filter(function(method) { 
    return method.indexOf(':') == -1 /* filter out methods with parameters */
       && method.indexOf('+') == -1 /* filter out public methods */
  })
  .forEach(function(method) { 
    send(method + ' : ' + UIDevice[method]())
  })