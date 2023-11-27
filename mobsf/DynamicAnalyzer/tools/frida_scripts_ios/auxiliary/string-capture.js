function captureString() {
  send('Capturing strings')
  Interceptor.attach(ObjC.classes.NSString['+ stringWithUTF8String:'].implementation, {
    onLeave: function (retval) {
      var str = new ObjC.Object(ptr(retval)).toString()
      send('[AUXILIARY] [NSString stringWithUTF8String:] -> '+ str);
      return retval;
    }
  });
}

try {
  captureString();
} catch(err) {}