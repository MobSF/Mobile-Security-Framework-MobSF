function captureStringCompare() {
  send('Capturing string comparisons')
  Interceptor.attach(ObjC.classes.NSString['- isEqualToString:'].implementation, {
    onEnter: function (args) {
      var str = new ObjC.Object(ptr(args[2])).toString()
      send('[AUXILIARY] [NSString isEqualToString:] -> '+ str);
    }
  });
}

function captureStringCompare2(){
  Interceptor.attach(ObjC.classes.NSTaggedPointerString['- isEqualToString:'].implementation, {
    onEnter: function (args) {
      var str = new ObjC.Object(ptr(args[2])).toString()
      send('[AUXILIARY] NSTaggedPointerString[- isEqualToString:] -> '+ str);
    }
  });
}
try {
  captureStringCompare();
} catch(err) {}

try {
  captureStringCompare2();
} catch(err) {}