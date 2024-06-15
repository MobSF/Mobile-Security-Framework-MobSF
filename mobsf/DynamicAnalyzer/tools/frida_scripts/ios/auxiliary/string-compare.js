function captureStringCompare() {
  send('Capturing string comparisons')
  Interceptor.attach(ObjC.classes.__NSCFString['- isEqualToString:'].implementation, {
    onEnter: function (args) {
      var src = new ObjC.Object(ptr(args[0])).toString()
      var str = new ObjC.Object(ptr(args[2])).toString()
      send('[AUXILIARY] [__NSCFString isEqualToString:] -> \nstring 1: '+ src + '\nstring 2: '+ str);
    }
  });
}

function captureStringCompare2(){
  Interceptor.attach(ObjC.classes.NSTaggedPointerString['- isEqualToString:'].implementation, {
    onEnter: function (args) {
      var src = new ObjC.Object(ptr(args[0])).toString()
      var str = new ObjC.Object(ptr(args[2])).toString()
      send('[AUXILIARY] NSTaggedPointerString[- isEqualToString:] -> \nstring 1: '+ src + '\nstring 2: '+ str);
    }
  });
}
try {
  captureStringCompare();
} catch(err) {}

try {
  captureStringCompare2();
} catch(err) {}