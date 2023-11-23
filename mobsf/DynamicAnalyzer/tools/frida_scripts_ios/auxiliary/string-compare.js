send('Capturing string comparisons')
Interceptor.attach(ObjC.classes.__NSCFString['- isEqualToString:'].implementation, {
    onEnter: function (args) {
      var str = new ObjC.Object(ptr(args[2])).toString()
      send('[AUXILIARY] __NSCFString[- isEqualToString:] -> ' + str);
    }
});

Interceptor.attach(ObjC.classes.NSTaggedPointerString['- isEqualToString:'].implementation, {
    onEnter: function (args) {
      var str = new ObjC.Object(ptr(args[2])).toString()
      send('[AUXILIARY] NSTaggedPointerString[- isEqualToString:] -> '+ str);
    }
});
