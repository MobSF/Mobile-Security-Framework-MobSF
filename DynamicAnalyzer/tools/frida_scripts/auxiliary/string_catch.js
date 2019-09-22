Java.perform(function() {
  ['java.lang.StringBuilder', 'java.lang.StringBuffer'].forEach(function(clazz, i) {
    var func = 'toString';
    Java.use(clazz)[func].implementation = function() {
      var ret = this[func]();
      send('[AUXILIARY] [String Catch] [' + i + '] ' + ret);
      return ret;
    }   
  }); 
});
