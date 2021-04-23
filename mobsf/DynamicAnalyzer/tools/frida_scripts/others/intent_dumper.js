// https://gist.github.com/bet4it/b62ac2d5bd45b8cb699905fa498baf5e
Java.perform(function () {
    var act = Java.use("android.app.Activity");
    act.getIntent.overload().implementation = function () {
      var intent = this.getIntent()
      var cp = intent.getComponent()
      send("[Intent Dumper] Starting " + cp.getPackageName() + "/" + cp.getClassName())
      var ext = intent.getExtras();
      if (ext) {
        var keys = ext.keySet()
        var iterator = keys.iterator()
        while (iterator.hasNext()) {
          var k = iterator.next().toString()
          var v = ext.get(k)
          send("\t" + v.getClass().getName())
          send("\t" + k + ' : ' + v.toString())
        }
      }
    return intent;
    };
 })