Java.perform(function() {
  var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  var BroadcastReceiver = Java.use('android.content.BroadcastReceiver');

  var BatteryReceiver = Java.registerClass({
      name: 'com.example.BatteryReceiver',
      superClass: BroadcastReceiver,
      methods: {
          onReceive: {
              implementation: function(context, intent) {
                  var level = intent.getIntExtra(Java.use('android.os.BatteryManager').EXTRA_LEVEL.value, -1);
                  var scale = intent.getIntExtra(Java.use('android.os.BatteryManager').EXTRA_SCALE.value, -1);
                  var voltage = intent.getIntExtra(Java.use('android.os.BatteryManager').EXTRA_VOLTAGE.value, -1);
                  var temperature = intent.getIntExtra(Java.use('android.os.BatteryManager').EXTRA_TEMPERATURE.value, -1);

                  send("Battery level (out of scale) -> " + level + " / " + scale);
                  send("Battery voltage -> " + voltage);
                  send("Battery temperature -> " + temperature);
              }
          },
          getDebugUnregister: {
              implementation: function() {
                  return BroadcastReceiver.getDebugUnregister.call(this);
              }
          },
          setDebugUnregister: {
              implementation: function(debugUnregister) {
                  BroadcastReceiver.setDebugUnregister.call(this, debugUnregister);
              }
          }
      }
  });

  var IntentFilter = Java.use('android.content.IntentFilter');
  context.registerReceiver(BatteryReceiver.$new(), IntentFilter.$new('android.intent.action.BATTERY_CHANGED'));
});
