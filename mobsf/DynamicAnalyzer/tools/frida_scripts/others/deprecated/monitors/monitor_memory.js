Java.perform(function() {
  var Runtime = Java.use('java.lang.Runtime');

  // Function to monitor memory usage
  function monitorMemoryUsage() {
    var runtime = Runtime.getRuntime();
    var totalMemory = runtime.totalMemory();
    var freeMemory = runtime.freeMemory();
    var usedMemory = totalMemory - freeMemory;
    var memoryUsagePercentage = (usedMemory / totalMemory) * 100;

    send('Total Memory (bytes): ' + totalMemory);
    send('Free Memory (bytes): ' + freeMemory);
    send('Used Memory (bytes): ' + usedMemory);
    send('Memory Usage (%): ' + memoryUsagePercentage.toFixed(2));
  }

  // Schedule memory monitoring every 10 seconds
  setInterval(monitorMemoryUsage, 10000);
});




  