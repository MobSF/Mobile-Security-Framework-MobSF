function monitorCpuUsage() {
  // Java class for obtaining the PID
  var process = Java.use('android.os.Process');
  // Java class for getting current time (nanoseconds)
  var System = Java.use('java.lang.System');
  // Java class for getting available processors
  var Runtime = Java.use('java.lang.Runtime');
  // Both Java classes used for reading /proc/pid/stat file
  var BufferedReader = Java.use('java.io.BufferedReader');
  var FileReader = Java.use('java.io.FileReader');
  var pid = process.myPid();
  var utime, stime;
  var cpuUsage = 0.0;
  
  var getCPU = function () {
    var reader = null;
    try {
      reader = BufferedReader.$new(FileReader.$new("/proc/" + pid + "/stat"));
      var line = reader.readLine();
      var fields = line.split(" ");
      // utime refers to time spent by cpu to run user level processes
      utime = parseInt(fields[13]);
      // stime refers to time spent by cpu to run system level processes
      stime = parseInt(fields[14]);
    } catch (e) {
      console.error(e);
    } finally {
      if (reader !== null) {
        try {
          reader.close();
        } catch (e) {
          console.error(e);
        }
      }
    }
  };
  
  var updateCPU = function () {
    getCPU();
    var total_time = utime + stime;
    var elapsed_time = System.nanoTime() - startTime;
    cpuUsage = (total_time - prevCpuTime) / (elapsed_time / 1000000) / cpus * 100;
    // prevCPUTime refers to time since last time function was invoked
    prevCpuTime = total_time;
    startTime = System.nanoTime();
  };
  
  var cpus = Runtime.getRuntime().availableProcessors();
  var prevCpuTime = 0;
  var startTime = System.nanoTime();
  
  setInterval(function() {
    updateCPU();
    send('CPU usage: ' + cpuUsage.toFixed(2) + '%');
  }, 1000);
}

Java.perform(monitorCpuUsage);
