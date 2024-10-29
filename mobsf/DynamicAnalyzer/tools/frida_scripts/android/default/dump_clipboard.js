// Based on https://github.com/sensepost/objection/blob/f8e78d8a29574c6dadd2b953a63207b45a19b1cf/objection/hooks/android/clipboard/monitor.js
// Variable used for the current string data
var string_data;

function check_clipboard_data() {

    Java.perform(function () {
        var ActivityThread = Java.use('android.app.ActivityThread');
        var ClipboardManager = Java.use('android.content.ClipboardManager');
        var CLIPBOARD_SERVICE = 'clipboard';

        var currentApplication = ActivityThread.currentApplication();
        var context = currentApplication.getApplicationContext();

        var clipboard_handle = context.getApplicationContext().getSystemService(CLIPBOARD_SERVICE);
        var clipboard = Java.cast(clipboard_handle, ClipboardManager);

        setInterval(function(){

            var primary_clip = clipboard.getPrimaryClip();

            // If we have managed to get the primary clipboard and there are
            // items stored in it, process an update.
            if (primary_clip != null && primary_clip.getItemCount() > 0) {
    
                var data = primary_clip.getItemAt(0).coerceToText(context).toString();
    
                // If the data is the same, just stop.
                if (string_data == data) {
                    return;
                }
    
                // Update the data with the new string and report back.
                string_data = data;
                send('mobsf-android-clipboard:' + data);
            }
        // Poll every 5 seconds
        }, 1000 * 5);
    });
}

check_clipboard_data();