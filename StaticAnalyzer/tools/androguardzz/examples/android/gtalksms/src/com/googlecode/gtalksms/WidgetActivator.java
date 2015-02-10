package com.googlecode.gtalksms;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/** Allows the application to start at boot */
public class WidgetActivator extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        Intent serviceIntent = new Intent(".GTalkSMS.ACTION");
      
        if (XmppService.getInstance() == null) {
            context.startService(serviceIntent);
            Log.i(XmppService.LOG_TAG, "WidgetActivator startService");
        } else {
            context.stopService(serviceIntent);
            Log.i(XmppService.LOG_TAG, "WidgetActivator stopService");
        }
    }
}
