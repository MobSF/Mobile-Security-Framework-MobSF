package com.googlecode.gtalksms;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;

/** Allows the application to start at boot */
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        SharedPreferences prefs = context.getSharedPreferences("GTalkSMS", 0);
        boolean startAtBoot = prefs.getBoolean("startAtBoot", false);
        if (startAtBoot) {
            Intent serviceIntent = new Intent(".GTalkSMS.ACTION");
            context.startService(serviceIntent);
        }
    }
}
