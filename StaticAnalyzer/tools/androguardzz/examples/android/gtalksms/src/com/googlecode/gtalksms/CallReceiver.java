package com.googlecode.gtalksms;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.telephony.PhoneStateListener;
import android.telephony.TelephonyManager;

public class CallReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        SharedPreferences prefs = context.getSharedPreferences("GTalkSMS", 0);
        boolean notifyIncomingCalls = prefs.getBoolean("notifyIncomingCalls", false);

        if (notifyIncomingCalls) {
            PhoneCallListener phoneListener = new PhoneCallListener();
            TelephonyManager telephony = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
            telephony.listen(phoneListener, PhoneStateListener.LISTEN_CALL_STATE);
        }
    }
}
