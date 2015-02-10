package com.googlecode.gtalksms;

import android.content.Context;
import android.content.SharedPreferences;
import android.provider.Settings;

public class SettingsManager {
    // XMPP connection
    public String serverHost;
    public String serviceName;
    public int serverPort;
    
    public String mLogin;
    public String mPassword;
    public String mTo;
    public boolean useDifferentAccount;
    
    // notifications
    public boolean notifyApplicationConnection;
    public boolean formatChatResponses;

    // ring
    public String ringtone = null;

    // battery
    public boolean notifyBattery;
    public int batteryNotificationInterval;

    // sms
    public int smsNumber;
    public boolean displaySentSms;
    public boolean notifySmsSent;
    public boolean notifySmsDelivered;
    
    // calls
    public int callLogsNumber;
    
    /** imports the preferences */
    public void importPreferences(Context c) {
        
        SharedPreferences prefs = c.getSharedPreferences("GTalkSMS", 0);
        
        serverHost = prefs.getString("serverHost", "");
        serverPort = prefs.getInt("serverPort", 0);
        serviceName = prefs.getString("serviceName", "");
        mTo = prefs.getString("notifiedAddress", "");
        mPassword =  prefs.getString("password", "");
        useDifferentAccount = prefs.getBoolean("useDifferentAccount", false);
        if (useDifferentAccount) {
            mLogin = prefs.getString("login", "");
        } else{
            mLogin = mTo;
        }
        
        notifyApplicationConnection = prefs.getBoolean("notifyApplicationConnection", true);
        notifyBattery = prefs.getBoolean("notifyBattery", true);
        batteryNotificationInterval = Integer.valueOf(prefs.getString("batteryNotificationInterval", "10"));
        notifySmsSent = prefs.getBoolean("notifySmsSent", true);
        notifySmsDelivered = prefs.getBoolean("notifySmsDelivered", true);
        ringtone = prefs.getString("ringtone", Settings.System.DEFAULT_RINGTONE_URI.toString());
        displaySentSms = prefs.getBoolean("showSentSms", false);
        smsNumber = prefs.getInt("smsNumber", 5);
        callLogsNumber = prefs.getInt("callLogsNumber", 10);
        formatChatResponses = prefs.getBoolean("formatResponses", false);
    }
}
