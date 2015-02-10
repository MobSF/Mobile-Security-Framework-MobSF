package com.googlecode.gtalksms.sms;

import java.util.ArrayList;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.database.Cursor;
import android.net.Uri;
import android.telephony.SmsManager;
import android.text.TextUtils;

import com.googlecode.gtalksms.SettingsManager;
import com.googlecode.gtalksms.Tools;
import com.googlecode.gtalksms.XmppService;
import com.googlecode.gtalksms.contacts.ContactsManager;
import com.googlecode.gtalksms.phone.Phone;

public class SmsMmsManager {

    static SettingsManager Settings = XmppService.Settings;
    
    // intents for sms sending
    public static PendingIntent sentPI = null;
    public static PendingIntent deliveredPI = null;
    public static BroadcastReceiver sentSmsReceiver = null;
    public static BroadcastReceiver deliveredSmsReceiver = null;
    
    /** clear the sms monitoring related stuff */
    public static void clearSmsMonitors() {
        if (sentSmsReceiver != null) {
            XmppService.getInstance().unregisterReceiver(sentSmsReceiver);
        }
        if (deliveredSmsReceiver != null) {
            XmppService.getInstance().unregisterReceiver(deliveredSmsReceiver);
        }
        sentPI = null;
        deliveredPI = null;
        sentSmsReceiver = null;
        deliveredSmsReceiver = null;
    }

    /** reinit sms monitors (that tell the user the status of the sms) */
    public static void initSmsMonitors() {
        if (Settings.notifySmsSent) {
            String SENT = "SMS_SENT";
            sentPI = PendingIntent.getBroadcast(XmppService.getInstance(), 0, new Intent(SENT), 0);
            sentSmsReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context arg0, Intent arg1) {
                    switch (getResultCode()) {
                        case Activity.RESULT_OK:
                            XmppService.getInstance().send("SMS sent");
                            break;
                        case SmsManager.RESULT_ERROR_GENERIC_FAILURE:
                            XmppService.getInstance().send("Generic failure");
                            break;
                        case SmsManager.RESULT_ERROR_NO_SERVICE:
                            XmppService.getInstance().send("No service");
                            break;
                        case SmsManager.RESULT_ERROR_NULL_PDU:
                            XmppService.getInstance().send("Null PDU");
                            break;
                        case SmsManager.RESULT_ERROR_RADIO_OFF:
                            XmppService.getInstance().send("Radio off");
                            break;
                    }
                }
            };
            XmppService.getInstance().registerReceiver(sentSmsReceiver, new IntentFilter(SENT));
        }
    
        if (Settings.notifySmsDelivered) {
            String DELIVERED = "SMS_DELIVERED";
            deliveredPI = PendingIntent.getBroadcast(XmppService.getInstance(), 0, new Intent(DELIVERED), 0);
            deliveredSmsReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context arg0, Intent arg1) {
                    switch (getResultCode()) {
                        case Activity.RESULT_OK:
                            XmppService.getInstance().send("SMS delivered");
                            break;
                        case Activity.RESULT_CANCELED:
                            XmppService.getInstance().send("SMS not delivered");
                            break;
                    }
                }
            };
            XmppService.getInstance().registerReceiver(deliveredSmsReceiver, new IntentFilter(DELIVERED));
        }
    }

    /** Sends a sms to the specified phone number */
    public static void sendSMSByPhoneNumber(String message, String phoneNumber) {
        // send("Sending sms to " + getContactName(phoneNumber));
        SmsManager sms = SmsManager.getDefault();
        ArrayList<String> messages = sms.divideMessage(message);

        // création des liste d'instents
        ArrayList<PendingIntent> listOfSentIntents = new ArrayList<PendingIntent>();
        listOfSentIntents.add(sentPI);
        ArrayList<PendingIntent> listOfDelIntents = new ArrayList<PendingIntent>();
        listOfDelIntents.add(deliveredPI);
        for (int i = 1; i < messages.size(); i++) {
            listOfSentIntents.add(null);
            listOfDelIntents.add(null);
        }

        sms.sendMultipartTextMessage(phoneNumber, null, messages, listOfSentIntents, listOfDelIntents);

        addSmsToSentBox(message, phoneNumber);
    }

    /**
     * Returns a ArrayList of <Sms> with count sms where the contactId match the
     * argument
     */
    public static ArrayList<Sms> getSms(ArrayList<Long> rawIds, String contactName) {
        if (rawIds.size() > 0) {
            return getAllSms("content://sms/inbox", contactName, "person IN (" + TextUtils.join(", ", rawIds) + ")");
        }
        return new ArrayList<Sms>();
    }

    /**
     * Returns a ArrayList of <Sms> with count sms where the contactId match the
     * argument
     */
    public static ArrayList<Sms> getAllSentSms() {
        return getAllSms("content://sms/sent", "Me", null);
    }

    public static ArrayList<Sms> getAllReceivedSms() {
        return getAllSms("content://sms/inbox", null, null);
    }

    private static ArrayList<Sms> getAllSms(String folder, String sender, String where) {
        ArrayList<Sms> res = new ArrayList<Sms>();

        Uri mSmsQueryUri = Uri.parse(folder);
        String columns[] = new String[] { "person", "address", "body", "date", "status" };
        String sortOrder = "date DESC";

        Cursor c = XmppService.getInstance().getContentResolver().query(mSmsQueryUri, columns, where, null, sortOrder);
        int maxSms = Settings.smsNumber;
        int nbSms = 0;
        
        for (boolean hasData = c.moveToFirst(); hasData && nbSms < maxSms; hasData = c.moveToNext(), ++nbSms) {
            Sms sms = new Sms();
            sms.date = Tools.getDateMilliSeconds(c, "date");
            sms.number = Tools.getString(c, "address");
            sms.message = Tools.getString(c, "body");
            if (sender == null) {
                sms.sender = ContactsManager.getContactName(Tools.getLong(c, "person"));
            } else {
                sms.sender = sender;
            }
            res.add(sms);

        }
        c.close();

        return res;
    }

    /**
     * Returns a ArrayList of <Sms> with count sms where the contactId match the
     * argument
     */
    public static ArrayList<Sms> getSentSms(ArrayList<Phone> phones, ArrayList<Sms> sms) {
        ArrayList<Sms> res = new ArrayList<Sms>();

        for (Sms aSms : sms) {
            Boolean phoneMatch = false;

            for (Phone phone : phones) {
                if (phone.phoneMatch(aSms.number)) {
                    phoneMatch = true;
                    break;
                }
            }

            if (phoneMatch) {
                res.add(aSms);
            }
        }

        return res;
    }

    /** Adds the text of the message to the sent box */
    public static void addSmsToSentBox(String message, String phoneNumber) {
        ContentValues values = new ContentValues();
        values.put("address", phoneNumber);
        values.put("date", System.currentTimeMillis());
        values.put("body", message);
        XmppService.getInstance().getContentResolver().insert(Uri.parse("content://sms/sent"), values);
    }
}
