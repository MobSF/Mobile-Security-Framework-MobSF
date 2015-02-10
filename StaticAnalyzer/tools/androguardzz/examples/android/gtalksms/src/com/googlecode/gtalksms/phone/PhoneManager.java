package com.googlecode.gtalksms.phone;

import java.util.ArrayList;

import android.content.ContentResolver;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.provider.CallLog;

import com.googlecode.gtalksms.Tools;
import com.googlecode.gtalksms.XmppService;

public class PhoneManager {

    /** Dial a phone number */
    public static Boolean Dial(String number) {
        try {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse("tel:" + number));
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            XmppService.getInstance().startActivity(intent);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    public static ArrayList<Call> getPhoneLogs() {
        ArrayList<Call> res = new ArrayList<Call>();

        ContentResolver resolver = XmppService.getInstance().getContentResolver();
        
        String[] projection = new String[] { CallLog.Calls.NUMBER, CallLog.Calls.TYPE, 
                CallLog.Calls.DURATION, CallLog.Calls.DATE};
        String sortOrder = CallLog.Calls.DATE + " ASC";

        Cursor c = resolver.query(CallLog.Calls.CONTENT_URI, projection, null, null, sortOrder);
        
        for (boolean hasData = c.moveToFirst() ; hasData ; hasData = c.moveToNext()) {
            
            Call call = new Call();
            call.phoneNumber = Tools.getString(c, CallLog.Calls.NUMBER);
            if (call.phoneNumber.equals("-1")) {
                call.phoneNumber = null;
            }
            call.duration = Tools.getLong(c, CallLog.Calls.DURATION);
            call.date = Tools.getDateMilliSeconds(c, CallLog.Calls.DATE);
            call.type = Call.Type[Tools.getInt(c,CallLog.Calls.TYPE)];
            
            res.add(call);
        }
        
        return res;
    }
}
