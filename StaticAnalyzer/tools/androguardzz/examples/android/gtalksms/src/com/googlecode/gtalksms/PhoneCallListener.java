package com.googlecode.gtalksms;

import android.telephony.PhoneStateListener;
import android.telephony.TelephonyManager;

import com.googlecode.gtalksms.contacts.ContactsManager;

public class PhoneCallListener extends PhoneStateListener {

    public void onCallStateChanged(int state, String incomingNumber) {
        switch(state) {
            case TelephonyManager.CALL_STATE_IDLE:
                break;
            case TelephonyManager.CALL_STATE_OFFHOOK:
                break;
            case TelephonyManager.CALL_STATE_RINGING:
                XmppService service = XmppService.getInstance();
                if (service != null) {
                    String contact = ContactsManager.getContactName(incomingNumber);
                    service.send(contact + " is calling");
                }
                break;
        }
    }
}
