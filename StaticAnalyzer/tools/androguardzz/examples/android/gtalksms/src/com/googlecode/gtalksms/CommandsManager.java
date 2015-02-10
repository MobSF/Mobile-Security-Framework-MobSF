package com.googlecode.gtalksms;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.location.Address;
import android.net.Uri;
import android.text.ClipboardManager;

import com.googlecode.gtalksms.contacts.Contact;
import com.googlecode.gtalksms.contacts.ContactAddress;
import com.googlecode.gtalksms.contacts.ContactsManager;
import com.googlecode.gtalksms.geo.GeoManager;
import com.googlecode.gtalksms.phone.Call;
import com.googlecode.gtalksms.phone.Phone;
import com.googlecode.gtalksms.phone.PhoneManager;
import com.googlecode.gtalksms.sms.Sms;
import com.googlecode.gtalksms.sms.SmsMmsManager;

public class CommandsManager {
    
    static SettingsManager Settings = XmppService.Settings;

    // last person who sent sms/who we sent an sms to
    public String lastRecipient = null;

    private MediaManager mediaMgr = new MediaManager();

    private Context context;
    
    public CommandsManager(Context baseContext) {
        context = baseContext;
    }

    public void init() {
        mediaMgr.initMediaPlayer(context);
        SmsMmsManager.initSmsMonitors();
    }
    
    public void cleanUp() {
        mediaMgr.clearMediaPlayer();
        SmsMmsManager.clearSmsMonitors();
    }
    
    
    /** handles the different commands */
    public void onCommandReceived(String commandLine) {
        try {
            String command;
            String args;
            if (-1 != commandLine.indexOf(":")) {
                command = commandLine.substring(0, commandLine.indexOf(":"));
                args = commandLine.substring(commandLine.indexOf(":") + 1);
            } else {
                command = commandLine;
                args = "";
            }

            // Not case sensitive commands
            command = command.toLowerCase();

            if (command.equals("?")) {
                StringBuilder builder = new StringBuilder();
                builder.append("Available commands:\n");
                builder.append("- \"?\": shows this help.\n");
                builder.append("- \"dial:#contact#\": dial the specified contact.\n");
                builder.append("- \"reply:#message#\": send a sms to your last recipient with content message.\n");
                builder.append("- \"sms\": display last sent sms from all contact.\n");
                builder.append("- \"sms:#contact#\": display last sent sms from searched contacts.\n");
                builder.append("- \"sms:#contact#:#message#\": sends a sms to number with content message.\n");
                builder.append("- \"calls\": display call log.\n");
                builder.append("- \"contact:#contact#\": display informations of a searched contact.\n");
                builder.append("- \"geo:#address#\": Open Maps or Navigation or Street view on specific address\n");
                builder.append("- \"where\": sends you google map updates about the location of the phone until you send \"stop\"\n");
                builder.append("- \"ring\": rings the phone until you send \"stop\"\n");
                builder.append("- \"copy:#text#\": copy text to clipboard\n");
                builder.append("and you can paste links and open it with the appropriate app\n");
                send(builder.toString());
            }
            else if (command.equals("sms")) {
                int separatorPos = args.indexOf(":");
                String contact = null;
                String message = null;
                if (-1 != separatorPos) {
                    contact = args.substring(0, separatorPos);
                    setLastRecipient(contact);
                    message = args.substring(separatorPos + 1);
                    sendSMS(message, contact);
                } else if (args.length() > 0) {
                    readSMS(args);
                } else {
                    readLastSMS();
                }
            }
            else if (command.equals("calls")) {
                readCallLogs();
            }
            else if (command.equals("reply")) {
                if (args.length() == 0) {
                    displayLastRecipient(lastRecipient);
                } else if (lastRecipient == null) {
                    send("Error: no recipient registered.");
                } else {
                    sendSMS(args, lastRecipient);
                }
            }
            else if (command.equals("copy")) {
                copyToClipboard(args);
            }
            else if (command.equals("geo")) {
                geo(args);
            }
            else if (command.equals("dial")) {
                dial(args);
            }
            else if (command.equals("contact")) {
                displayContacts(args);
            }
            else if (command.equals("where")) {
                send("Start locating phone");
                GeoManager.startLocatingPhone();
            }
            else if (command.equals("stop")) {
                send("Stopping ongoing actions");
                GeoManager.stopLocatingPhone();
                stopRinging();
            }
            else if (command.equals("ring")) {
                send("Ringing phone");
                ring();
            }
            else if (command.equals("http")) {
                open("http:" + args);
            }
            else if (command.equals("https")) {
                open("https:" + args);
            }
            else {
                send('"'+ commandLine + '"' + ": unknown command. Send \"?\" for getting help");
            }
        } catch (Exception ex) {
            send("Error : " + ex);
        }
    }
    
    private void send(String msg) {
        XmppService.getInstance().send(msg);
    }

    public void setLastRecipient(String phoneNumber) {
        if (lastRecipient == null || !phoneNumber.equals(lastRecipient)) {
            lastRecipient = phoneNumber;
            displayLastRecipient(phoneNumber);
        }
    }

    public String makeBold(String in) {
        if (Settings.formatChatResponses) {
            return " *" + in + "* ";
        }
        return in;
    }

    public String makeItalic(String in) {
        if (Settings.formatChatResponses) {
            return " _" + in + "_ ";
        }
        return in;
    }

    /** dial the specified contact */
    public void dial(String searchedText) {
        String number = null;
        String contact = null;

        if (Phone.isCellPhoneNumber(searchedText)) {
            number = searchedText;
            contact = ContactsManager.getContactName(number);
        } else {
            ArrayList<Phone> mobilePhones = ContactsManager.getMobilePhones(searchedText);
            if (mobilePhones.size() > 1) {
                send("Specify more details:");

                for (Phone phone : mobilePhones) {
                    send(phone.contactName + " - " + phone.cleanNumber);
                }
            } else if (mobilePhones.size() == 1) {
                Phone phone = mobilePhones.get(0);
                contact = phone.contactName;
                number = phone.cleanNumber;
            } else {
                send("No match for \"" + searchedText + "\"");
            }
        }

        if( number != null) {
            send("Dial " + contact + " (" + number + ")");
            if(!PhoneManager.Dial(number)) {
                send("Error can't dial.");
            }
        }
    }

    /** sends a SMS to the specified contact */
    public void sendSMS(String message, String contact) {
        if (Phone.isCellPhoneNumber(contact)) {
            send("Sending sms to " + ContactsManager.getContactName(contact));
            SmsMmsManager.sendSMSByPhoneNumber(message, contact);
        } else {
            ArrayList<Phone> mobilePhones = ContactsManager.getMobilePhones(contact);
            if (mobilePhones.size() > 1) {
                send("Specify more details:");

                for (Phone phone : mobilePhones) {
                    send(phone.contactName + " - " + phone.cleanNumber);
                }
            } else if (mobilePhones.size() == 1) {
                Phone phone = mobilePhones.get(0);
                send("Sending sms to " + phone.contactName + " (" + phone.cleanNumber + ")");
                SmsMmsManager.sendSMSByPhoneNumber(message, phone.cleanNumber);
            } else {
                send("No match for \"" + contact + "\"");
            }
        }
    }

    /** reads (count) SMS from all contacts matching pattern */
    public void readSMS(String searchedText) {

        ArrayList<Contact> contacts = ContactsManager.getMatchingContacts(searchedText);
        ArrayList<Sms> sentSms = new ArrayList<Sms>();
        if (Settings.displaySentSms) {
            sentSms = SmsMmsManager.getAllSentSms();
        }

        if (contacts.size() > 0) {
            
            StringBuilder noSms = new StringBuilder();
            Boolean hasMatch = false;
            for (Contact contact : contacts) {
                ArrayList<Sms> smsArrayList = SmsMmsManager.getSms(contact.rawIds, contact.name);
                if (Settings.displaySentSms) {
                    smsArrayList.addAll(SmsMmsManager.getSentSms(ContactsManager.getPhones(contact.id),sentSms));
                }
                Collections.sort(smsArrayList);
                
                List<Sms> smsList = Tools.getLastElements(smsArrayList, Settings.smsNumber);
                if (smsList.size() > 0) {
                    hasMatch = true;
                    StringBuilder smsContact = new StringBuilder();
                    smsContact.append(makeBold(contact.name));
                    for (Sms sms : smsList) {
                        smsContact.append("\r\n" + makeItalic(sms.date.toLocaleString() + " - " + sms.sender));
                        smsContact.append("\r\n" + sms.message);
                    }
                    if (smsList.size() < Settings.smsNumber) {
                        smsContact.append("\r\n" + makeItalic("Only got " + smsList.size() + " sms"));
                    }
                    send(smsContact.toString() + "\r\n");
                } else {
                    noSms.append(contact.name + " - No sms found\r\n");
                }
            }
            if (!hasMatch) {
                send(noSms.toString());
            }
        } else {
            send("No match for \"" + searchedText + "\"");
        }
    }

    /** reads last (count) SMS from all contacts */
    public void readLastSMS() {

        ArrayList<Sms> smsArrayList = SmsMmsManager.getAllReceivedSms();
        StringBuilder allSms = new StringBuilder();
        
        if (Settings.displaySentSms) {
            smsArrayList.addAll(SmsMmsManager.getAllSentSms());
        }
        Collections.sort(smsArrayList);
        
        List<Sms> smsList = Tools.getLastElements(smsArrayList, Settings.smsNumber);
        if (smsList.size() > 0) {
            for (Sms sms : smsList) {
                allSms.append("\r\n" + makeItalic(sms.date.toLocaleString() + " - " + sms.sender));
                allSms.append("\r\n" + sms.message);
            }
        } else {
            allSms.append("No sms found");
        }
        send(allSms.toString() + "\r\n");
    }


    /** reads last Call Logs from all contacts */
    public void readCallLogs() {

        ArrayList<Call> arrayList = PhoneManager.getPhoneLogs();
        StringBuilder all = new StringBuilder();
        
        List<Call> callList = Tools.getLastElements(arrayList, Settings.callLogsNumber);
        if (callList.size() > 0) {
            for (Call call : callList) {
                String caller = makeBold(ContactsManager.getContactName(call.phoneNumber));

                all.append("\r\n" + makeItalic(call.date.toLocaleString()) + " - " + caller );
                all.append(" - " + call.type + " of " + call.duration());
            }
        } else {
            all.append("No sms found");
        }
        send(all.toString() + "\r\n");
    }


    public void displayLastRecipient(String phoneNumber) {
        if (phoneNumber == null) {
            send("Reply contact is not set");
        } else {
            String contact = ContactsManager.getContactName(phoneNumber);
            if (Phone.isCellPhoneNumber(phoneNumber) && contact.compareTo(phoneNumber) != 0){
                contact += " (" + phoneNumber + ")";
            }
            send("Reply contact is now " + contact);
        }
    }

    /** reads (count) SMS from all contacts matching pattern */
    public void displayContacts(String searchedText) {

        ArrayList<Contact> contacts = ContactsManager.getMatchingContacts(searchedText);

        if (contacts.size() > 0) {
            
            if (contacts.size() > 1) {
                send(contacts.size() + " contacts found for \"" + searchedText + "\"");
            }
            
            for (Contact contact : contacts) {
                StringBuilder strContact = new StringBuilder();
                strContact.append(makeBold(contact.name));
                
//                strContact.append("\r\n" + "Id : " + contact.id);
//                strContact.append("\r\n" + "Raw Ids : " + TextUtils.join(" ", contact.rawIds));
                
                ArrayList<Phone> mobilePhones = ContactsManager.getPhones(contact.id);
                if (mobilePhones.size() > 0) {
                    strContact.append("\r\n" + makeItalic("Phones"));
                    for (Phone phone : mobilePhones) {
                        strContact.append("\r\n" + phone.label + " - " + phone.cleanNumber);
                    }
                }

                ArrayList<ContactAddress> emails = ContactsManager.getEmailAddresses(contact.id);
                if (emails.size() > 0) {
                    strContact.append("\r\n" + makeItalic("Emails"));
                    for (ContactAddress email : emails) {
                        strContact.append("\r\n" + email.label + " - " + email.address);
                    }
                }

                ArrayList<ContactAddress> addresses = ContactsManager.getPostalAddresses(contact.id);
                if (addresses.size() > 0) {
                    strContact.append("\r\n" + makeItalic("Addresses"));
                    for (ContactAddress address : addresses) {
                        strContact.append("\r\n" + address.label + " - " + address.address);
                    }
                }
                send(strContact.toString() + "\r\n");
            }
        } else {
            send("No match for \"" + searchedText + "\"");
        }
    }

    /** Open geolocalization application */
    private void geo(String text) {
        List<Address> addresses = GeoManager.geoDecode(text);
        if (addresses != null) {
            if (addresses.size() > 1) {
                send("Specify more details:");
                for (Address address : addresses) {
                    StringBuilder addr = new StringBuilder();
                    for (int i = 0; i < address.getMaxAddressLineIndex(); i++) {
                        addr.append(address.getAddressLine(i) + "\n");
                    }
                    send(addr.toString());
                }
            } else if (addresses.size() == 1) {
                GeoManager.launchExternal(addresses.get(0).getLatitude() + "," + addresses.get(0).getLongitude());
            }
        } else {
            send("No match for \"" + text + "\"");
            // For emulation testing
            // GeoManager.launchExternal("48.833199,2.362232");
        }
    }

    /** copy text to clipboard */
    private void copyToClipboard(String text) {
        try {
            ClipboardManager clipboard = (ClipboardManager) context.getSystemService(Service.CLIPBOARD_SERVICE);
            clipboard.setText(text);
            send("Text copied");
        }
        catch(Exception ex) {
            send("Clipboard access failed");
        }
    }

    /** lets the user choose an activity compatible with the url */
    private void open(String url) {
        Intent target = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
        Intent intent = Intent.createChooser(target, "GTalkSMS: choose an activity");
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(intent);
    }

    /** makes the phone ring */
    private void ring() {
        if (!mediaMgr.ring(context)) {
            send("Unable to ring, change the ringtone in the options");
        }
    }

    /** Stops the phone from ringing */
    private void stopRinging() {
        mediaMgr.stopRinging();
    }
    
    
}
