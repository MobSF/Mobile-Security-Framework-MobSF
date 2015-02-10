package com.googlecode.gtalksms.contacts;

import java.util.ArrayList;
import java.util.Collections;

import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.provider.ContactsContract;
import android.provider.ContactsContract.CommonDataKinds;
import android.provider.ContactsContract.Contacts;
import android.provider.ContactsContract.PhoneLookup;
import android.provider.ContactsContract.RawContacts;

import com.googlecode.gtalksms.Tools;
import com.googlecode.gtalksms.XmppService;
import com.googlecode.gtalksms.phone.Phone;

public class ContactsManager {

    /**
     * Tries to get the contact display name of the specified phone number.
     * If not found, returns the argument.
     */
    public static String getContactName (String phoneNumber) {
        String res;
        if (phoneNumber != null) {
            res = phoneNumber;
            ContentResolver resolver = XmppService.getInstance().getContentResolver();
            Uri uri = Uri.withAppendedPath(PhoneLookup.CONTENT_FILTER_URI, Uri.encode(phoneNumber));
            Cursor c = resolver.query(uri, new String[]{PhoneLookup.DISPLAY_NAME}, null, null, null);

            if (c.moveToFirst()) {
                res = Tools.getString(c, CommonDataKinds.Phone.DISPLAY_NAME);
            }
        } else {
            res = "[hidden number]";
        }
        return res;
    }

    /**
     * Returns a ArrayList of <Contact> where the names/company match the argument
     */
    public static String getContactName(long rawId) {
        String res = "Unknown";
        
        ContentResolver resolver = XmppService.getInstance().getContentResolver();
        Cursor c = resolver.query(RawContacts.CONTENT_URI,
                new String[]{RawContacts.CONTACT_ID},
                RawContacts._ID + "=?",
                new String[]{String.valueOf(rawId)}, null);
        
        long id = -1;
        if (c.moveToFirst()) {
            id = Tools.getLong(c, RawContacts.CONTACT_ID);
        }
        c.close();
        
        c = resolver.query(Contacts.CONTENT_URI,
                new String[]{Contacts.DISPLAY_NAME},
                RawContacts._ID + "=?",
                new String[]{String.valueOf(id)}, null);
        
        if (c.moveToFirst()) {
            res = Tools.getString(c, Contacts.DISPLAY_NAME);
        }
        c.close();
       
        return res;
    }

    /**
     * Returns a ArrayList of <Contact> where the names/company match the argument
     */
    public static ArrayList<Contact> getMatchingContacts(String searchedName) {
        ArrayList<Contact> res = new ArrayList<Contact>();
        if (Phone.isCellPhoneNumber(searchedName)) {
            searchedName = getContactName(searchedName);
        }

        if (!searchedName.equals("")) {
            ContentResolver resolver = XmppService.getInstance().getContentResolver();
            String[] projection = new String[] { Contacts._ID, Contacts.DISPLAY_NAME };
            String sortOrder = ContactsContract.Contacts.DISPLAY_NAME + " COLLATE LOCALIZED ASC";

            Uri contactUri = Uri.withAppendedPath(Contacts.CONTENT_FILTER_URI, Uri.encode(searchedName));
            Cursor c = resolver.query(contactUri, projection, null, null, sortOrder);
            for (boolean hasData = c.moveToFirst() ; hasData ; hasData = c.moveToNext()) {
                Long id = Tools.getLong(c, Contacts._ID);
                if (null != id) {
                    
                    String contactName = Tools.getString(c, Contacts.DISPLAY_NAME);
                    if(null != contactName) {
                        Contact contact = new Contact();
                        contact.id = id;
                        contact.name = contactName;
                        
                        Cursor c1 = resolver.query(RawContacts.CONTENT_URI,
                                new String[]{RawContacts._ID},
                                RawContacts.CONTACT_ID + "=?",
                                new String[]{String.valueOf(id)}, null);
                        
                        for (boolean hasData1 = c1.moveToFirst() ; hasData1 ; hasData1 = c1.moveToNext()) {
                            contact.rawIds.add(Tools.getLong(c1, RawContacts._ID));
                        }
                        
                        res.add(contact);
                    }   
                }
            }
            c.close();
        }
        Collections.sort(res);
        return res;
    }

    /**
     * Returns a ArrayList of <ContactAddress> containing postal addresses which match to contact id
     */
    public static ArrayList<ContactAddress> getPostalAddresses(Long contactId) {
        ArrayList<ContactAddress> res = new ArrayList<ContactAddress>();
        XmppService xmpp = XmppService.getInstance();
        
        if(null != contactId) {
            String where = ContactsContract.Data.CONTACT_ID + " = ? AND " + ContactsContract.Data.MIMETYPE + " = ?"; 
            String[] whereParams = new String[]{contactId.toString(), ContactsContract.CommonDataKinds.StructuredPostal.CONTENT_ITEM_TYPE}; 
        
            Cursor c = xmpp.getContentResolver().query(ContactsContract.Data.CONTENT_URI, 
                        null, where, whereParams, null); 
            
            while(c.moveToNext()) {
                int type = Tools.getLong(c, ContactsContract.CommonDataKinds.StructuredPostal.TYPE).intValue();
                String label = Tools.getString(c, ContactsContract.CommonDataKinds.StructuredPostal.LABEL);

//                String poBox        = Tools.getString(c, ContactsContract.CommonDataKinds.StructuredPostal.POBOX);
//                String street       = Tools.getString(c, ContactsContract.CommonDataKinds.StructuredPostal.STREET);
//                String city         = Tools.getString(c, ContactsContract.CommonDataKinds.StructuredPostal.CITY);
//                String state        = Tools.getString(c, ContactsContract.CommonDataKinds.StructuredPostal.REGION);
//                String postalCode   = Tools.getString(c, ContactsContract.CommonDataKinds.StructuredPostal.POSTCODE);
//                String country      = Tools.getString(c, ContactsContract.CommonDataKinds.StructuredPostal.COUNTRY);

                if (label == null || label.compareTo("") != 0) {
                    label = ContactsContract.CommonDataKinds.StructuredPostal.getTypeLabel(xmpp.getResources(), type, "").toString();
                }
                
                ContactAddress a = new ContactAddress();
                a.address = Tools.getString(c, ContactsContract.CommonDataKinds.StructuredPostal.DATA);
                a.label = label;
                res.add(a);
            } 
            c.close();
        }
        
        return res;
    }

    /**
     * Returns a ArrayList of <ContactAddress> containing email addresses which match to contact id
     */
    public static ArrayList<ContactAddress> getEmailAddresses(Long contactId) {
        ArrayList<ContactAddress> res = new ArrayList<ContactAddress>();
        XmppService xmpp = XmppService.getInstance();

        if(null != contactId) {
            String where =  ContactsContract.CommonDataKinds.Email.CONTACT_ID + " = " + contactId;
            Cursor c = xmpp.getContentResolver().query(ContactsContract.CommonDataKinds.Email.CONTENT_URI, null, where, null, null); 
            while(c.moveToNext()) {

                String label = Tools.getString(c, ContactsContract.CommonDataKinds.Email.LABEL);
                int type = Tools.getLong(c, ContactsContract.CommonDataKinds.Email.TYPE).intValue();

                if (label == null || label.compareTo("") != 0) {
                    label = ContactsContract.CommonDataKinds.Email.getTypeLabel(xmpp.getResources(), type, "").toString();
                }

                ContactAddress a = new ContactAddress();
                a.address = Tools.getString(c, ContactsContract.CommonDataKinds.Email.DATA);
                a.label = label;
                res.add(a);
            }
            c.close();
        }
        return res;
    }

    /**
     * Returns a ArrayList < Phone > of a specific contact
     * ! phone.contactName not set
     */
    public static ArrayList<Phone> getPhones(Long contactId) {
        ArrayList<Phone> res = new ArrayList<Phone>();
        XmppService xmpp = XmppService.getInstance();
        
        if(null != contactId) {
            String where =  ContactsContract.CommonDataKinds.Phone.CONTACT_ID + " = " + contactId;
            Cursor c = xmpp.getContentResolver().query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI, null, where, null, null);
            
            while (c.moveToNext()) {

                String number = Tools.getString(c, CommonDataKinds.Phone.NUMBER);
                String label = Tools.getString(c,CommonDataKinds.Phone.LABEL);
                int type = Tools.getLong(c, CommonDataKinds.Phone.TYPE).intValue();
    
                if (label == null || label.compareTo("") != 0) {
                    label = ContactsContract.CommonDataKinds.Phone.getTypeLabel(xmpp.getResources(), type, "").toString();
                }
    
                Phone phone = new Phone();
                phone.number = number;
                phone.cleanNumber = Phone.cleanPhoneNumber(phone.number);
                phone.isCellPhoneNumber = Phone.isCellPhoneNumber(phone.number);
                phone.label = label;
                phone.type = type;
    
                res.add(phone);
            }
            c.close();
        }
        
        return res;
    }

    /**
     * Returns a ArrayList < Phone >
     * with all matching phones for the argument
     */
    public static ArrayList<Phone> getPhones(String searchedText) {
        ArrayList<Phone> res = new ArrayList<Phone>();
        if (Phone.isCellPhoneNumber(searchedText)) {
            Phone phone = new Phone();
            phone.number = searchedText;
            phone.cleanNumber = Phone.cleanPhoneNumber(phone.number);
            phone.contactName = getContactName(searchedText);
            phone.isCellPhoneNumber = true;
            phone.type = CommonDataKinds.Phone.TYPE_MOBILE;

            res.add(phone);
        } else {
            // get the matching contacts, dictionary of < id, names >
            ArrayList<Contact> contacts = getMatchingContacts(searchedText);
            if (contacts.size() > 0) {
                for (Contact contact : contacts) {
                    ArrayList<Phone> phones = getPhones(contact.id);
                    for (Phone phone : phones) {
                        phone.contactName = getContactName(contact.name);
                        res.add(phone);
                    }
                }
            }
        }
        return res;
    }

    /**
     * Returns a ArrayList < Phone >
     * with all matching mobile phone for the argument
     */
    public static ArrayList<Phone> getMobilePhones(String searchedText) {
        ArrayList<Phone> res = new ArrayList<Phone>();
        ArrayList<Phone> phones = getPhones(searchedText);

        for (Phone phone : phones) {
            if (phone.type == CommonDataKinds.Phone.TYPE_MOBILE) {
                res.add(phone);
            }
        }

        // manage all phones number
        if (res.size() == 0) {
            for (Phone phone : phones) {
                res.add(phone);
            }
        }

        return res;
    }
}
