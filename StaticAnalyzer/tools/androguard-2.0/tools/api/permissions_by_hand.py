PERMISSIONS_BY_HAND = {
    "SEND_SMS" : { "android.telephony.SmsManager" : [
                        [ "F", "getDefault()", "static SmsManager" ],
                        [ "F", "sendDataMessage(java.lang.String, java.lang.String, short, byte[], PendingIntent, PendingIntent)", "void" ],
#                        [ "F", "sendMultipartTextMessage(String destinationAddress, String scAddress, ArrayList<String> parts, ArrayList<PendingIntent> sentIntents, ArrayList<PendingIntent> deliveryIntents", "void" ],
                        [ "F", "sendTextMessage(java.lang.String, java.lang.String, java.lang.String, PendingIntent, PendingIntent)", "void" ],
                      ],
        
                      "android.telephony.gsm.SmsManager" : [
                        [ "F", "getDefault()", "static android.telephony.gsm.SmsManager" ],
                        [ "F", "sendDataMessage(java.lang.String, java.lang.String, short, byte[], PendingIntent, PendingIntent)", "void" ],
#                        [ "F", "sendMultipartTextMessage(String destinationAddress, String scAddress, ArrayList<String> parts, ArrayList<PendingIntent> sentIntents, ArrayList<PendingIntent> deliveryIntents", "void" ],
                        [ "F", "sendTextMessage(java.lang.String, java.lang.String, java.lang.String, PendingIntent, PendingIntent)", "void" ],
                      ],
    },

    "SET_WALLPAPER" : { "android.app.WallpaperManager" : [
                            [ "F", "setBitmap(Bitmap)", "void" ],

                        ],
    },

    "READ_CONTACTS" : { "android.provider.ContactsContract$CommonDataKinds$Phone" : [
                            [ "C", "CONTENT_URI", "Uri" ]
                        ],
    },

}
