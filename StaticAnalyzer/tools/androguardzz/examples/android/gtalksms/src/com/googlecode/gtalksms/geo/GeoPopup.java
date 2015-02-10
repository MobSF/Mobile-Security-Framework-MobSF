package com.googlecode.gtalksms.geo;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;

public class GeoPopup extends Activity {

    final String[] items = {"Maps", "Navigation", "Street View"};

    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        try {
            super.onCreate(savedInstanceState);

            final String url = getIntent().getStringExtra("url");
            final Activity popup = this;

            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle("Choose Geo App");
            builder.setSingleChoiceItems(items, -1, new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int item) {
                    dialog.cancel();

                    String intentUrl = "";
                    if (items[item].compareTo("Maps") == 0) {
                        intentUrl = "geo:" + url;
                    } else if (items[item].compareTo("Navigation") == 0) {
                        intentUrl = "google.navigation:" + url;
                    } else if (items[item].compareTo("Street View") == 0) {
                        intentUrl = "google.streetview:cbll=" + url;
                    }

                    try {
                        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(intentUrl));
                        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                        startActivity(intent);
                    } catch (Exception e) {
                    }

                    popup.finish();
                }
            });
            builder.setOnCancelListener(new DialogInterface.OnCancelListener() {
                public void onCancel(DialogInterface dialog) {
                    try {
                        dialog.cancel();
                        popup.finish();
                    } catch (Exception e) {
                    }
                }
            });
            builder.show();
        } catch (Exception e) {
        }

    }
}
