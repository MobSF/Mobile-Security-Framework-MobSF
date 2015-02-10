package com.googlecode.gtalksms.panels;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

import com.googlecode.gtalksms.R;
import com.googlecode.gtalksms.Tools;
import com.googlecode.gtalksms.XmppService;

public class MainScreen extends Activity {


    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        TextView label = (TextView) findViewById(R.id.VersionLabel);
        label.setText("GTalkSMS " + Tools.getVersionName(getBaseContext(), getClass()));

        Button prefBtn = (Button) findViewById(R.id.Preferences);
        prefBtn.setOnClickListener(new OnClickListener() {

                public void onClick(View v) {
                    Intent settingsActivity = new Intent(getBaseContext(), Preferences.class);
                    startActivity(settingsActivity);
                }
        });

        Button startStopButton = (Button) findViewById(R.id.StartStop);
        startStopButton.setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    Intent intent = new Intent(".GTalkSMS.ACTION");
                    if (XmppService.getInstance() == null) {
                        startService(intent);
                    }
                    else {
                        stopService(intent);
                    }
                }
        });
    }
}
