package com.googlecode.gtalksms.panels;

import android.os.Bundle;
import android.preference.PreferenceActivity;

import com.googlecode.gtalksms.R;

public class Preferences extends PreferenceActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            getPreferenceManager().setSharedPreferencesName("GTalkSMS");
            addPreferencesFromResource(R.xml.preferences);
    }

}
