package org.t0t0.androguard.test;

import android.app.Activity;
import android.os.Bundle;

public class TestActivity extends Activity
{
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
        Test1 t = new Test1();        
        t.go();
    }
}
