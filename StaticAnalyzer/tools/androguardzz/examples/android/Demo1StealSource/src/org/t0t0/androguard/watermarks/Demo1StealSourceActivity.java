package org.t0t0.androguard.watermarks;

import android.app.Activity;
import android.os.Bundle;

public class Demo1StealSourceActivity extends Activity
{
    private byte state[] = new byte[256];
    private int x, y;

    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
    }

    public byte[] rc4(byte[] buf) {
        int xorIndex;
        byte tmp;
        
        if (buf == null) {
            return null;
        }
        
        byte[] result = new byte[buf.length];
        
        for (int i=0; i < buf.length; i++) {

            x = (x + 1) & 0xff;
            y = ((state[x] & 0xff) + y) & 0xff;

            tmp = state[x];
            state[x] = state[y];
            state[y] = tmp;
            
            xorIndex = ((state[x] &0xff) + (state[y] & 0xff)) & 0xff;
            result[i] = (byte)(buf[i] ^ state[xorIndex]);
        }
        return result;
    }
}
