package com.googlecode.gtalksms;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.util.Log;

public class NetworkConnectivityReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {

        XmppService service = XmppService.getInstance();
        if (service != null) {
            // is this notification telling us about a new network which is a 
            // 'failover' due to another network stopping? 
            boolean failover = intent.getBooleanExtra(ConnectivityManager.EXTRA_IS_FAILOVER, false);
            // Are we in a 'no connectivity' state?
            boolean nocon = intent.getBooleanExtra(ConnectivityManager.EXTRA_NO_CONNECTIVITY, false);
            NetworkInfo network = (NetworkInfo) intent.getParcelableExtra(ConnectivityManager.EXTRA_NETWORK_INFO);
            // if no network, or if this is a "failover" notification 
            // (meaning the network we are connected to has stopped) 
            // and we are connected , we must disconnect.
            if (network == null || !network.isConnected() || (failover && service.isConnected())) {
                Log.i(XmppService.LOG_TAG, "network unavailable - closing connection");
                service.clearConnection();
            }
            // connect if not already connected (eg, if we disconnected above) and we have connectivity
            if (!nocon && !service.isConnected()) {
                Log.i(XmppService.LOG_TAG, "network available and not connected - connecting");
                service.initConnection();
            }
        }
    }
}
