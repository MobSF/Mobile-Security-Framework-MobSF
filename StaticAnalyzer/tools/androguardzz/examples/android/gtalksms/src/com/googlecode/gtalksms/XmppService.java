package com.googlecode.gtalksms;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.PacketListener;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.filter.MessageTypeFilter;
import org.jivesoftware.smack.filter.PacketFilter;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.Packet;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.appwidget.AppWidgetManager;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Handler;
import android.os.IBinder;
import android.util.Log;
import android.widget.RemoteViews;
import android.widget.Toast;

import com.googlecode.gtalksms.geo.GeoManager;
import com.googlecode.gtalksms.panels.MainScreen;

public class XmppService extends Service {

    private static final int DISCONNECTED = 0;
    private static final int CONNECTING = 1;
    private static final int CONNECTED = 2;
    private static final int DISCONNECTING = 3;

    // Indicates the current state of the service (disconnected/connecting/connected)
    private int mStatus = DISCONNECTED;

    // Service instance
    private static XmppService instance = null;
    
    private CommandsManager commandsMgr;
    public static SettingsManager Settings = new SettingsManager();
    
    public BroadcastReceiver mBatInfoReceiver = null;
    
    private ConnectionConfiguration mConnectionConfiguration = null;
    private XMPPConnection mConnection = null;
    private PacketListener mPacketListener = null;
    
    // notification stuff
    @SuppressWarnings("unchecked")
    private static final Class[] mStartForegroundSignature = new Class[] {
        int.class, Notification.class};
    @SuppressWarnings("unchecked")
    private static final Class[] mStopForegroundSignature = new Class[] {
        boolean.class};
    private NotificationManager mNM;
    private Method mStartForeground;
    private Method mStopForeground;
    private Object[] mStartForegroundArgs = new Object[2];
    private Object[] mStopForegroundArgs = new Object[1];
    private PendingIntent contentIntent = null;

    // Our current retry attempt, plus a runnable and handler to implement retry
    private int mCurrentRetryCount = 0;
    Runnable mReconnectRunnable = null;
    Handler mReconnectHandler = new Handler();

    public final static String LOG_TAG = "gtalksms";
    
    /** Updates the status about the service state (and the statusbar)*/
    private void updateStatus(int status) {
        if (status != mStatus) {
            // Get the layout for the AppWidget and attach an on-click listener to the button
            RemoteViews views = new RemoteViews(getPackageName(), R.layout.appwidget);
            
            Notification notification = new Notification();
            switch(status) {
                case CONNECTED:
                    notification = new Notification(
                            R.drawable.status_green,
                            "Connected",
                            System.currentTimeMillis());
                    notification.setLatestEventInfo(
                            getApplicationContext(),
                            "GTalkSMS",
                            "Connected",
                            contentIntent);
                    views.setImageViewResource(R.id.Button, R.drawable.icon_green);     
                    break;
                case CONNECTING:
                    notification = new Notification(
                            R.drawable.status_orange,
                            "Connecting...",
                            System.currentTimeMillis());
                    notification.setLatestEventInfo(
                            getApplicationContext(),
                            "GTalkSMS",
                            "Connecting...",
                            contentIntent);
                    views.setImageViewResource(R.id.Button, R.drawable.icon_orange);     
                    break;
                case DISCONNECTED:
                    notification = new Notification(
                            R.drawable.status_red,
                            "Disconnected",
                            System.currentTimeMillis());
                    notification.setLatestEventInfo(
                            getApplicationContext(),
                            "GTalkSMS",
                            "Disconnected",
                            contentIntent);
                    views.setImageViewResource(R.id.Button, R.drawable.icon_red);     
                    break;
                case DISCONNECTING:
                    notification = new Notification(
                            R.drawable.status_orange,
                            "Disconnecting...",
                            System.currentTimeMillis());
                    notification.setLatestEventInfo(
                            getApplicationContext(),
                            "GTalkSMS",
                            "Disconnecting...",
                            contentIntent);
                    views.setImageViewResource(R.id.Button, R.drawable.icon_orange);     
                    break;
                default:
                    break;
            }
            
            // Update all AppWidget with current status
            AppWidgetManager manager = AppWidgetManager.getInstance(this);
            ComponentName component = new ComponentName(getBaseContext().getPackageName(), WidgetProvider.class.getName());
            manager.updateAppWidget(manager.getAppWidgetIds(component), views);
            
            notification.flags |= Notification.FLAG_ONGOING_EVENT;
            notification.flags |= Notification.FLAG_NO_CLEAR;
            stopForegroundCompat(mStatus);
            startForegroundCompat(status, notification);
            mStatus = status;
        }
    }
    
    /**
     * This is a wrapper around the startForeground method, using the older
     * APIs if it is not available.
     */
    void startForegroundCompat(int id, Notification notification) {
        // If we have the new startForeground API, then use it.
        if (mStartForeground != null) {
            mStartForegroundArgs[0] = Integer.valueOf(id);
            mStartForegroundArgs[1] = notification;
            try {
                mStartForeground.invoke(this, mStartForegroundArgs);
            } catch (InvocationTargetException e) {
                // Should not happen.
                Log.w(LOG_TAG, "Unable to invoke startForeground", e);
            } catch (IllegalAccessException e) {
                // Should not happen.
                Log.w(LOG_TAG, "Unable to invoke startForeground", e);
            }
            return;
        }
        // Fall back on the old API.
        setForeground(true);
        mNM.notify(id, notification);
    }

    /**
     * This is a wrapper around the stopForeground method, using the older
     * APIs if it is not available.
     */
    void stopForegroundCompat(int id) {
        // If we have the new stopForeground API, then use it.
        if (mStopForeground != null) {
            mStopForegroundArgs[0] = Boolean.TRUE;
            try {
                mStopForeground.invoke(this, mStopForegroundArgs);
            } catch (InvocationTargetException e) {
                // Should not happen.
                Log.w(LOG_TAG, "Unable to invoke stopForeground", e);
            } catch (IllegalAccessException e) {
                // Should not happen.
                Log.w(LOG_TAG, "Unable to invoke stopForeground", e);
            }
            return;
        }

        // Fall back on the old API.  Note to cancel BEFORE changing the
        // foreground state, since we could be killed at that point.
        mNM.cancel(id);
        setForeground(false);
    }

    /**
     * This makes the 2 previous wrappers possible
     */
    private void initNotificationStuff() {
        mNM = (NotificationManager)getSystemService(NOTIFICATION_SERVICE);
        try {
            mStartForeground = getClass().getMethod("startForeground", mStartForegroundSignature);
            mStopForeground = getClass().getMethod("stopForeground", mStopForegroundSignature);
        } catch (NoSuchMethodException e) {
            // Running on an older platform.
            mStartForeground = mStopForeground = null;
        }
        contentIntent = PendingIntent.getActivity(this, 0, new Intent(this, MainScreen.class), 0);
    }

    /** imports the preferences */
    private void importPreferences() {
        
        Settings.importPreferences(getBaseContext());
        
        mConnectionConfiguration = new ConnectionConfiguration(Settings.serverHost, 
                Settings.serverPort, Settings.serviceName);
    }

    /** clears the XMPP connection */
    public void clearConnection() {
        if (isConnected()) {
            updateStatus(DISCONNECTING);
            if (Settings.notifyApplicationConnection) {
                send("GTalkSMS stopped.");
            }
        }
        
        if (mReconnectRunnable != null) {
            mReconnectHandler.removeCallbacks(mReconnectRunnable);
        }
        
        if (mConnection != null) {
            if (mPacketListener != null) {
                mConnection.removePacketListener(mPacketListener);
            }
            // don't try to disconnect if already disconnected
            if (isConnected()) {
                mConnection.disconnect();
            }
        }
        mConnection = null;
        mPacketListener = null;
        mConnectionConfiguration = null;
        updateStatus(DISCONNECTED);
    }

    private void maybeStartReconnect() {
        if (mCurrentRetryCount > 5) {
            // we failed after all the retries - just die.
            Log.v(LOG_TAG, "maybeStartReconnect ran out of retrys");
            updateStatus(DISCONNECTED);
            Toast.makeText(this, "Failed to connect.", Toast.LENGTH_SHORT).show();
            onDestroy();
            return;
        } else {
            mCurrentRetryCount += 1;
            // a simple linear-backoff strategy.
            int timeout = 5000 * mCurrentRetryCount;
            Log.e(LOG_TAG, "maybeStartReconnect scheduling retry in " + timeout);
            mReconnectHandler.postDelayed(mReconnectRunnable, timeout);
        }
    }

    /** init the XMPP connection */
    public void initConnection() {
        updateStatus(CONNECTING);
        NetworkInfo active = ((ConnectivityManager)getSystemService(CONNECTIVITY_SERVICE)).getActiveNetworkInfo();
        if (active==null || !active.isAvailable()) {
            Log.e(LOG_TAG, "connection request, but no network available");
            Toast.makeText(this, "Waiting for network to become available.", Toast.LENGTH_SHORT).show();
            // we don't destroy the service here - our network receiver will notify us when
            // the network comes up and we try again then.
            updateStatus(DISCONNECTED);
            return;
        }
        if (mConnectionConfiguration == null) {
            importPreferences();
        }
        XMPPConnection connection = new XMPPConnection(mConnectionConfiguration);
        try {
            connection.connect();
        } catch (Exception e) {
            Log.e(LOG_TAG, "xmpp connection failed: " + e);
            Toast.makeText(this, "Connection failed.", Toast.LENGTH_SHORT).show();
            maybeStartReconnect();
            return;
        }
        try {
            connection.login(Settings.mLogin, Settings.mPassword);
        } catch (Exception e) {
            try {
                connection.disconnect();
            } catch (Exception e2) {
                Log.e(LOG_TAG, "xmpp disconnect failed: " + e2);
            }
            
            Log.e(LOG_TAG, "xmpp login failed: " + e);
            // sadly, smack throws the same generic XMPPException for network
            // related messages (eg "no response from the server") as for
            // authoritative login errors (ie, bad password).  The only
            // differentiator is the message itself which starts with this
            // hard-coded string.
            if (e.getMessage().indexOf("SASL authentication")==-1) {
                // doesn't look like a bad username/password, so retry
                Toast.makeText(this, "Login failed", Toast.LENGTH_SHORT).show();
                maybeStartReconnect();
            } else {
                Toast.makeText(this, "Invalid username or password", Toast.LENGTH_SHORT).show();
                onDestroy();
            }
            return;
        }
        mConnection = connection;
        onConnectionComplete();
    }

    private void onConnectionComplete() {
        Log.v(LOG_TAG, "connection established");
        mCurrentRetryCount = 0;
        PacketFilter filter = new MessageTypeFilter(Message.Type.chat);
        mPacketListener = new PacketListener() {
            public void processPacket(Packet packet) {
                Message message = (Message) packet;

                if (    message.getFrom().toLowerCase().startsWith(Settings.mTo.toLowerCase() + "/")
                    && !message.getFrom().equals(mConnection.getUser()) // filters self-messages
                ) {
                    if (message.getBody() != null) {
                        commandsMgr.onCommandReceived(message.getBody());
                    }
                }
            }
        };
        mConnection.addPacketListener(mPacketListener, filter);
        updateStatus(CONNECTED);
        // Send welcome message
        if (Settings.notifyApplicationConnection) {
            send("Welcome to GTalkSMS " + Tools.getVersionName(getBaseContext(), getClass()) + 
                 ". Send \"?\" for getting help");
        }
    }

    /** returns true if the service is correctly connected */
    public boolean isConnected() {
        return    (mConnection != null
                && mConnection.isConnected()
                && mConnection.isAuthenticated());
    }

   
    /** clear the battery monitor*/
    private void clearBatteryMonitor() {
        if (mBatInfoReceiver != null) {
            unregisterReceiver(mBatInfoReceiver);
        }
        mBatInfoReceiver = null;
    }

    /** init the battery stuff */
    private void initBatteryMonitor() {
        if (Settings.notifyBattery) {
            mBatInfoReceiver = new BroadcastReceiver(){
                private int lastPercentageNotified = -1;
                @Override
                public void onReceive(Context arg0, Intent intent) {
                    int level = intent.getIntExtra("level", 0);
                    if (lastPercentageNotified == -1) {
                        notifyAndSavePercentage(level);
                    } else {
                        if (level != lastPercentageNotified && level % Settings.batteryNotificationInterval == 0) {
                            notifyAndSavePercentage(level);
                        }
                    }
                }
                private void notifyAndSavePercentage(int level) {
                    send("Battery level " + level + "%");
                    lastPercentageNotified = level;
                }
            };
            registerReceiver(mBatInfoReceiver, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        }
    }

    private void _onStart() {
        // Get configuration
        if (instance == null)
        {
            instance = this;

            commandsMgr = new CommandsManager(getBaseContext());
            
            initNotificationStuff();
            updateStatus(DISCONNECTED);

            // first, clean everything
            cleanUp();
            
            // then, re-import preferences
            importPreferences();

            initBatteryMonitor();
            commandsMgr.init();
            
            mCurrentRetryCount = 0;
            mReconnectRunnable = new Runnable() {
                public void run() {
                    Log.v(LOG_TAG, "attempting reconnection");
                    Toast.makeText(XmppService.this, "Reconnecting", Toast.LENGTH_SHORT).show();
                    initConnection();
                }
            };
            initConnection();
        }
    }

    public static XmppService getInstance() {
        return instance;
    }

    @Override
    public IBinder onBind(Intent arg0) {
        return null;
    }

    @Override
    public void onStart(Intent intent, int startId) {
        _onStart();
    };

    @Override
    public void onDestroy() {
        GeoManager.stopLocatingPhone();
        
        cleanUp();
        
        stopForegroundCompat(mStatus);

        instance = null;

        Toast.makeText(this, "GTalkSMS stopped", Toast.LENGTH_SHORT).show();
    }
    
    public void cleanUp() {
        commandsMgr.cleanUp();
        
        clearConnection();
        clearBatteryMonitor();
    }

    public void setLastRecipient(String phoneNumber) {
        commandsMgr.setLastRecipient(phoneNumber);
    }
    
    /** sends a message to the user */
    public void send(String message) {
        if (isConnected()) {
            Message msg = new Message(Settings.mTo, Message.Type.chat);
            msg.setBody(message);
            mConnection.sendPacket(msg);
        }
    }
}
