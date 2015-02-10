package com.googlecode.gtalksms;

/*
 * Source code of this class originally written by Kevin AN <anyupu@gmail.com>
 * from the project android-phonefinder: http://code.google.com/p/android-phonefinder/
 */

import java.lang.reflect.Method;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Bundle;
import android.os.IBinder;
import android.provider.Settings;

public class LocationService extends Service {

    private LocationManager mLocationManager = null;
    private LocationListener mLocationListener = null;
    private Location currentBestLocation = null;

    private static final int TWO_MINUTES = 1000 * 60 * 2;
    public static final String STOP_SERVICE = "STOP_SERVICE";
    public static final String START_SERVICE = "START_SERVICE";

    @Override
    public IBinder onBind(Intent arg0) {
        return null;
    }

    @Override
    public void onCreate() {
        mLocationManager = (LocationManager) getSystemService(Context.LOCATION_SERVICE);
    }

    /*
     * http://www.maximyudin.com/2008/12/07/android/vklyuchenievyklyuchenie-gps-na-g1-programmno/
     */
    private boolean getGPSStatus()
    {
        String allowedLocationProviders =
            Settings.System.getString(getContentResolver(),
            Settings.System.LOCATION_PROVIDERS_ALLOWED);
        if (allowedLocationProviders == null) {
            allowedLocationProviders = "";
        }
        return allowedLocationProviders.contains(LocationManager.GPS_PROVIDER);
    }

    private void setGPSStatus(boolean pNewGPSStatus)
    {
        String allowedLocationProviders =
            Settings.System.getString(getContentResolver(),
            Settings.System.LOCATION_PROVIDERS_ALLOWED);
        if (allowedLocationProviders == null) {
            allowedLocationProviders = "";
        }
        boolean networkProviderStatus =
            allowedLocationProviders.contains(LocationManager.NETWORK_PROVIDER);
        allowedLocationProviders = "";
        if (networkProviderStatus == true) {
            allowedLocationProviders += LocationManager.NETWORK_PROVIDER;
        }
        if (pNewGPSStatus == true) {
            allowedLocationProviders += "," + LocationManager.GPS_PROVIDER;
        }
        Settings.System.putString(getContentResolver(),
            Settings.System.LOCATION_PROVIDERS_ALLOWED, allowedLocationProviders);
        try {
            Method m =
                mLocationManager.getClass().getMethod("updateProviders", new Class[] {});
            m.setAccessible(true);
            m.invoke(mLocationManager, new Object[]{});
        }
        catch(Exception e) {
        }
        return;
    }

    /**
     * Sends the location to the user.
     * @param location the location to send.
     */
    public void sendLocationUpdate(Location location) {
        StringBuilder builder = new StringBuilder();
        builder.append("http://maps.google.com/maps?q=" + location.getLatitude() + "," + location.getLongitude() + " (");
        builder.append("accuracy: " + location.getAccuracy() + "m ");
        builder.append("altitude: " + location.getAltitude() + " ");
        builder.append("speed: " + location.getSpeed() + "m/s ");
        builder.append("provider: " + location.getProvider() + ")");
        XmppService service = XmppService.getInstance();
        if (service != null) {
            service.send(builder.toString());
        }
    }

    public void onStart(final Intent intent, int startId) {
        super.onStart(intent, startId);

        if ( intent.getAction().equals(STOP_SERVICE) ) {
            destroy();
            stopSelf();
            return;
        }

        try {
            if(!getGPSStatus())
                setGPSStatus(true);
        }
        catch(Exception e) {
        }
        mLocationListener = new LocationListener() {
            public void onLocationChanged(Location location) {
                if (isBetterLocation(location, currentBestLocation)) {
                    currentBestLocation = location;
                    sendLocationUpdate(currentBestLocation);
                }
            }
            public void onStatusChanged(String arg0, int arg1, Bundle arg2) {}
            public void onProviderDisabled(String arg0) {}
            public void onProviderEnabled(String arg0) {}
        };

        // We query every available location providers
        mLocationManager.requestLocationUpdates(LocationManager.GPS_PROVIDER, 0, 0, mLocationListener);
        mLocationManager.requestLocationUpdates(LocationManager.NETWORK_PROVIDER, 0, 0, mLocationListener);

        Location location = mLocationManager.getLastKnownLocation("gps");
        if (location == null)
        {
            location = mLocationManager.getLastKnownLocation("network");
            if (location != null) {
                if (isBetterLocation(location, currentBestLocation)) {
                    currentBestLocation = location;
                    XmppService service = XmppService.getInstance();
                    if (service != null) {
                        service.send("Last known location");
                    }
                    sendLocationUpdate(currentBestLocation);
                }
            }
        }
    }

    public void onDestroy() {
        destroy();
    }

    private void destroy() {
        if (mLocationManager != null && mLocationListener != null) {
            mLocationManager.removeUpdates(mLocationListener);
            mLocationManager = null;
            mLocationListener = null;
        }
    }

    /** From the SDK documentation. Determines whether one Location reading is better than the current Location fix
      * @param location  The new Location that you want to evaluate
      * @param currentBestLocation  The current Location fix, to which you want to compare the new one
      */
    protected boolean isBetterLocation(Location location, Location currentBestLocation) {
        if (currentBestLocation == null) {
            // A new location is always better than no location
            return true;
        }

        // Check whether the new location fix is newer or older
        long timeDelta = location.getTime() - currentBestLocation.getTime();
        boolean isSignificantlyNewer = timeDelta > TWO_MINUTES;
        boolean isSignificantlyOlder = timeDelta < -TWO_MINUTES;
        boolean isNewer = timeDelta > 0;

        // If it's been more than two minutes since the current location, use the new location
        // because the user has likely moved
        if (isSignificantlyNewer) {
            return true;
        // If the new location is more than two minutes older, it must be worse
        } else if (isSignificantlyOlder) {
            return false;
        }

        // Check whether the new location fix is more or less accurate
        int accuracyDelta = (int) (location.getAccuracy() - currentBestLocation.getAccuracy());
        boolean isLessAccurate = accuracyDelta > 0;
        boolean isMoreAccurate = accuracyDelta < 0;
        boolean isSignificantlyLessAccurate = accuracyDelta > 200;

        // Check if the old and new location are from the same provider
        boolean isFromSameProvider = isSameProvider(location.getProvider(),
                currentBestLocation.getProvider());

        // Determine location quality using a combination of timeliness and accuracy
        if (isMoreAccurate) {
            return true;
        } else if (isNewer && !isLessAccurate) {
            return true;
        } else if (isNewer && !isSignificantlyLessAccurate && isFromSameProvider) {
            return true;
        }
        return false;
    }

    /** Checks whether two providers are the same */
    private boolean isSameProvider(String provider1, String provider2) {
        if (provider1 == null) {
          return provider2 == null;
        }
        return provider1.equals(provider2);
    }
}
