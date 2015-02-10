package com.googlecode.gtalksms;

import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.Context;
import android.content.Intent;
import android.view.View;
import android.widget.RemoteViews;

public class WidgetProvider extends AppWidgetProvider {

    public void onUpdate(Context context, AppWidgetManager appWidgetManager, int[] appWidgetIds) {
        
        // Create an Intent to launch ExampleActivity
        Intent intent = new Intent(".WidgetGTalkSMS.ACTION");
        PendingIntent pendingIntent = PendingIntent.getBroadcast(context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT);

        // Get the layout for the AppWidget and attach an on-click listener to the button
        RemoteViews views = new RemoteViews(context.getPackageName(), R.layout.appwidget);
        views.setOnClickPendingIntent(R.id.Button, pendingIntent);
        
        // Set FREE label for not donate version
        if (context.getPackageName().endsWith("donate")) {
            views.setViewVisibility(R.id.Label, View.GONE);
        } else {
            views.setViewVisibility(R.id.Label, View.VISIBLE);
        }
        
        // Tell the AppWidgetManager to perform an update on the current AppWidget
        appWidgetManager.updateAppWidget(appWidgetIds, views);
    }
}