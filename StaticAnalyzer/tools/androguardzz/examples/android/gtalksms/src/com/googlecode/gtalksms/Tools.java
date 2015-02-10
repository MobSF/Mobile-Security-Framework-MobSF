package com.googlecode.gtalksms;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.database.Cursor;

public class Tools {

    public static String getVersionName(Context context, Class<?> cls) {

        try {
            ComponentName comp = new ComponentName(context, cls);
            PackageInfo pinfo = context.getPackageManager().getPackageInfo(
                    comp.getPackageName(), 0);

            return "v" + pinfo.versionName + " by Yakoo";
        } catch (android.content.pm.PackageManager.NameNotFoundException e) {
            return "";
        }
    }
    
    public static <T> List<T> getLastElements(ArrayList<T> list, int nbElems) {
        return list.subList(Math.max(list.size() - nbElems, 0), list.size());
    }
    
    public static Long getLong(Cursor c, String col) {
        return c.getLong(c.getColumnIndex(col));
    }
    
    public static int getInt(Cursor c, String col) {
        return c.getInt(c.getColumnIndex(col));
    }

    public static String getString(Cursor c, String col) {
        return c.getString(c.getColumnIndex(col));
    }

    public static boolean getBoolean(Cursor c, String col) {
        return getInt(c, col) == 1;
    }

    public static Date getDateSeconds(Cursor c, String col) {
        return new Date(Long.parseLong(Tools.getString(c, col)) * 1000);
    }

    public static Date getDateMilliSeconds(Cursor c, String col) {
        return new Date(Long.parseLong(Tools.getString(c, col)));
    }
}
