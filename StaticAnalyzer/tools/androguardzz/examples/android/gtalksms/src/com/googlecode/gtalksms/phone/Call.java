package com.googlecode.gtalksms.phone;

import java.util.Date;

public class Call {
    final static public String [] Type = {"Unknown", "Incoming", "Outgoing", "Missed"};
    public String phoneNumber;
    public String type;
    public long duration;
    public Date date;
    public boolean isNew;
    
    public String duration() {
        long minutes = duration / 60;
        long seconds = duration % 60;
        String res = "";
        
        if (minutes > 0) {
            res = minutes + "min ";
        }
        
        return res + seconds + "s";
    }
}
