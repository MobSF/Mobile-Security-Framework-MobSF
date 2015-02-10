package com.googlecode.gtalksms.contacts;

import java.util.ArrayList;

public class Contact implements Comparable<Contact> {
    public Long id;
    public ArrayList<Long> rawIds = new ArrayList<Long>();
    public String name;

    @Override
    public int compareTo(Contact another) {
        return name.compareTo(another.name);
    }
}
