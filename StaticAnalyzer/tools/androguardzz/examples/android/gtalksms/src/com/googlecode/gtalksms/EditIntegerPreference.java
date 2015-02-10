package com.googlecode.gtalksms;

import android.content.Context;
import android.preference.EditTextPreference;
import android.util.AttributeSet;

/** Used to put an integer in the preferences string (for server port)*/

public class EditIntegerPreference extends EditTextPreference {
	
	public EditIntegerPreference(Context context) { 
		super(context); 
	}
	
	public EditIntegerPreference(Context context, AttributeSet attrs) { 
		super(context, attrs); 
	}
	
	public EditIntegerPreference(Context context, AttributeSet attrs, int defStyle) { 
		super(context, attrs, defStyle); 
	}
	
	@Override 
	public String getText() { 
		return String.valueOf(getSharedPreferences().getInt(getKey(), 0)); 
	}
	
	@Override 
	public void setText(String text) { 
		getSharedPreferences().edit().putInt(getKey(), Integer.parseInt(text)) .commit(); 
	}
	
	@Override 
	protected void onSetInitialValue(boolean restoreValue, Object defaultValue) { 
		if (restoreValue) getEditText().setText(getText()); 
		else super.onSetInitialValue(restoreValue, defaultValue); 
	}
	
} 