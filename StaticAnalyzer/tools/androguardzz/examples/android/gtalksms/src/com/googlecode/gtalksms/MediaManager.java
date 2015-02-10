package com.googlecode.gtalksms;

import android.content.Context;
import android.media.AudioManager;
import android.media.MediaPlayer;
import android.net.Uri;

public class MediaManager {
    private MediaPlayer mMediaPlayer;
    private boolean canRing;
    
    /** clears the media player */
    public void clearMediaPlayer() {
        if (mMediaPlayer != null) {
            mMediaPlayer.stop();
        }
        mMediaPlayer = null;
    }

    /** init the media player */
    public void initMediaPlayer(Context c) {
        canRing = true;
        Uri alert = Uri.parse(XmppService.Settings.ringtone);
        mMediaPlayer = new MediaPlayer();
        try {
            mMediaPlayer.setDataSource(c, alert);
        } catch (Exception e) {
            canRing = false;
        }
        mMediaPlayer.setAudioStreamType(AudioManager.STREAM_ALARM);
        mMediaPlayer.setLooping(true);
    }
    
    /** makes the phone ring */
    public boolean ring(Context c) {
        boolean res = false;
        final AudioManager audioManager = (AudioManager) c.getSystemService(Context.AUDIO_SERVICE);
        if (canRing && audioManager.getStreamVolume(AudioManager.STREAM_ALARM) != 0) {
            try {
                mMediaPlayer.prepare();
            } catch (Exception e) {
                canRing = false;
            }
            mMediaPlayer.start();
            
            res = true;
        }
        return res;
    }

    /** Stops the phone from ringing */
    public void stopRinging() {
        if (canRing) {
            mMediaPlayer.stop();
        }
    }

}