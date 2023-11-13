Java.perform(function () {

    // Config
    var CONFIG = {
        // if TRUE print stack trace
        printStackTrace: false
    };



    // Initialise Android Objects
    var mediaRecorder = Java.use('android.media.MediaRecorder');
    var audioRecord = Java.use('android.media.AudioRecord');



    // Set audio source
    mediaRecorder.setAudioSource.overload('int').implementation = function (audioSource) {
        send('[Media Recorder.Audio] Setting audio source to -> ' + audioSource);
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.setAudioSource(audioSource);
    };

    // Set video source
    mediaRecorder.setVideoSource.overload('int').implementation = function (videoSource) {
        send('[Media Recorder.Video] Setting video source to -> ' + videoSource);
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.setVideoSource(audioSource);
    };

    // Set output format
    mediaRecorder.setOutputFormat.overload('int').implementation = function (outputFormat) {
        var outputFormatValue = {
            0: 'DEFAULT',
            1: 'THREE_GPP',
            2: 'MPEG_4',
            3: 'RAW_AMR',
            8: 'MPEG_2_TS',
            9: 'WEBM',
            11: 'OGG'
        };

        try {
            send('[Media Recorder] Setting output format -> ' + outputFormatValue[outputFormat]);
        } catch (err) {
            send('[Media Recorder] Setting output format -> ' + outputFormat);
        }
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.setOutputFormat(outputFormat);
    };

    // Set audio encoder
    mediaRecorder.setAudioEncoder.overload('int').implementation = function (audioEncoder) {
        var audioEncoderValue = {
            0: 'DEFAULT',
            4: 'HE_AAC',
            6: 'VORBIS',
            7: 'OPUS'
        };

        try {
            send('[Media Recorder.Audio] Setting audio encoder -> ' + audioEncoderValue[audioEncoder]);
        } catch (err) {
            send('[Media Recorder.Audio] Setting audio encoder -> ' + audioEncoder);
        }
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.setAudioEncoder(audioEncoder);
    };

    // Set audio encoder
    mediaRecorder.setVideoEncoder.overload('int').implementation = function (videoEncoder) {
        var videoEncoderValue = {
            0: 'DEFAULT',
            1: 'H263',
            2: 'H264',
            3: 'MPEG_4_SP',
            4: 'VP8',
            5: 'HEVC',
            6: 'VP9',
            7: 'DOLBY_VISION'
        };

        try {
            send('[Media Recorder.Video] Setting video encoder -> ' + videoEncoderValue[videoEncoder]);
        } catch (err) {
            send('[Media Recorder.Video] Setting video encoder -> ' + videoEncoder);
        }
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.setVideoEncoder(videoEncoder);
    };

    // Set output file
    mediaRecorder.setOutputFile.overload('java.io.FileDescriptor').implementation = function (fileDescriptor) {
        send('[Media Recorder] Setting output file');
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.setOutputFile(fileDescriptor);
    };
    mediaRecorder.setOutputFile.overload('java.lang.String').implementation = function (filePath) {
        send('[Media Recorder] Setting output file -> ' + filePath);
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.setOutputFile(filePath);
    };
    mediaRecorder.setOutputFile.overload('java.io.File').implementation = function (file) {
        send('[Media Recorder] Setting output file -> ' + file.getPath());
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.setOutputFile(file);
    };

    // Start recording
    mediaRecorder.start.implementation = function () {
        send('[Media Recorder] Starting recording');
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.start();
    };



    // Set audio source
    audioRecord.startRecording.overload().implementation = function () {
        send('[Audio Record] Starting Audio Recording');
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.startRecording();
    };
    audioRecord.startRecording.overload('android.media.MediaSyncEvent').implementation = function (mediaSyncEvent) {
        send('[Audio Record] Starting Audio Recording');
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.startRecording(mediaSyncEvent);
    };



    // Stack Trace Function
    function stackTrace() {
        send(Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
    }
});