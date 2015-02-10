;;;; Copyright 2007 The Android Open Source Project

;;; Set up GUD+JDB to attach to a Java process running on the phone or
;;; under the emulator.

(defvar android-jdb-port-history '("8700")
 "history of ports supplied to `android-jdb'")

(defvar android-jdb-project-root-history '()
 "history of project roots supplied to `android-jdb'")
(defvar android-jdb-history nil
 "history of commands supplied to `android-jdb'")

(defvar android-jdb-activity-class-history ()
 "history of activity classes supplied to `start-android-activity'")

(defcustom  android-jdb-command-name "jdb"
  "Name of Java debugger."
  :type 'string
  :group 'android)

(defgroup android nil
  "Android Applications."
  :group 'applications)

(defcustom android-project-root nil
 "This is where your Android project root is stored."
  :type 'directory
 :group 'android )

(defcustom android-apk nil
 "This is where your Android Application Package is stored."
 :type 'string
 :group 'android)

(defcustom android-activity-class nil
 "This is where your Android Activity class is stored."
 :type 'string
 :group 'android)

(defun android-read-project-root ()
 (if (or (string-match "XEmacs" emacs-version)
         (>= emacs-major-version 22))
     (read-file-name "Android project root: "
                     android-project-root
                     nil
                     t
                     nil
                     'file-directory-p)
   (labels ((read-directory ()
                            (read-file-name "Android project root: "
                                            android-project-root
                                            nil
                                            t
                                            nil)))
     (do ((entered-root (read-directory) (read-directory)))
         ((and entered-root
               (file-directory-p entered-root))
          (expand-file-name entered-root))))))

(defun android-jdb (port root)
 "Set GUD+JDB up to run against Android on PORT in directory ROOT."
 (interactive
  (list
   (read-from-minibuffer "Activity's JDWP DDMS port: "
                     (car android-jdb-port-history)
                     nil
                     t
                     'android-jdb-port-history)
                    (android-read-project-root)))
 (setq android-project-root root)
 (let ((jdb-command
        (format "%s -attach localhost:%s -sourcepath%s"
                android-jdb-command-name
                port
                (format "%s/src" root))))
   (if (not (string= jdb-command (car android-jdb-history)))
       (push jdb-command android-jdb-history))
   (jdb jdb-command)))

(defun android-emulate ()
 "Run the Android emulator. This expects the SDK tools directory to be in the current path."
 (interactive)
 (compile "emulator"))

(defun android-install-app (apk)
  "Install an Android application package APK in the Android emulator. This expects the SDK tools directory to be in the current path."
  (interactive (list (expand-file-name
                      (read-file-name "Android Application Package (.apk): "
                                      nil
                                      android-apk
                                      t
                                      nil
                                      nil))))
  (setq android-apk apk)
  (compile (format "adb install -r %s" apk)))

(defun android-uninstall-app (package-name)
  "Uninstall an Android application package APK in the Android emulator. This expects the SDK tools directory to be in the current path.
Specify the package name --- and not the name of the application e.g., com.android.foo."
  (interactive
   (list
    (read-from-minibuffer "Package: ")))
  (compile (format "adb uninstall %s" package-name)))

(defun android-start-activity (package class)
 "Start the activity PACKAGE/CLASS in the Android emulator. This expects the SDK tools directory to be in the current path."
 (interactive
  (list
   (read-from-minibuffer "Package: ")
   (read-from-minibuffer "Activity Java class: "
         (car android-jdb-activity-class-history)
         nil
         t
         'android-jdb-activity-class-history)))
 (compile (format "adb shell am start -n %s/%s" package class)))

(defun android-debug-activity (package class)
 "Start the activity PACKAGE/CLASS within the debugger in the Android emulator. This expects the SDK tools directory to be in the current path."
 (interactive
  (list
   (read-from-minibuffer "Package: ")
   (read-from-minibuffer "Activity Java class: "
         (car android-jdb-activity-class-history)
         nil
         t
         'android-jdb-activity-class-history)))
 (compile (format "adb shell am start -D -n %s/%s" package class)))

(provide 'android)

