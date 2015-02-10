package org.t0t0.androguard.android;                                                                                                                                                                                              

// ----------------------------------------------------------------------------
// $Id: Properties.java,v 1.7 2004/01/14 23:17:42 rsdio Exp $
//
// Copyright (C) 2003, 2004 Free Software Foundation, Inc.
//
// This file is part of GNU Crypto.
//
// GNU Crypto is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2, or (at your option)
// any later version.
//
// GNU Crypto is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; see the file COPYING.  If not, write to the
//
//    Free Software Foundation Inc.,
//    59 Temple Place - Suite 330,
//    Boston, MA 02111-1307
//    USA
//
// Linking this library statically or dynamically with other modules is
// making a combined work based on this library.  Thus, the terms and
// conditions of the GNU General Public License cover the whole
// combination.
//
// As a special exception, the copyright holders of this library give
// you permission to link this library with independent modules to
// produce an executable, regardless of the license terms of these
// independent modules, and to copy and distribute the resulting
// executable under terms of your choice, provided that you also meet,
// for each linked independent module, the terms and conditions of the
// license of that module.  An independent module is a module which is
// not derived from or based on this library.  If you modify this
// library, you may extend this exception to your version of the
// library, but you are not obligated to do so.  If you do not wish to
// do so, delete this exception statement from your version.
// ----------------------------------------------------------------------------

import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;

import java.security.AccessController;
import java.security.PrivilegedAction;

import java.util.HashMap;
import java.util.PropertyPermission;

/**
 * <p>A global object containing build-specific properties that affect the
 * behaviour of the generated binaries from this library.</p>
 *
 * @version $Revision: 1.7 $
 */
public final class Properties {

   // Debugging methods and variables
   // -------------------------------------------------------------------------

   private static final String NAME = "Properties";
   private static final boolean DEBUG = true;
//   private static final int debuglevel = 9;
   private static final PrintWriter err = new PrintWriter(System.out, true);
   private static void debug(final String s) {
      err.println(">>> "+NAME+": "+s);
   }

   // Constants and variables
   // -------------------------------------------------------------------------

   public static final String PROPERTIES_FILE = "gnu.crypto.properties.file";
   public static final String REPRODUCIBLE_PRNG = "gnu.crypto.with.reproducible.prng";
   public static final String CHECK_WEAK_KEYS = "gnu.crypto.with.check.for.weak.keys";
   public static final String DO_RSA_BLINDING = "gnu.crypto.with.rsa.blinding";

   private static final String TRUE = Boolean.TRUE.toString();
   private static final String FALSE = Boolean.FALSE.toString();
   private static final HashMap props = new HashMap();
   private static Properties singleton = null;

   private boolean reproducible = false;
   private boolean checkForWeakKeys = true;
   private boolean doRSABlinding = true;

   // Constructor(s)
   // -------------------------------------------------------------------------

   /** Trivial constructor to enforce Singleton pattern. */
   private Properties() {
      super();

      init();
   }

   // Class methods
   // -------------------------------------------------------------------------

   /**
    * <p>Returns the string representation of the library global configuration
    * property with the designated <code>key</code>.</p>
    *
    * @param key the case-insensitive, non-null and non-empty name of a
    * configuration property.
    * @return the string representation of the designated property, or
    * <code>null</code> if such property is not yet set, or <code>key</code> is
    * empty.
    */
   public static synchronized final String getProperty(String key) {
      if (key == null) {
         return null;
      }
      SecurityManager sm = System.getSecurityManager();
      if (sm != null) {
         sm.checkPermission(new PropertyPermission(key, "read"));
      }
      key = key.trim().toLowerCase();
      if ("".equals(key)) {
         return null;
      }
      return (String) props.get(key);
   }

   /**
    * <p>Sets the value of a designated library global configuration property,
    * to a string representation of what should be a legal value.</p>
    *
    * @param key the case-insensitive, non-null and non-empty name of a
    * configuration property.
    * @param value the non-null, non-empty string representation of a legal
    * value of the configuration property named by <code>key</code>.
    */
   public static synchronized final void setProperty(String key, String value) {
      if (key == null || value == null) {
         return;
      }
      key = key.trim().toLowerCase();
      if ("".equals(key)) {
         return;
      }
      value = value.trim();
      if ("".equals(value)) {
         return;
      }
      SecurityManager sm = System.getSecurityManager();
      if (sm != null) {
         sm.checkPermission(new PropertyPermission(key, "write"));
      }
      if (key.equals(REPRODUCIBLE_PRNG)
            && (value.equalsIgnoreCase(TRUE) || value.equalsIgnoreCase(FALSE))) {
         setReproducible(Boolean.valueOf(value).booleanValue());
      } else if (key.equals(CHECK_WEAK_KEYS)
            && (value.equalsIgnoreCase(TRUE) || value.equalsIgnoreCase(FALSE))) {
         setCheckForWeakKeys(Boolean.valueOf(value).booleanValue());
      } else if (key.equals(DO_RSA_BLINDING)
            && (value.equalsIgnoreCase(TRUE) || value.equalsIgnoreCase(FALSE))) {
         setDoRSABlinding(Boolean.valueOf(value).booleanValue());
      } else {
         props.put(key, value);
      }
   }

   /**
    * <p>A convenience method that returns, as a boolean, the library global
    * configuration property indicating if the default Pseudo Random Number
    * Generator produces, or not, the same bit stream when instantiated.</p>
    *
    * @return <code>true</code> if the default PRNG produces the same bit stream
    * with every VM instance. Returns <code>false</code> if the default PRNG is
    * seeded with the time of day of its first invocation.
    */
   public static synchronized final boolean isReproducible() {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null) {
         sm.checkPermission(new PropertyPermission(REPRODUCIBLE_PRNG, "read"));
      }
      return instance().reproducible;
   }

   /**
    * <p>A convenience method that returns, as a boolean, the library global
    * configuration property indicating if the implementations of symmetric
    * key block ciphers check, or not, for possible/potential weak and semi-weak
    * keys that may be produced in the course of generating round encryption
    * and/or decryption keys.</p>
    *
    * @return <code>true</code> if the cipher implementations check for weak and
    * semi-weak keys. Returns <code>false</code> if the cipher implementations
    * do not check for weak or semi-weak keys.
    */
   public static synchronized final boolean checkForWeakKeys() {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null) {
         sm.checkPermission(new PropertyPermission(CHECK_WEAK_KEYS, "read"));
      }
      return instance().checkForWeakKeys;
   }

   /**
    * <p>A convenience method that returns, as a boolean, the library global
    * configuration property indicating if RSA decryption (RSADP primitive),
    * does, or not, blinding against timing attacks.</p>
    *
    * @return <code>true</code> if the RSA decryption primitive includes a
    * blinding operation. Returns <code>false</code> if the RSA decryption
    * primitive does not include the additional blinding operation.
    */
   public static synchronized final boolean doRSABlinding() {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null) {
         sm.checkPermission(new PropertyPermission(DO_RSA_BLINDING, "read"));
      }
      return instance().doRSABlinding;
   }

   /**
    * <p>A convenience method to set the global property for reproducibility of
    * the default PRNG bit stream output.</p>
    *
    * @param value if <code>true</code> then the default PRNG bit stream output
    * is the same with every invocation of the VM.
    */
   public static synchronized final void setReproducible(final boolean value) {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null) {
         sm.checkPermission(new PropertyPermission(REPRODUCIBLE_PRNG, "write"));
      }
      instance().reproducible = value;
      props.put(REPRODUCIBLE_PRNG, String.valueOf(value));
   }

   /**
    * <p>A convenience method to set the global property for checking for weak
    * and semi-weak cipher keys.</p>
    *
    * @param value if <code>true</code> then the cipher implementations will
    * invoke additional checks for weak and semi-weak key values that may get
    * generated.
    */
   public static synchronized final void setCheckForWeakKeys(final boolean value) {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null) {
         sm.checkPermission(new PropertyPermission(CHECK_WEAK_KEYS, "write"));
      }
      instance().checkForWeakKeys = value;
      props.put(CHECK_WEAK_KEYS, String.valueOf(value));
   }

   /**
    * <p>A convenience method to set the global property fo adding a blinding
    * operation when executing the RSA decryption primitive.</p>
    *
    * @param value if <code>true</code> then the code for performing the RSA
    * decryption primitive will include a blinding operation.
    */
   public static synchronized final void setDoRSABlinding(final boolean value) {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null) {
         sm.checkPermission(new PropertyPermission(DO_RSA_BLINDING, "write"));
      }
      instance().doRSABlinding = value;
      props.put(DO_RSA_BLINDING, String.valueOf(value));
   }

   private static synchronized final Properties instance() {
      if (singleton == null) {
         singleton = new Properties();
      }
      return singleton;
   }

   // Instance methods
   // -------------------------------------------------------------------------

   private void init() {
      // default values
      props.put(REPRODUCIBLE_PRNG, new Boolean(reproducible).toString());
      props.put(CHECK_WEAK_KEYS,   new Boolean(checkForWeakKeys).toString());
      props.put(DO_RSA_BLINDING,   new Boolean(doRSABlinding).toString());

      // 1. allow site-wide override by reading a properties file
      String propFile = null;
      try {
         propFile = (String) AccessController.doPrivileged(
            new PrivilegedAction() {
               public Object run() {
                  return System.getProperty(PROPERTIES_FILE);
               }
            }
         );
      } catch (SecurityException se) {
         if (DEBUG) debug("Reading property "+PROPERTIES_FILE+" not allowed. Ignored.");
      }
      if (propFile != null) {
         try {
            final java.util.Properties temp = new java.util.Properties();
            final FileInputStream fin = new FileInputStream(propFile);
            temp.load(fin);
            temp.list(System.out);
            props.putAll(temp);
         } catch (IOException ioe) {
            if (DEBUG) debug("IO error reading "+propFile+": "+ioe.getMessage());
         } catch (SecurityException se) {
            if (DEBUG) debug("Security error reading "+propFile+": "+se.getMessage());
         }
      }

      // 2. allow vm-specific override by allowing -D options in launcher
      handleBooleanProperty(REPRODUCIBLE_PRNG);
      handleBooleanProperty(CHECK_WEAK_KEYS);
      handleBooleanProperty(DO_RSA_BLINDING);

      // re-sync the 'known' properties
      reproducible =     new Boolean((String) props.get(REPRODUCIBLE_PRNG)).booleanValue();
      checkForWeakKeys = new Boolean((String) props.get(CHECK_WEAK_KEYS)).booleanValue();
      doRSABlinding =    new Boolean((String) props.get(DO_RSA_BLINDING)).booleanValue();
   }

   private void handleBooleanProperty(final String name) {
      String s = null;
      try {
         s = System.getProperty(name);
      } catch (SecurityException x) {
         if (DEBUG) debug("SecurityManager forbids reading system properties. Ignored");
      }
      if (s != null) {
         s = s.trim().toLowerCase();
         // we have to test for explicit "true" or "false".  anything else may
         // hide valid value set previously
         if (s.equals(TRUE) || s.equals(FALSE)) {
            if (DEBUG) debug("Setting "+name+" to '"+s+"'");
            props.put(name, s);
         } else {
            if (DEBUG) debug("Invalid value for -D"+name+": "+s+". Ignored");
         }
      }
   }
}
