// ----------------------------------------------------------------------------
// $Id: Util.java,v 1.10 2003/09/27 00:03:01 raif Exp $
//
// Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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

import java.math.BigInteger;

/**
 * <p>A collection of utility methods used throughout this project.</p>
 *
 * @version $Revision: 1.10 $
 */
public class Util {

   // Constants and variables
   // -------------------------------------------------------------------------

   // Hex charset
   private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();

   // Base-64 charset
   private static final String BASE64_CHARS =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./";
   private static final char[] BASE64_CHARSET = BASE64_CHARS.toCharArray();

   // Constructor(s)
   // -------------------------------------------------------------------------

   /** Trivial constructor to enforce Singleton pattern. */
   private Util() {
      super();
   }

   // Class methods
   // -------------------------------------------------------------------------

   /**
    * <p>Returns a string of hexadecimal digits from a byte array. Each byte is
    * converted to 2 hex symbols; zero(es) included.</p>
    *
    * <p>This method calls the method with same name and three arguments as:</p>
    *
    * <pre>
    *    toString(ba, 0, ba.length);
    * </pre>
    *
    * @param ba the byte array to convert.
    * @return a string of hexadecimal characters (two for each byte)
    * representing the designated input byte array.
    */
   public static String toString(byte[] ba) {
      return toString(ba, 0, ba.length);
   }

   /**
    * <p>Returns a string of hexadecimal digits from a byte array, starting at
    * <code>offset</code> and consisting of <code>length</code> bytes. Each byte
    * is converted to 2 hex symbols; zero(es) included.</p>
    *
    * @param ba the byte array to convert.
    * @param offset the index from which to start considering the bytes to
    * convert.
    * @param length the count of bytes, starting from the designated offset to
    * convert.
    * @return a string of hexadecimal characters (two for each byte)
    * representing the designated input byte sub-array.
    */
   public static final String toString(byte[] ba, int offset, int length) {
      char[] buf = new char[length * 2];
      for (int i = 0, j = 0, k; i < length; ) {
         k = ba[offset + i++];
         buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
         buf[j++] = HEX_DIGITS[ k        & 0x0F];
      }
      return new String(buf);
   }

   /**
    * <p>Returns a string of hexadecimal digits from a byte array. Each byte is
    * converted to 2 hex symbols; zero(es) included. The argument is
    * treated as a large little-endian integer and is returned as a
    * large big-endian integer.</p>
    *
    * <p>This method calls the method with same name and three arguments as:</p>
    *
    * <pre>
    *    toReversedString(ba, 0, ba.length);
    * </pre>
    *
    * @param ba the byte array to convert.
    * @return a string of hexadecimal characters (two for each byte)
    * representing the designated input byte array.
    */
   public static String toReversedString(byte[] ba) {
      return toReversedString(ba, 0, ba.length);
   }

   /**
    * <p>Returns a string of hexadecimal digits from a byte array, starting at
    * <code>offset</code> and consisting of <code>length</code> bytes. Each byte
    * is converted to 2 hex symbols; zero(es) included.</p>
    *
    * <p>The byte array is treated as a large little-endian integer, and
    * is returned as a large big-endian integer.</p>
    *
    * @param ba the byte array to convert.
    * @param offset the index from which to start considering the bytes to
    * convert.
    * @param length the count of bytes, starting from the designated offset to
    * convert.
    * @return a string of hexadecimal characters (two for each byte)
    * representing the designated input byte sub-array.
    */
   public static final String
   toReversedString(byte[] ba, int offset, int length) {
      char[] buf = new char[length * 2];
      for (int i = offset+length-1, j = 0, k; i >= offset; ) {
         k = ba[offset + i--];
         buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
         buf[j++] = HEX_DIGITS[ k        & 0x0F];
      }
      return new String(buf);
   }

   /**
    * <p>Returns a byte array from a string of hexadecimal digits.</p>
    *
    * @param s a string of hexadecimal ASCII characters
    * @return the decoded byte array from the input hexadecimal string.
    */
   public static byte[] toBytesFromString(String s) {
      int limit = s.length();
      byte[] result = new byte[((limit + 1) / 2)];
      int i = 0, j = 0;
      if ((limit % 2) == 1) {
         result[j++] = (byte) fromDigit(s.charAt(i++));
      }
      while (i < limit) {
         result[j  ]  = (byte) (fromDigit(s.charAt(i++)) << 4);
         result[j++] |= (byte)  fromDigit(s.charAt(i++));
      }
      return result;
   }

   /**
    * <p>Returns a byte array from a string of hexadecimal digits, interpreting
    * them as a large big-endian integer and returning it as a large
    * little-endian integer.</p>
    *
    * @param s a string of hexadecimal ASCII characters
    * @return the decoded byte array from the input hexadecimal string.
    */
   public static byte[] toReversedBytesFromString(String s) {
      int limit = s.length();
      byte[] result = new byte[((limit + 1) / 2)];
      int i = 0;
      if ((limit % 2) == 1) {
         result[i++] = (byte) fromDigit(s.charAt(--limit));
      }
      while (limit > 0) {
         result[i  ]  = (byte)  fromDigit(s.charAt(--limit));
         result[i++] |= (byte) (fromDigit(s.charAt(--limit)) << 4);
      }
      return result;
   }

   /**
    * <p>Returns a number from <code>0</code> to <code>15</code> corresponding
    * to the designated hexadecimal digit.</p>
    *
    * @param c a hexadecimal ASCII symbol.
    */
   public static int fromDigit(char c) {
      if (c >= '0' && c <= '9') {
         return c - '0';
      } else if (c >= 'A' && c <= 'F') {
         return c - 'A' + 10;
      } else if (c >= 'a' && c <= 'f') {
         return c - 'a' + 10;
      } else
         throw new IllegalArgumentException("Invalid hexadecimal digit: " + c);
   }

   /**
    * <p>Returns a string of 8 hexadecimal digits (most significant digit first)
    * corresponding to the unsigned integer <code>n</code>.</p>
    *
    * @param n the unsigned integer to convert.
    * @return a hexadecimal string 8-character long.
    */
   public static String toString(int n) {
      char[] buf = new char[8];
      for (int i = 7; i >= 0; i--) {
         buf[i] = HEX_DIGITS[n & 0x0F];
         n >>>= 4;
      }
      return new String(buf);
   }

   /**
    * <p>Returns a string of hexadecimal digits from an integer array. Each int
    * is converted to 4 hex symbols.</p>
    */
   public static String toString(int[] ia) {
      int length = ia.length;
      char[] buf = new char[length * 8];
      for (int i = 0, j = 0, k; i < length; i++) {
         k = ia[i];
         buf[j++] = HEX_DIGITS[(k >>> 28) & 0x0F];
         buf[j++] = HEX_DIGITS[(k >>> 24) & 0x0F];
         buf[j++] = HEX_DIGITS[(k >>> 20) & 0x0F];
         buf[j++] = HEX_DIGITS[(k >>> 16) & 0x0F];
         buf[j++] = HEX_DIGITS[(k >>> 12) & 0x0F];
         buf[j++] = HEX_DIGITS[(k >>>  8) & 0x0F];
         buf[j++] = HEX_DIGITS[(k >>>  4) & 0x0F];
         buf[j++] = HEX_DIGITS[ k         & 0x0F];
      }
      return new String(buf);
   }

   /**
    * <p>Returns a string of 16 hexadecimal digits (most significant digit first)
    * corresponding to the unsigned long <code>n</code>.</p>
    *
    * @param n the unsigned long to convert.
    * @return a hexadecimal string 16-character long.
    */
   public static String toString(long n) {
      char[] b = new char[16];
      for (int i = 15; i >= 0; i--) {
         b[i] = HEX_DIGITS[(int)(n & 0x0FL)];
         n >>>= 4;
      }
      return new String(b);
   }

   /**
    * <p>Similar to the <code>toString()</code> method except that the Unicode
    * escape character is inserted before every pair of bytes. Useful to
    * externalise byte arrays that will be constructed later from such strings;
    * eg. s-box values.</p>
    *
    * @throws ArrayIndexOutOfBoundsException if the length is odd.
    */
   public static String toUnicodeString(byte[] ba) {
      return toUnicodeString(ba, 0, ba.length);
   }

   /**
    * <p>Similar to the <code>toString()</code> method except that the Unicode
    * escape character is inserted before every pair of bytes. Useful to
    * externalise byte arrays that will be constructed later from such strings;
    * eg. s-box values.</p>
    *
    * @throws ArrayIndexOutOfBoundsException if the length is odd.
    */
   public static final String
   toUnicodeString(byte[] ba, int offset, int length) {
      StringBuffer sb = new StringBuffer();
      int i = 0;
      int j = 0;
      int k;
      sb.append('\n').append("\"");
      while (i < length) {
         sb.append("\\u");

         k = ba[offset + i++];
         sb.append(HEX_DIGITS[(k >>> 4) & 0x0F]);
         sb.append(HEX_DIGITS[ k        & 0x0F]);

         k = ba[offset + i++];
         sb.append(HEX_DIGITS[(k >>> 4) & 0x0F]);
         sb.append(HEX_DIGITS[ k        & 0x0F]);

         if ((++j % 8) == 0) {
            sb.append("\"+").append('\n').append("\"");
         }
      }
      sb.append("\"").append('\n');
      return sb.toString();
   }

   /**
    * <p>Similar to the <code>toString()</code> method except that the Unicode
    * escape character is inserted before every pair of bytes. Useful to
    * externalise integer arrays that will be constructed later from such
    * strings; eg. s-box values.</p>
    *
    * @throws ArrayIndexOutOfBoundsException if the length is not a multiple of 4.
    */
   public static String toUnicodeString(int[] ia) {
      StringBuffer sb = new StringBuffer();
      int i = 0;
      int j = 0;
      int k;
      sb.append('\n').append("\"");
      while (i < ia.length) {
         k = ia[i++];
         sb.append("\\u");
         sb.append(HEX_DIGITS[(k >>> 28) & 0x0F]);
         sb.append(HEX_DIGITS[(k >>> 24) & 0x0F]);
         sb.append(HEX_DIGITS[(k >>> 20) & 0x0F]);
         sb.append(HEX_DIGITS[(k >>> 16) & 0x0F]);
         sb.append("\\u");
         sb.append(HEX_DIGITS[(k >>> 12) & 0x0F]);
         sb.append(HEX_DIGITS[(k >>>  8) & 0x0F]);
         sb.append(HEX_DIGITS[(k >>>  4) & 0x0F]);
         sb.append(HEX_DIGITS[ k         & 0x0F]);

         if ((++j % 4) == 0) {
            sb.append("\"+").append('\n').append("\"");
         }
      }
      sb.append("\"").append('\n');
      return sb.toString();
   }

   public static byte[] toBytesFromUnicode(String s) {
      int limit = s.length() * 2;
      byte[] result = new byte[limit];
      char c;
      for (int i = 0; i < limit; i++) {
         c = s.charAt(i >>> 1);
         result[i] = (byte)(((i & 1) == 0) ? c >>> 8 : c);
      }
      return result;
   }

   /**
    * <p>Dumps a byte array as a string, in a format that is easy to read for
    * debugging. The string <code>m</code> is prepended to the start of each
    * line.</p>
    *
    * <p>If <code>offset</code> and <code>length</code> are omitted, the whole
    * array is used. If <code>m</code> is omitted, nothing is prepended to each
    * line.</p>
    *
    * @param data the byte array to be dumped.
    * @param offset the offset within <i>data</i> to start from.
    * @param length the number of bytes to dump.
    * @param m a string to be prepended to each line.
    * @return a string containing the result.
    */
   public static String dumpString(byte[] data, int offset, int length, String m) {
      if (data == null) {
         return m + "null\n";
      }
      StringBuffer sb = new StringBuffer(length * 3);
      if (length > 32) {
         sb.append(m).append("Hexadecimal dump of ").append(length).append(" bytes...\n");
      }
      // each line will list 32 bytes in 4 groups of 8 each
      int end = offset + length;
      String s;
      int l = Integer.toString(length).length();
      if (l < 4) {
         l = 4;
      }
      for ( ; offset < end; offset += 32) {
         if (length > 32) {
            s = "         " + offset;
            sb.append(m).append(s.substring(s.length()-l)).append(": ");
         }
         int i = 0;
         for ( ; i < 32 && offset + i + 7 < end; i += 8) {
            sb.append(toString(data, offset + i, 8)).append(' ');
         }
         if (i < 32) {
            for ( ; i < 32 && offset + i < end; i++) {
               sb.append(byteToString(data[offset + i]));
            }
         }
         sb.append('\n');
      }
      return sb.toString();
   }

   public static String dumpString(byte[] data) {
      return (data == null) ? "null\n" : dumpString(data, 0, data.length, "");
   }

   public static String dumpString(byte[] data, String m) {
      return (data == null) ? "null\n" : dumpString(data, 0, data.length, m);
   }

   public static String dumpString(byte[] data, int offset, int length) {
      return dumpString(data, offset, length, "");
   }

   /**
    * <p>Returns a string of 2 hexadecimal digits (most significant digit first)
    * corresponding to the lowest 8 bits of <code>n</code>.</p>
    *
    * @param n the byte value to convert.
    * @return a string of 2 hex characters representing the input.
    */
   public static String byteToString(int n) {
      char[] buf = { HEX_DIGITS[(n >>> 4) & 0x0F], HEX_DIGITS[n & 0x0F] };
      return new String(buf);
   }

   /**
    * <p>Converts a designated byte array to a Base-64 representation, with the
    * exceptions that (a) leading 0-byte(s) are ignored, and (b) the character
    * '.' (dot) shall be used instead of "+' (plus).</p>
    *
    * <p>Used by SASL password file manipulation primitives.</p>
    *
    * @param buffer an arbitrary sequence of bytes to represent in Base-64.
    * @return unpadded (without the '=' character(s)) Base-64 representation of
    * the input.
    */
   public static final String toBase64(byte[] buffer) {
      int len = buffer.length, pos = len % 3;
      byte b0 = 0, b1 = 0, b2 = 0;
      switch (pos) {
      case 1:
         b2 = buffer[0];
         break;
      case 2:
         b1 = buffer[0];
         b2 = buffer[1];
         break;
      }
      StringBuffer sb = new StringBuffer();
      int c;
      boolean notleading = false;
      do {
         c = (b0 & 0xFC) >>> 2;
         if (notleading || c != 0) {
           sb.append(BASE64_CHARSET[c]);
           notleading = true;
         }
         c = ((b0 & 0x03) << 4) | ((b1 & 0xF0) >>> 4);
         if (notleading || c != 0) {
           sb.append(BASE64_CHARSET[c]);
           notleading = true;
         }
         c = ((b1 & 0x0F) << 2) | ((b2 & 0xC0) >>> 6);
         if (notleading || c != 0) {
           sb.append(BASE64_CHARSET[c]);
           notleading = true;
         }
         c = b2 & 0x3F;
         if (notleading || c != 0) {
           sb.append(BASE64_CHARSET[c]);
           notleading = true;
         }
         if (pos >= len) {
           break;
         } else {
           try {
             b0 = buffer[pos++];
             b1 = buffer[pos++];
             b2 = buffer[pos++];
           } catch (ArrayIndexOutOfBoundsException x) {
             break;
           }
         }
      } while (true);

      if (notleading) {
        return sb.toString();
      }
      return "0";
   }

   /**
    * <p>The inverse function of the above.</p>
    *
    * <p>Converts a string representing the encoding of some bytes in Base-64
    * to their original form.</p>
    *
    * @param str the Base-64 encoded representation of some byte(s).
    * @return the bytes represented by the <code>str</code>.
    * @throws NumberFormatException if <code>str</code> is <code>null</code>, or
    * <code>str</code> contains an illegal Base-64 character.
    * @see #toBase64(byte[])
    */
   public static final byte[] fromBase64(String str) {
      int len = str.length();
      if (len == 0) {
         throw new NumberFormatException("Empty string");
      }
      byte[] a = new byte[len + 1];
      int i, j;
      for (i = 0; i < len; i++) {
         try {
            a[i] = (byte) BASE64_CHARS.indexOf(str.charAt(i));
         } catch (ArrayIndexOutOfBoundsException x) {
            throw new NumberFormatException("Illegal character at #"+i);
         }
      }
      i = len - 1;
      j = len;
      try {
         while (true) {
            a[j] = a[i];
            if (--i < 0) {
               break;
            }
            a[j] |= (a[i] & 0x03) << 6;
            j--;
            a[j] = (byte)((a[i] & 0x3C) >>> 2);
            if (--i < 0) {
               break;
            }
            a[j] |= (a[i] & 0x0F) << 4;
            j--;
            a[j] = (byte)((a[i] & 0x30) >>> 4);
            if (--i < 0) {
               break;
            }
            a[j] |= (a[i] << 2);
            j--;
            a[j] = 0;
            if (--i < 0) {
               break;
            }
         }
      } catch (Exception ignored) {
      }

      try { // ignore leading 0-bytes
         while(a[j] == 0) {
            j++;
         }
      } catch (Exception x) {
         return new byte[1]; // one 0-byte
      }
      byte[] result = new byte[len - j + 1];
      System.arraycopy(a, j, result, 0, len - j + 1);
      return result;
   }

   // BigInteger utilities ----------------------------------------------------

   /**
    * <p>Treats the input as the MSB representation of a number, and discards
    * leading zero elements. For efficiency, the input is simply returned if no
    * leading zeroes are found.</p>
    *
    * @param n the {@link BigInteger} to trim.
    * @return the byte array representation of the designated {@link BigInteger}
    * with no leading 0-bytes.
    */
   public static final byte[] trim(BigInteger n) {
      byte[] in = n.toByteArray();
      if (in.length == 0 || in[0] != 0) {
         return in;
      }
      int len = in.length;
      int i = 1;
      while (in[i] == 0 && i < len) {
         ++i;
      }
      byte[] result = new byte[len - i];
      System.arraycopy(in, i, result, 0, len - i);
      return result;
   }

   /**
    * <p>Returns a hexadecimal dump of the trimmed bytes of a {@link BigInteger}.
    * </p>
    *
    * @param x the {@link BigInteger} to display.
    * @return the string representation of the designated {@link BigInteger}.
    */
   public static final String dump(BigInteger x) {
      return dumpString(trim(x));
   }
}
