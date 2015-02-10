package org.t0t0.androguard.android;                                                                                                                                                                                              

// ----------------------------------------------------------------------------
// $Id: DES.java,v 1.3 2003/10/05 03:41:38 raif Exp $
//
// Copyright (C) 2002, 2003 Free Software Foundation, Inc.
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
//
// --------------------------------------------------------------------------

import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;

/**
 * <p>The Data Encryption Standard. DES is a 64-bit block cipher with a 56-bit
 * key, developed by IBM in the 1970's for the standardization process begun by
 * the National Bureau of Standards (now NIST).</p>
 *
 * <p>New applications should not use DES except for compatibility.</p>
 *
 * <p>This version is based upon the description and sample implementation in
 * [1].</p>
 *
 * <p>References:</p>
 * <ol>
 *    <li>Bruce Schneier, <i>Applied Cryptography: Protocols, Algorithms, and
 *    Source Code in C, Second Edition</i>. (1996 John Wiley and Sons) ISBN
 *    0-471-11709-9. Pages 265--301, 623--632.</li>
 * </ol>
 *
 * @version $Revision: 1.3 $
 */
public class DES extends BaseCipher {

   // Constants and variables
   // -------------------------------------------------------------------------

   /** DES operates on 64 bit blocks. */
   public static final int BLOCK_SIZE = 8;

   /** DES uses 56 bits of a 64 bit parity-adjusted key. */
   public static final int KEY_SIZE = 8;

   // S-Boxes 1 through 8.
   private static final int[] SP1 = new int[] {
      0x01010400, 0x00000000, 0x00010000, 0x01010404,
      0x01010004, 0x00010404, 0x00000004, 0x00010000,
      0x00000400, 0x01010400, 0x01010404, 0x00000400,
      0x01000404, 0x01010004, 0x01000000, 0x00000004,
      0x00000404, 0x01000400, 0x01000400, 0x00010400,
      0x00010400, 0x01010000, 0x01010000, 0x01000404,
      0x00010004, 0x01000004, 0x01000004, 0x00010004,
      0x00000000, 0x00000404, 0x00010404, 0x01000000,
      0x00010000, 0x01010404, 0x00000004, 0x01010000,
      0x01010400, 0x01000000, 0x01000000, 0x00000400,
      0x01010004, 0x00010000, 0x00010400, 0x01000004,
      0x00000400, 0x00000004, 0x01000404, 0x00010404,
      0x01010404, 0x00010004, 0x01010000, 0x01000404,
      0x01000004, 0x00000404, 0x00010404, 0x01010400,
      0x00000404, 0x01000400, 0x01000400, 0x00000000,
      0x00010004, 0x00010400, 0x00000000, 0x01010004
   };

   private static final int[] SP2 = new int[] {
      0x80108020, 0x80008000, 0x00008000, 0x00108020,
      0x00100000, 0x00000020, 0x80100020, 0x80008020,
      0x80000020, 0x80108020, 0x80108000, 0x80000000,
      0x80008000, 0x00100000, 0x00000020, 0x80100020,
      0x00108000, 0x00100020, 0x80008020, 0x00000000,
      0x80000000, 0x00008000, 0x00108020, 0x80100000,
      0x00100020, 0x80000020, 0x00000000, 0x00108000,
      0x00008020, 0x80108000, 0x80100000, 0x00008020,
      0x00000000, 0x00108020, 0x80100020, 0x00100000,
      0x80008020, 0x80100000, 0x80108000, 0x00008000,
      0x80100000, 0x80008000, 0x00000020, 0x80108020,
      0x00108020, 0x00000020, 0x00008000, 0x80000000,
      0x00008020, 0x80108000, 0x00100000, 0x80000020,
      0x00100020, 0x80008020, 0x80000020, 0x00100020,
      0x00108000, 0x00000000, 0x80008000, 0x00008020,
      0x80000000, 0x80100020, 0x80108020, 0x00108000
   };

   private static final int[] SP3 = new int[] {
      0x00000208, 0x08020200, 0x00000000, 0x08020008,
      0x08000200, 0x00000000, 0x00020208, 0x08000200,
      0x00020008, 0x08000008, 0x08000008, 0x00020000,
      0x08020208, 0x00020008, 0x08020000, 0x00000208,
      0x08000000, 0x00000008, 0x08020200, 0x00000200,
      0x00020200, 0x08020000, 0x08020008, 0x00020208,
      0x08000208, 0x00020200, 0x00020000, 0x08000208,
      0x00000008, 0x08020208, 0x00000200, 0x08000000,
      0x08020200, 0x08000000, 0x00020008, 0x00000208,
      0x00020000, 0x08020200, 0x08000200, 0x00000000,
      0x00000200, 0x00020008, 0x08020208, 0x08000200,
      0x08000008, 0x00000200, 0x00000000, 0x08020008,
      0x08000208, 0x00020000, 0x08000000, 0x08020208,
      0x00000008, 0x00020208, 0x00020200, 0x08000008,
      0x08020000, 0x08000208, 0x00000208, 0x08020000,
      0x00020208, 0x00000008, 0x08020008, 0x00020200
   };

   private static final int[] SP4 = new int[] {
      0x00802001, 0x00002081, 0x00002081, 0x00000080,
      0x00802080, 0x00800081, 0x00800001, 0x00002001,
      0x00000000, 0x00802000, 0x00802000, 0x00802081,
      0x00000081, 0x00000000, 0x00800080, 0x00800001,
      0x00000001, 0x00002000, 0x00800000, 0x00802001,
      0x00000080, 0x00800000, 0x00002001, 0x00002080,
      0x00800081, 0x00000001, 0x00002080, 0x00800080,
      0x00002000, 0x00802080, 0x00802081, 0x00000081,
      0x00800080, 0x00800001, 0x00802000, 0x00802081,
      0x00000081, 0x00000000, 0x00000000, 0x00802000,
      0x00002080, 0x00800080, 0x00800081, 0x00000001,
      0x00802001, 0x00002081, 0x00002081, 0x00000080,
      0x00802081, 0x00000081, 0x00000001, 0x00002000,
      0x00800001, 0x00002001, 0x00802080, 0x00800081,
      0x00002001, 0x00002080, 0x00800000, 0x00802001,
      0x00000080, 0x00800000, 0x00002000, 0x00802080
   };

   private static final int[] SP5 = new int[] {
      0x00000100, 0x02080100, 0x02080000, 0x42000100,
      0x00080000, 0x00000100, 0x40000000, 0x02080000,
      0x40080100, 0x00080000, 0x02000100, 0x40080100,
      0x42000100, 0x42080000, 0x00080100, 0x40000000,
      0x02000000, 0x40080000, 0x40080000, 0x00000000,
      0x40000100, 0x42080100, 0x42080100, 0x02000100,
      0x42080000, 0x40000100, 0x00000000, 0x42000000,
      0x02080100, 0x02000000, 0x42000000, 0x00080100,
      0x00080000, 0x42000100, 0x00000100, 0x02000000,
      0x40000000, 0x02080000, 0x42000100, 0x40080100,
      0x02000100, 0x40000000, 0x42080000, 0x02080100,
      0x40080100, 0x00000100, 0x02000000, 0x42080000,
      0x42080100, 0x00080100, 0x42000000, 0x42080100,
      0x02080000, 0x00000000, 0x40080000, 0x42000000,
      0x00080100, 0x02000100, 0x40000100, 0x00080000,
      0x00000000, 0x40080000, 0x02080100, 0x40000100
   };

   private static final int[] SP6 = new int[] {
      0x20000010, 0x20400000, 0x00004000, 0x20404010,
      0x20400000, 0x00000010, 0x20404010, 0x00400000,
      0x20004000, 0x00404010, 0x00400000, 0x20000010,
      0x00400010, 0x20004000, 0x20000000, 0x00004010,
      0x00000000, 0x00400010, 0x20004010, 0x00004000,
      0x00404000, 0x20004010, 0x00000010, 0x20400010,
      0x20400010, 0x00000000, 0x00404010, 0x20404000,
      0x00004010, 0x00404000, 0x20404000, 0x20000000,
      0x20004000, 0x00000010, 0x20400010, 0x00404000,
      0x20404010, 0x00400000, 0x00004010, 0x20000010,
      0x00400000, 0x20004000, 0x20000000, 0x00004010,
      0x20000010, 0x20404010, 0x00404000, 0x20400000,
      0x00404010, 0x20404000, 0x00000000, 0x20400010,
      0x00000010, 0x00004000, 0x20400000, 0x00404010,
      0x00004000, 0x00400010, 0x20004010, 0x00000000,
      0x20404000, 0x20000000, 0x00400010, 0x20004010
   };

   private static final int[] SP7 = new int[] {
      0x00200000, 0x04200002, 0x04000802, 0x00000000,
      0x00000800, 0x04000802, 0x00200802, 0x04200800,
      0x04200802, 0x00200000, 0x00000000, 0x04000002,
      0x00000002, 0x04000000, 0x04200002, 0x00000802,
      0x04000800, 0x00200802, 0x00200002, 0x04000800,
      0x04000002, 0x04200000, 0x04200800, 0x00200002,
      0x04200000, 0x00000800, 0x00000802, 0x04200802,
      0x00200800, 0x00000002, 0x04000000, 0x00200800,
      0x04000000, 0x00200800, 0x00200000, 0x04000802,
      0x04000802, 0x04200002, 0x04200002, 0x00000002,
      0x00200002, 0x04000000, 0x04000800, 0x00200000,
      0x04200800, 0x00000802, 0x00200802, 0x04200800,
      0x00000802, 0x04000002, 0x04200802, 0x04200000,
      0x00200800, 0x00000000, 0x00000002, 0x04200802,
      0x00000000, 0x00200802, 0x04200000, 0x00000800,
      0x04000002, 0x04000800, 0x00000800, 0x00200002
   };

   private static final int[] SP8 = new int[] {
      0x10001040, 0x00001000, 0x00040000, 0x10041040,
      0x10000000, 0x10001040, 0x00000040, 0x10000000,
      0x00040040, 0x10040000, 0x10041040, 0x00041000,
      0x10041000, 0x00041040, 0x00001000, 0x00000040,
      0x10040000, 0x10000040, 0x10001000, 0x00001040,
      0x00041000, 0x00040040, 0x10040040, 0x10041000,
      0x00001040, 0x00000000, 0x00000000, 0x10040040,
      0x10000040, 0x10001000, 0x00041040, 0x00040000,
      0x00041040, 0x00040000, 0x10041000, 0x00001000,
      0x00000040, 0x10040040, 0x00001000, 0x00041040,
      0x10001000, 0x00000040, 0x10000040, 0x10040000,
      0x10040040, 0x10000000, 0x00040000, 0x10001040,
      0x00000000, 0x10041040, 0x00040040, 0x10000040,
      0x10040000, 0x10001000, 0x10001040, 0x00000000,
      0x10041040, 0x00041000, 0x00041000, 0x00001040,
      0x00001040, 0x00040040, 0x10000000, 0x10041000
   };

   /**
    * Constants that help in determining whether or not a byte array is parity
    * adjusted.
    */
   private static final byte[] PARITY = {
      8,1,0,8,0,8,8,0,0,8,8,0,8,0,2,8,0,8,8,0,8,0,0,8,8,0,0,8,0,8,8,3,
      0,8,8,0,8,0,0,8,8,0,0,8,0,8,8,0,8,0,0,8,0,8,8,0,0,8,8,0,8,0,0,8,
      0,8,8,0,8,0,0,8,8,0,0,8,0,8,8,0,8,0,0,8,0,8,8,0,0,8,8,0,8,0,0,8,
      8,0,0,8,0,8,8,0,0,8,8,0,8,0,0,8,0,8,8,0,8,0,0,8,8,0,0,8,0,8,8,0,
      0,8,8,0,8,0,0,8,8,0,0,8,0,8,8,0,8,0,0,8,0,8,8,0,0,8,8,0,8,0,0,8,
      8,0,0,8,0,8,8,0,0,8,8,0,8,0,0,8,0,8,8,0,8,0,0,8,8,0,0,8,0,8,8,0,
      8,0,0,8,0,8,8,0,0,8,8,0,8,0,0,8,0,8,8,0,8,0,0,8,8,0,0,8,0,8,8,0,
      4,8,8,0,8,0,0,8,8,0,0,8,0,8,8,0,8,5,0,8,0,8,8,0,0,8,8,0,8,0,6,8
   };

   // Key schedule constants.

   private static final byte[] ROTARS = {
      1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28
   };

   private static final byte[] PC1 = {
      56, 48, 40, 32, 24, 16,  8,  0, 57, 49, 41, 33, 25, 17,
       9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 59, 51, 43, 35,
      62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37, 29, 21,
      13,  5, 60, 52, 44, 36, 28, 20, 12,  4, 27, 19, 11,  3
   };

   private static final byte[] PC2 = {
      13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
      22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
      40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
      43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
   };

   /**
    * Weak keys (parity adjusted): If all the bits in each half are either 0
    * or 1, then the key used for any cycle of the algorithm is the same as
    * all other cycles. 
    */
   public static final byte[][] WEAK_KEYS = {
      Util.toBytesFromString("0101010101010101"),
      Util.toBytesFromString("01010101FEFEFEFE"),
      Util.toBytesFromString("FEFEFEFE01010101"),
      Util.toBytesFromString("FEFEFEFEFEFEFEFE")
   };

   /**
    * Semi-weak keys (parity adjusted):  Some pairs of keys encrypt plain text
    * to identical cipher text. In other words, one key in the pair can decrypt
    * messages that were encrypted with the other key. These keys are called
    * semi-weak keys. This occurs because instead of 16 different sub-keys being
    * generated, these semi-weak keys produce only two different sub-keys.
    */
   public static final byte[][] SEMIWEAK_KEYS = {
      Util.toBytesFromString("01FE01FE01FE01FE"), Util.toBytesFromString("FE01FE01FE01FE01"),
      Util.toBytesFromString("1FE01FE00EF10EF1"), Util.toBytesFromString("E01FE01FF10EF10E"),
      Util.toBytesFromString("01E001E001F101F1"), Util.toBytesFromString("E001E001F101F101"),
      Util.toBytesFromString("1FFE1FFE0EFE0EFE"), Util.toBytesFromString("FE1FFE1FFE0EFE0E"),
      Util.toBytesFromString("011F011F010E010E"), Util.toBytesFromString("1F011F010E010E01"),
      Util.toBytesFromString("E0FEE0FEF1FEF1FE"), Util.toBytesFromString("FEE0FEE0FEF1FEF1")
   };

   /** Possible weak keys (parity adjusted) --produce 4 instead of 16 subkeys. */
   public static final byte[][] POSSIBLE_WEAK_KEYS = {
      Util.toBytesFromString("1F1F01010E0E0101"),
      Util.toBytesFromString("011F1F01010E0E01"),
      Util.toBytesFromString("1F01011F0E01010E"),
      Util.toBytesFromString("01011F1F01010E0E"),
      Util.toBytesFromString("E0E00101F1F10101"),
      Util.toBytesFromString("FEFE0101FEFE0101"),
      Util.toBytesFromString("FEE01F01FEF10E01"),
      Util.toBytesFromString("E0FE1F01F1FE0E01"),
      Util.toBytesFromString("FEE0011FFEF1010E"),
      Util.toBytesFromString("E0FE011FF1FE010E"),
      Util.toBytesFromString("E0E01F1FF1F10E0E"),
      Util.toBytesFromString("FEFE1F1FFEFE0E0E"),
      Util.toBytesFromString("1F1F01010E0E0101"),
      Util.toBytesFromString("011F1F01010E0E01"),
      Util.toBytesFromString("1F01011F0E01010E"),
      Util.toBytesFromString("01011F1F01010E0E"),
      Util.toBytesFromString("01E0E00101F1F101"),
      Util.toBytesFromString("1FFEE0010EFEF001"),
      Util.toBytesFromString("1FE0FE010EF1FE01"),
      Util.toBytesFromString("01FEFE0101FEFE01"),
      Util.toBytesFromString("1FE0E01F0EF1F10E"),
      Util.toBytesFromString("01FEE01F01FEF10E"),
      Util.toBytesFromString("01E0FE1F01F1FE0E"),
      Util.toBytesFromString("1FFEFE1F0EFEFE0E"),

      Util.toBytesFromString("E00101E0F10101F1"),
      Util.toBytesFromString("FE1F01E0FE0E0EF1"),
      Util.toBytesFromString("FE011FE0FE010EF1"),
      Util.toBytesFromString("E01F1FE0F10E0EF1"),
      Util.toBytesFromString("FE0101FEFE0101FE"),
      Util.toBytesFromString("E01F01FEF10E01FE"),
      Util.toBytesFromString("E0011FFEF1010EFE"),
      Util.toBytesFromString("FE1F1FFEFE0E0EFE"),
      Util.toBytesFromString("1FFE01E00EFE01F1"),
      Util.toBytesFromString("01FE1FE001FE0EF1"),
      Util.toBytesFromString("1FE001FE0EF101FE"),
      Util.toBytesFromString("01E01FFE01F10EFE"),
      Util.toBytesFromString("0101E0E00101F1F1"),
      Util.toBytesFromString("1F1FE0E00E0EF1F1"),
      Util.toBytesFromString("1F01FEE00E01FEF1"),
      Util.toBytesFromString("011FFEE0010EFEF1"),
      Util.toBytesFromString("1F01E0FE0E01F1FE"),
      Util.toBytesFromString("011FE0FE010EF1FE"),
      Util.toBytesFromString("0101FEFE0001FEFE"),
      Util.toBytesFromString("1F1FFEFE0E0EFEFE"),
      Util.toBytesFromString("FEFEE0E0FEFEF1F1"),
      Util.toBytesFromString("E0FEFEE0F1FEFEF1"),
      Util.toBytesFromString("FEE0E0FEFEF1F1FE"),
      Util.toBytesFromString("E0E0FEFEF1F1FEFE")
   };

   // Constructor(s)
   // -------------------------------------------------------------------------

   /** Default 0-argument constructor. */
   public DES() {
      super(Registry.DES_CIPHER, BLOCK_SIZE, KEY_SIZE);
   }

   // Class methods
   // -------------------------------------------------------------------------

   /**
    * <p>Adjust the parity for a raw key array. This essentially means that each
    * byte in the array will have an odd number of '1' bits (the last bit in
    * each byte is unused.</p>
    *
    * @param kb The key array, to be parity-adjusted.
    * @param offset The starting index into the key bytes.
    */
   public static void adjustParity(byte[] kb, int offset) {
      for (int i = offset; i < KEY_SIZE; i++) {
         kb[i] ^= (PARITY[kb[i] & 0xff] == 8) ? 1 : 0;
      }
   }

   /**
    * <p>Test if a byte array, which must be at least 8 bytes long, is parity
    * adjusted.</p>
    *
    * @param kb The key bytes.
    * @param offset The starting index into the key bytes.
    * @return <code>true</code> if the first 8 bytes of <i>kb</i> have been
    * parity adjusted. <code>false</code> otherwise.
    */
   public static boolean isParityAdjusted(byte[] kb, int offset) {
      int w = 0x88888888;
      int n = PARITY[kb[offset+0] & 0xff]; n <<= 4;
      n |= PARITY[kb[offset+1] & 0xff]; n <<= 4;
      n |= PARITY[kb[offset+2] & 0xff]; n <<= 4;
      n |= PARITY[kb[offset+3] & 0xff]; n <<= 4;
      n |= PARITY[kb[offset+4] & 0xff]; n <<= 4;
      n |= PARITY[kb[offset+5] & 0xff]; n <<= 4;
      n |= PARITY[kb[offset+6] & 0xff]; n <<= 4;
      n |= PARITY[kb[offset+7] & 0xff];
      return (n & w) == 0;
   }

   /**
    * <p>Test if a key is a weak key.</p>
    *
    * @param kb The key to test.
    * @return <code>true</code> if the key is weak.
    */
   public static boolean isWeak(byte[] kb) {
//      return Arrays.equals(kb, WEAK_KEYS[0]) || Arrays.equals(kb, WEAK_KEYS[1])
//          || Arrays.equals(kb, WEAK_KEYS[2]) || Arrays.equals(kb, WEAK_KEYS[3])
//          || Arrays.equals(kb, WEAK_KEYS[4]) || Arrays.equals(kb, WEAK_KEYS[5])
//          || Arrays.equals(kb, WEAK_KEYS[6]) || Arrays.equals(kb, WEAK_KEYS[7]);
      for (int i = 0; i < WEAK_KEYS.length; i++) {
         if (Arrays.equals(WEAK_KEYS[i], kb)) {
            return true;
         }
      }
      return false;
   }

   /**
    * <p>Test if a key is a semi-weak key.</p>
    *
    * @param kb The key to test.
    * @return <code>true</code> if this key is semi-weak.
    */
   public static boolean isSemiWeak(byte[] kb) {
//      return Arrays.equals(kb, SEMIWEAK_KEYS[0])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[1])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[2])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[3])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[4])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[5])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[6])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[7])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[8])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[9])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[10])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[11]);
      for (int i = 0; i < SEMIWEAK_KEYS.length; i++) {
         if (Arrays.equals(SEMIWEAK_KEYS[i], kb)) {
            return true;
         }
      }
      return false;
   }

   /**
    * <p>Test if the designated byte array represents a possibly weak key.</p>
    *
    * @param kb the byte array to test.
    * @return <code>true</code> if <code>kb</code>represents a possibly weak key.
    * Returns <code>false</code> otherwise.
    */
   public static boolean isPossibleWeak(byte[] kb) {
      for (int i = 0; i < POSSIBLE_WEAK_KEYS.length; i++) {
         if (Arrays.equals(POSSIBLE_WEAK_KEYS[i], kb)) {
            return true;
         }
      }
      return false;
   }

   /**
    * <p>The core DES function. This is used for both encryption and decryption,
    * the only difference being the key.</p>
    *
    * @param in The input bytes.
    * @param i The starting offset into the input bytes.
    * @param out The output bytes.
    * @param o The starting offset into the output bytes.
    * @param key The working key.
    */
   private static void desFunc(byte[] in, int i, byte[] out, int o, int[] key) {
      int right, left, work;

      // Load.
      left  = (in[i++] & 0xff) << 24 | (in[i++] & 0xff) << 16
            | (in[i++] & 0xff) <<  8 |  in[i++] & 0xff;
      right = (in[i++] & 0xff) << 24 | (in[i++] & 0xff) << 16
            | (in[i++] & 0xff) <<  8 |  in[i  ] & 0xff;

      // Initial permutation.
      work  = ((left >>>  4) ^ right) & 0x0F0F0F0F;
      left  ^= work << 4;
      right ^= work;

      work  = ((left >>> 16) ^ right) & 0x0000FFFF;
      left  ^= work << 16;
      right ^= work;

      work  = ((right >>>  2) ^ left) & 0x33333333;
      right ^= work << 2;
      left  ^= work;

      work  = ((right >>>  8) ^ left) & 0x00FF00FF;
      right ^= work << 8;
      left  ^= work;

      right = ((right << 1) | ((right >>> 31) & 1)) & 0xFFFFFFFF;
      work = (left ^ right) & 0xAAAAAAAA;
      left  ^= work;
      right ^= work;
      left = ((left << 1) | ((left >>> 31) & 1)) & 0xFFFFFFFF;

      int k = 0, t;
      for (int round = 0; round < 8; round++) {
         work = right >>> 4 | right << 28;
         work ^= key[k++];
         t  = SP7[work & 0x3F]; work >>>= 8;
         t |= SP5[work & 0x3F]; work >>>= 8;
         t |= SP3[work & 0x3F]; work >>>= 8;
         t |= SP1[work & 0x3F];
         work = right ^ key[k++];
         t |= SP8[work & 0x3F]; work >>>= 8;
         t |= SP6[work & 0x3F]; work >>>= 8;
         t |= SP4[work & 0x3F]; work >>>= 8;
         t |= SP2[work & 0x3F];
         left ^= t;

         work = left >>> 4 | left << 28;
         work ^= key[k++];
         t  = SP7[work & 0x3F]; work >>>= 8;
         t |= SP5[work & 0x3F]; work >>>= 8;
         t |= SP3[work & 0x3F]; work >>>= 8;
         t |= SP1[work & 0x3F];
         work = left ^ key[k++];
         t |= SP8[work & 0x3F]; work >>>= 8;
         t |= SP6[work & 0x3F]; work >>>= 8;
         t |= SP4[work & 0x3F]; work >>>= 8;
         t |= SP2[work & 0x3F];
         right ^= t;
      }

      // The final permutation.
      right = (right << 31) | (right >>> 1);
      work = (left ^ right) & 0xAAAAAAAA;
      left  ^= work;
      right ^= work;
      left = (left << 31) | (left >>> 1);

      work = ((left >>> 8) ^ right) & 0x00FF00FF;
      left ^= work << 8;
      right ^= work;

      work = ((left >>> 2) ^ right) & 0x33333333;
      left  ^= work << 2;
      right ^= work;

      work = ((right >>> 16) ^ left) & 0x0000FFFF;
      right ^= work << 16;
      left  ^= work;

      work = ((right >>> 4) ^ left) & 0x0F0F0F0F;
      right ^= work << 4;
      left  ^= work;

      out[o++] = (byte)(right >>> 24);
      out[o++] = (byte)(right >>> 16);
      out[o++] = (byte)(right >>>  8);
      out[o++] = (byte) right;
      out[o++] = (byte)(left >>> 24);
      out[o++] = (byte)(left >>> 16);
      out[o++] = (byte)(left >>>  8);
      out[o  ] = (byte) left;
   }

   // Instance methods implementing BaseCipher
   // -------------------------------------------------------------------------

   public Object clone() {
      return new DES();
   }

   public Iterator blockSizes() {
      return Collections.singleton(new Integer(BLOCK_SIZE)).iterator();
   }

   public Iterator keySizes() {
      return Collections.singleton(new Integer(KEY_SIZE)).iterator();
   }

   public Object makeKey(byte[] kb, int bs) throws InvalidKeyException {
      if (kb == null || kb.length != KEY_SIZE)
         throw new InvalidKeyException("DES keys must be 8 bytes long");

      if (Properties.checkForWeakKeys()
            && (isWeak(kb) || isSemiWeak(kb) || isPossibleWeak(kb))) {
         throw new WeakKeyException();
      }

      int i, j, l, m, n;
      long pc1m = 0, pcr = 0;

      for (i = 0; i < 56; i++) {
         l = PC1[i];
         pc1m |= ((kb[l >>> 3] & (0x80 >>> (l & 7))) != 0)
               ? (1L << (55 - i)) : 0;
      }

      Context ctx = new Context();

      // Encryption key first.
      for (i = 0; i < 16; i++) {
         pcr = 0;
         m = i << 1;
         n = m + 1;
         for (j = 0; j < 28; j++) {
            l = j + ROTARS[i];
            if (l < 28) pcr |= ((pc1m & 1L << (55 - l)) != 0)
                             ? (1L << (55 - j)) : 0;
            else pcr |= ((pc1m & 1L << (55 - (l - 28))) != 0)
                      ? (1L << (55 - j)) : 0;
         }
         for (j = 28; j < 56; j++) {
            l = j + ROTARS[i];
            if (l < 56) pcr |= ((pc1m & 1L << (55 - l)) != 0)
                             ? (1L << (55 - j)) : 0;
            else pcr |= ((pc1m & 1L << (55 - (l - 28))) != 0)
                      ? (1L << (55 - j)) : 0;
         }
         for (j = 0; j < 24; j++) {
            if ((pcr & 1L << (55 - PC2[j   ])) != 0) ctx.ek[m] |= 1 << (23 - j);
            if ((pcr & 1L << (55 - PC2[j+24])) != 0) ctx.ek[n] |= 1 << (23 - j);
         }
      }

      // The decryption key is the same, but in reversed order.
      for (i = 0; i < Context.EXPANDED_KEY_SIZE; i += 2) {
         ctx.dk[30 - i] = ctx.ek[i];
         ctx.dk[31 - i] = ctx.ek[i+1];
      }

      // "Cook" the keys.
      for (i = 0; i < 32; i += 2) {
         int x, y;

         x = ctx.ek[i  ];
         y = ctx.ek[i+1];

         ctx.ek[i  ] = ((x & 0x00FC0000)  <<  6) | ((x & 0x00000FC0)  << 10)
                     | ((y & 0x00FC0000) >>> 10) | ((y & 0x00000FC0) >>>  6);
         ctx.ek[i+1] = ((x & 0x0003F000)  << 12) | ((x & 0x0000003F)  << 16)
                     | ((y & 0x0003F000) >>>  4) |  (y & 0x0000003F);

         x = ctx.dk[i  ];
         y = ctx.dk[i+1];

         ctx.dk[i  ] = ((x & 0x00FC0000)  <<  6) | ((x & 0x00000FC0)  << 10)
                     | ((y & 0x00FC0000) >>> 10) | ((y & 0x00000FC0) >>>  6);
         ctx.dk[i+1] = ((x & 0x0003F000)  << 12) | ((x & 0x0000003F)  << 16)
                     | ((y & 0x0003F000) >>>  4) |  (y & 0x0000003F);
      }

      return ctx;
   }

   public void encrypt(byte[] in, int i, byte[] out, int o, Object K, int bs) {
      desFunc(in, i, out, o, ((Context) K).ek);
   }

   public void decrypt(byte[] in, int i, byte[] out, int o, Object K, int bs) {
      desFunc(in, i, out, o, ((Context) K).dk);
   }

   // Inner classe(s)
   // =========================================================================

   /**
    * Simple wrapper class around the session keys. Package-private so TripleDES
    * can see it.
    */
   final class Context {

      // Constants and variables
      // ----------------------------------------------------------------------

      private static final int EXPANDED_KEY_SIZE = 32;

      /** The encryption key. */
      int[] ek;

      /** The decryption key. */
      int[] dk;

      // Constructor(s)
      // ----------------------------------------------------------------------

      /** Default 0-arguments constructor. */
      Context() {
         ek = new int[EXPANDED_KEY_SIZE];
         dk = new int[EXPANDED_KEY_SIZE];
      }

      // Class methods
      // ----------------------------------------------------------------------

      // Instance methods
      // ----------------------------------------------------------------------

      byte[] getEncryptionKeyBytes() {
         return toByteArray(ek);
      }

      byte[] getDecryptionKeyBytes() {
         return toByteArray(dk);
      }

      byte[] toByteArray(int[] k) {
         byte[] result = new byte[4 * k.length];
         for (int i = 0, j = 0; i < k.length; i++) {
            result[j++] = (byte)(k[i] >>> 24);
            result[j++] = (byte)(k[i] >>> 16);
            result[j++] = (byte)(k[i] >>>  8);
            result[j++] = (byte) k[i];
         }
         return result;
      }
   }
}
