package org.t0t0.androguard.android;                                                                                                                                                                                              
// ----------------------------------------------------------------------------
// $Id: IBlockCipherSpi.java,v 1.4 2002/11/07 17:17:45 raif Exp $
//
// Copyright (C) 2001, 2002, Free Software Foundation, Inc.
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

import java.security.InvalidKeyException;
import java.util.Iterator;

/**
 * <p>Package-private interface exposing mandatory methods to be implemented by
 * concrete {@link gnu.crypto.cipher.BaseCipher} sub-classes.</p>
 *
 * @version $Revision: 1.4 $
 */
interface IBlockCipherSpi extends Cloneable {

   // Constants
   // -------------------------------------------------------------------------

   // Methods
   // -------------------------------------------------------------------------

   /**
    * <p>Returns an {@link java.util.Iterator} over the supported block sizes.
    * Each element returned by this object is a {@link java.lang.Integer}.</p>
    *
    * @return an <code>Iterator</code> over the supported block sizes.
    */
   Iterator blockSizes();

   /**
    * <p>Returns an {@link java.util.Iterator} over the supported key sizes.
    * Each element returned by this object is a {@link java.lang.Integer}.</p>
    *
    * @return an <code>Iterator</code> over the supported key sizes.
    */
   Iterator keySizes();

   /**
    * <p>Expands a user-supplied key material into a session key for a
    * designated <i>block size</i>.</p>
    *
    * @param k the user-supplied key material.
    * @param bs the desired block size in bytes.
    * @return an Object encapsulating the session key.
    * @exception IllegalArgumentException if the block size is invalid.
    * @exception InvalidKeyException if the key data is invalid.
    */
   Object makeKey(byte[]k, int bs) throws InvalidKeyException;

   /**
    * <p>Encrypts exactly one block of plaintext.</p>
    *
    * @param in the plaintext.
    * @param inOffset index of <code>in</code> from which to start considering
    * data.
    * @param out the ciphertext.
    * @param outOffset index of <code>out</code> from which to store the result.
    * @param k the session key to use.
    * @param bs the block size to use.
    * @exception IllegalArgumentException if the block size is invalid.
    * @exception ArrayIndexOutOfBoundsException if there is not enough room in
    * either the plaintext or ciphertext buffers.
    */
   void
   encrypt(byte[] in, int inOffset, byte[] out, int outOffset, Object k, int bs);

   /**
    * <p>Decrypts exactly one block of ciphertext.</p>
    *
    * @param in the ciphertext.
    * @param inOffset index of <code>in</code> from which to start considering
    * data.
    * @param out the plaintext.
    * @param outOffset index of <code>out</code> from which to store the result.
    * @param k the session key to use.
    * @param bs the block size to use.
    * @exception IllegalArgumentException if the block size is invalid.
    * @exception ArrayIndexOutOfBoundsException if there is not enough room in
    * either the plaintext or ciphertext buffers.
    */
   void
   decrypt(byte[] in, int inOffset, byte[] out, int outOffset, Object k, int bs);

   /**
    * <p>A <i>correctness</i> test that consists of basic symmetric encryption /
    * decryption test(s) for all supported block and key sizes, as well as one
    * (1) variable key Known Answer Test (KAT).</p>
    *
    * @return <code>true</code> if the implementation passes simple
    * <i>correctness</i> tests. Returns <code>false</code> otherwise.
    */
   boolean selfTest();
}
