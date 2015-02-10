// Implementation of Wu Manber's Multi-Pattern Search Algorithm
// Implemented by Ray Burkholder, ray@oneunified.net
// Copyright (2008) One Unified
// For use without restriction but one:  this copyright notice must be preserved.

//#include "stdafx.h"
#include <stdio.h>

#include "WuManber.h"


#include <math.h>
#include <assert.h>

#include <exception>
#include <iostream>
#include <string>
using namespace std;

// use http://www.asciitable.com/ for determining additional character types
char WuManber::rchSpecialCharacters[] = { 0x21, 0x22, 0x23, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
    0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x5b, 0x5c, 0x5d,
    0x5e, 0x5f, 0x60, 0x7b, 0x7c, 0x7d, 0x7e,
    0x00 };

unsigned char WuManber::rchExtendedAscii[] = { 
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,       0x99, 0x9a,       0x9c, 0x0d,       0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
    0x00 };

WuManber::WuManber( void ): 
  k( 0 ), m( 0 ), m_bInitialized( false ) {
}

WuManber::~WuManber( void ) {
}

void WuManber::Initialize( const vector<const char *> &patterns, 
                          bool bCaseSensitive, bool bIncludeSpecialCharacters, bool bIncludeExtendedAscii ) {
// bIncludeExtendedAscii, bIncludeSpecialCharacters matched as whitespace when false

  k = patterns.size();
  m = 0; // start with 0 and grow from there
  for ( unsigned int i = 0; i < k; ++i ) {
    size_t lenPattern = strlen( patterns[ i ] );
    if ( B > lenPattern ) throw runtime_error( "found pattern less than B in length" );
    m = ( 0 == m ) ? lenPattern : min( m, lenPattern );
  }

  m_nSizeOfAlphabet = 1; // at minimum we have a white space character
  for ( unsigned short i = 0; i <= 255; ++i ) {
    m_lu[i].letter = ' '; // table is defaulted to whitespace
    m_lu[i].offset = 0;  // 
    if ( ( i >= 'a' ) && ( i <= 'z' ) ) {
      m_lu[i].letter = (char) i; // no problems with lower case letters
      m_lu[i].offset = m_nSizeOfAlphabet++;
    }  
    if ( bCaseSensitive ) { // case of !bCaseSensitive fixed up later on
      if ( ( i >= 'A' ) && ( i <= 'Z' ) ) {  
        m_lu[i].letter = (char) i; // map upper case to lower case
        m_lu[i].offset = m_nSizeOfAlphabet++;
      }
    }
    if ( ( i >= '0' ) && ( i <= '9' ) ) {
      m_lu[i].letter = (char) i; // use digits
      m_lu[i].offset = m_nSizeOfAlphabet++;
    }
  }
  if ( !bCaseSensitive ) {  // fix up upper case mappings ( uppercase comes before lower case in ascii table )
    for ( unsigned short i = 'A'; i <= 'Z'; ++i ) {
      char letter = i - 'A' + 'a';  // map upper case to lower case
      m_lu[i].letter = letter; // map upper case to lower case
      m_lu[i].offset = m_lu[letter].offset;  
      // no unique characters so don't increment size
    }
  }
  if ( bIncludeSpecialCharacters ) {
    for ( char *c = rchSpecialCharacters; 0 != *c; ++c ) {
      m_lu[*c].letter = *c;
      m_lu[*c].offset = m_nSizeOfAlphabet++;
    }
  }
  if ( bIncludeExtendedAscii ) {
    for ( unsigned char *c = rchExtendedAscii; 0 != *c; ++c ) {
      m_lu[*c].letter = static_cast<char>( *c );
      m_lu[*c].offset = m_nSizeOfAlphabet++;
    }
  }

  m_nBitsInShift = (unsigned short) ceil( log( (double) m_nSizeOfAlphabet ) / log( (double) 2 ) );
  // can use fewer bits in shift to turn it into a hash

  m_nTableSize = (size_t) pow( pow( (double) 2, m_nBitsInShift ), (int) B );  
    // 2 ** bits ** B, will be some unused space when not hashed
  m_ShiftTable = new unsigned int[ m_nTableSize ]; 

  for ( size_t i = 0; i < m_nTableSize; ++i ) {
    m_ShiftTable[ i ] = m - B + 1; // default to m-B+1 for shift
  }

  m_vPatternMap = new vector<structPatternMap>[ m_nTableSize ];
  
  for ( size_t j = 0; j < k; ++j ) {  // loop through patterns
    for ( size_t q = m; q >= B; --q ) {
      unsigned int hash;
      hash  = m_lu[patterns[j][q - 2 - 1]].offset; // bring in offsets of X in pattern j
      hash <<= m_nBitsInShift;
      hash += m_lu[patterns[j][q - 1 - 1]].offset;
      hash <<= m_nBitsInShift;
      hash += m_lu[patterns[j][q     - 1]].offset;
      size_t shiftlen = m - q;
      m_ShiftTable[ hash ] = min( m_ShiftTable[ hash ], shiftlen );
      if ( 0 == shiftlen ) {
        m_PatternMapElement.ix = j;
        m_PatternMapElement.PrefixHash = m_lu[patterns[j][0]].offset;
        m_PatternMapElement.PrefixHash <<= m_nBitsInShift;
        m_PatternMapElement.PrefixHash += m_lu[patterns[j][1]].offset;
        m_vPatternMap[ hash ].push_back( m_PatternMapElement );
      }
    }
  }
  m_bInitialized = true;
}

void WuManber::Search( size_t TextLength, const char *Text, const vector<const char *> &patterns ) {

  assert( k == patterns.size() );
  assert( m < TextLength );
  assert( m_bInitialized );
  size_t ix = m - 1; // start off by matching end of largest common pattern
  while ( ix < TextLength ) {
    unsigned int hash1;
    hash1 = m_lu[Text[ix-2]].offset;
    hash1 <<= m_nBitsInShift;
    hash1 += m_lu[Text[ix-1]].offset;
    hash1 <<= m_nBitsInShift;
    hash1 += m_lu[Text[ix]].offset;
    size_t shift = m_ShiftTable[ hash1 ];
    if ( shift > 0 ) {
      ix += shift;
    }
    else {  // we have a potential match when shift is 0
      unsigned int hash2;  // check for matching prefixes
      hash2 = m_lu[Text[ix-m+1]].offset;
      hash2 <<= m_nBitsInShift;
      hash2 += m_lu[Text[ix-m+2]].offset;
      vector<structPatternMap> &element = m_vPatternMap[ hash1 ];
      vector<structPatternMap>::iterator iter = element.begin();
      while ( element.end() != iter ) {
        if ( hash2 == (*iter).PrefixHash ) {  
          // since prefix matches, compare target substring with pattern
          const char *ixTarget = Text + ix - m + 3; // we know first two characters already match
          const char *ixPattern = patterns[ (*iter).ix ] + 2;  // ditto
          while ( ( 0 != *ixTarget ) && ( 0 != *ixPattern ) ) { // match until we reach end of either string
            if ( m_lu[ *ixTarget ].letter == m_lu[ *ixPattern ].letter ) {  // match against chosen case sensitivity
              ++ixTarget;
              ++ixPattern;
            }
            else {
              break;
            }
          }
          if ( 0 == *ixPattern ) {  // we found the end of the pattern, so match found
            cout << "match found: " << patterns[ (*iter).ix ] << endl;
          }
        }
        ++iter;
      }
      ++ix;
    }
  }
}



