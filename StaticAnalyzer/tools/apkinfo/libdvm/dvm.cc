/* 
   This file is part of Androguard.

   Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
   All rights reserved.

   Androguard is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   Androguard is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of  
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with Androguard.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dvm.h"

unsigned int B_A_OP_CCCC(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned short i16;
    unsigned short *si16;

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    //memcpy( &i16, b->read( 2 ), 2 );
    v->push_back( (unsigned int)(i16 & 0xff) );
    v->push_back( (unsigned int)((i16 >> 8) & 0xf) );
    v->push_back( (unsigned int)((i16 >> 12) & 0xf) );

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    //memcpy( &i16, b->read( 2 ), 2 );
    v->push_back( (unsigned int)i16 );

    return 4;
}

unsigned int B_A_OP_CCCC_3_FIELD(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned int size = B_A_OP_CCCC( b, v, vdesc );

    vdesc->push_back( OPVALUE );
    for(int i=1; i < v->size(); i++)
        vdesc->push_back( REGISTER );

    (*vdesc)[3] = FIELD;

    return size;
}

unsigned int B_A_OP_CCCC_3_TYPE(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned int size = B_A_OP_CCCC( b, v, vdesc );

    vdesc->push_back( OPVALUE );
    for(int i=1; i < v->size(); i++)
        vdesc->push_back( REGISTER );

    (*vdesc)[3] = TYPE;

    return size;
}

unsigned int B_A_OP_CCCC_G_F_E_D(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned short i16;

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    //memcpy( &i16, b->read( 2 ), 2 );
    v->push_back( (unsigned int)(i16 & 0xff) );
    v->push_back( (unsigned int)((i16 >> 8) & 0xf) );
    v->push_back( (unsigned int)((i16 >> 12) & 0xf) );

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    //memcpy( &i16, b->read( 2 ), 2 );
    v->push_back( (unsigned int)i16 );

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    //memcpy( &i16, b->read( 2 ), 2 );
    v->push_back( (unsigned int)(i16 & 0xf) );

    v->push_back( (unsigned int)((i16 >> 4) & 0xf) );
    v->push_back( (unsigned int)((i16 >> 8) & 0xf) );
    v->push_back( (unsigned int)((i16 >> 12) & 0xf) );

    return 6;
}

unsigned int OP_00(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned char i8;

    i8 = *( reinterpret_cast<unsigned char *>( const_cast<char *>(b->read(1))) );
    v->push_back( (unsigned int)(i8) );

    b->read(1);

    vdesc->push_back( OPVALUE );

    return 2;
}

unsigned int AA_OP_SBBBB(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned short i16;

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16 & 0xff) );
    v->push_back( (unsigned int)((i16 >> 8) & 0xff) );

    signed short si16;
    si16 = *( reinterpret_cast<signed short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (signed int)(si16) );

    vdesc->push_back( OPVALUE );
    vdesc->push_back( REGISTER );
    vdesc->push_back( INTEGER );

    return 4;
}

unsigned int AA_OP_SBBBB_BRANCH(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned int size = AA_OP_SBBBB(b, v, vdesc);

    (*vdesc)[2] = INTEGER_BRANCH;

    return size;
}

unsigned int SB_A_OP(Buff *b, vector<int> *v, vector<int> *vdesc) {
    signed short si16;

    si16 = *( reinterpret_cast<signed short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(si16 & 0xff) );
    v->push_back( (unsigned int)((si16 >> 8) & 0xf) );
    v->push_back( (signed int)((si16 >> 12) & 0xf) );

    vdesc->push_back( OPVALUE );
    vdesc->push_back( REGISTER );
    vdesc->push_back( INTEGER );

    return 2;
}

unsigned int AA_OP(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned short i16;

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16 & 0xff) );
    v->push_back( (unsigned int)((i16 >> 8) & 0xff) );

    vdesc->push_back( OPVALUE );
    vdesc->push_back( REGISTER );

    return 2;
}

unsigned int AA_OP_BBBB(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned short i16;

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16 & 0xff) );
    v->push_back( (unsigned int)((i16 >> 8) & 0xff) );

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16) );

    vdesc->push_back( OPVALUE );
    for(int i=1; i < v->size(); i++)
        vdesc->push_back( REGISTER );

    return 4;
}

unsigned int DAA_OP_DBBBB(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned short i16;

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16 & 0xff) );
    v->push_back( (unsigned int)((i16 >> 8) & 0xff) );

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16) );

    vdesc->push_back( OPVALUE );
    for(int i=1; i < v->size(); i++)
        vdesc->push_back( INTEGER );

    return 4;
}


unsigned int AA_OP_BBBB_2_FIELD(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned int size = AA_OP_BBBB( b, v, vdesc );

    (*vdesc)[2] = FIELD;

    return size;
}

unsigned int AA_OP_BBBB_2_TYPE(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned int size = AA_OP_BBBB( b, v, vdesc );

    (*vdesc)[2] = TYPE;

    return size;
}

unsigned int AA_OP_BBBB_2_STRING(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned int size = AA_OP_BBBB( b, v, vdesc );

    (*vdesc)[2] = STRING;

    return size;
}

unsigned int AA_OP_BBBBBBBB(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned short i16;
    unsigned int i32;

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16 & 0xff) );
    v->push_back( (unsigned int)((i16 >> 8) & 0xff) );

    i32 = *( reinterpret_cast<unsigned int *>( const_cast<char *>(b->read(4))) );
    v->push_back( (unsigned int)(i32) );

    vdesc->push_back( OPVALUE );
    for(int i=1; i < v->size(); i++)
        vdesc->push_back( REGISTER );

    return 6;
}

unsigned int AA_OP_BBBBBBBB_2_STRING(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned int size = AA_OP_BBBBBBBB(b, v, vdesc);

    (*vdesc)[2] = STRING;

    return size;
}

unsigned int OP_SAA(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned char i8;
    signed char si8;

    i8 = *( reinterpret_cast<unsigned char *>( const_cast<char *>(b->read(1))) );
    v->push_back( (unsigned int)(i8) );

    si8 = *( reinterpret_cast<signed char *>( const_cast<char *>(b->read(1))) );
    v->push_back( (signed int)(si8) );

    vdesc->push_back( OPVALUE );
    vdesc->push_back( INTEGER );

    return 2;
}

unsigned int OP_SAA_BRANCH(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned int size = OP_SAA(b, v, vdesc);

    (*vdesc)[ 1 ] = INTEGER_BRANCH;

    return size;
}

unsigned int B_A_OP(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned short i16;

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16 & 0xff) );
    v->push_back( (unsigned int)((i16 >> 8) & 0xf) );
    v->push_back( (unsigned int)((i16 >> 12) & 0xf) );

    vdesc->push_back( OPVALUE );
    vdesc->push_back( REGISTER );
    vdesc->push_back( REGISTER );

    return 2;
}

unsigned int _00_OP_SAAAA(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned short i16;
    signed short si16;

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16 & 0xff) );

    si16 = *( reinterpret_cast<signed short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (signed int)(si16) );

    vdesc->push_back( OPVALUE );
    vdesc->push_back( INTEGER );

    return 4;
}

unsigned int _00_OP_SAAAA_BRANCH(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned int size = _00_OP_SAAAA(b, v, vdesc);

    (*vdesc)[ 1 ] = INTEGER_BRANCH;

    return size;
}

unsigned int _00_OP_SAAAAAAAA(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned short i16;
    signed int si32;

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16 & 0xff) );

    si32 = *( reinterpret_cast<signed int *>( const_cast<char *>(b->read(4))) );
    v->push_back( (signed int)(si32) );

    vdesc->push_back( OPVALUE );
    vdesc->push_back( INTEGER );

    return 6;
}

unsigned int _00_OP_SAAAAAAAA_BRANCH(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned int size = _00_OP_SAAAAAAAA(b, v, vdesc);

    (*vdesc)[ 1 ] = INTEGER_BRANCH;

    return size;
}

unsigned int B_A_OP_SCCCC(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned short i16;
    signed short si16;

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16 & 0xff) );
    v->push_back( (unsigned int)((i16 >> 8) & 0xf) );
    v->push_back( (unsigned int)((i16 >> 12) & 0xf) );


    si16 = *( reinterpret_cast<signed short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (signed int)si16 );

    vdesc->push_back( OPVALUE );
    vdesc->push_back( REGISTER );
    vdesc->push_back( REGISTER );
    vdesc->push_back( INTEGER );

    return 4;
}

unsigned int B_A_OP_SCCCC_BRANCH(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned int size = B_A_OP_SCCCC(b, v, vdesc);

    (*vdesc)[3] = INTEGER_BRANCH;

    return size;
}

unsigned int AA_OP_CC_BB(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned short i16;

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16 & 0xff) );
    v->push_back( (unsigned int)((i16 >> 8) & 0xff) );

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16 & 0xff) );
    v->push_back( (unsigned int)((i16 >> 8) & 0xff) );

    vdesc->push_back( OPVALUE );
    vdesc->push_back( REGISTER );
    vdesc->push_back( REGISTER );
    vdesc->push_back( REGISTER );

    return 4;
}

unsigned int AA_OP_BB_SCC(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned short i16;
    unsigned char i8;
    char si8;

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16 & 0xff) );
    v->push_back( (unsigned int)((i16 >> 8) & 0xff) );

    i8 = *( reinterpret_cast<unsigned char *>( const_cast<char *>(b->read(1))) );
    v->push_back( (unsigned int)(i8) );

    si8 = *( reinterpret_cast<signed char *>( const_cast<char *>(b->read(1))) );
    v->push_back( (signed int)(si8) );

    vdesc->push_back( OPVALUE );
    vdesc->push_back( REGISTER );
    vdesc->push_back( REGISTER );
    vdesc->push_back( INTEGER );

    return 4;
}

unsigned int AA_OP_SBBBBBBBB(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned short i16;
    signed int si32;

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16 & 0xff) );
    v->push_back( (unsigned int)((i16 >> 8) & 0xff) );

    si32 = *( reinterpret_cast<signed int *>( const_cast<char *>(b->read(4))) );
    v->push_back( (signed int)(si32) );

    vdesc->push_back( OPVALUE );
    vdesc->push_back( REGISTER );
    vdesc->push_back( INTEGER );

    return 6;
}

unsigned int AA_OP_BBBB_CCCC(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned short i16;

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16 & 0xff) );
    v->push_back( (unsigned int)((i16 >> 8) & 0xff) );

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16) );

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16) );

    return 6;
}

unsigned int AA_OP_SBBBB_SBBBB(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned short i16;
    signed short si16;

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16 & 0xff) );
    v->push_back( (unsigned int)((i16 >> 8) & 0xff) );

    si16 = *( reinterpret_cast<signed short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (signed int)(si16) );

    si16 = *( reinterpret_cast<signed short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (signed int)(si16) );

    vdesc->push_back( OPVALUE );
    vdesc->push_back( REGISTER );
    vdesc->push_back( INTEGER );
    vdesc->push_back( INTEGER );

    return 6;
}

unsigned int AA_OP_SBBBB_SBBBB_SBBBB_SBBBB(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned short i16;
    signed short si16;

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16 & 0xff) );
    v->push_back( (unsigned int)((i16 >> 8) & 0xff) );

    si16 = *( reinterpret_cast<signed short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (signed int)(si16) );

    si16 = *( reinterpret_cast<signed short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (signed int)(si16) );

    si16 = *( reinterpret_cast<signed short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (signed int)(si16) );

    si16 = *( reinterpret_cast<signed short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (signed int)(si16) );

    vdesc->push_back( OPVALUE );
    vdesc->push_back( REGISTER );
    vdesc->push_back( INTEGER );
    vdesc->push_back( INTEGER );
    vdesc->push_back( INTEGER );
    vdesc->push_back( INTEGER );

    return 10;
}

unsigned int _00_OP_AAAA_BBBB(Buff *b, vector<int> *v, vector<int> *vdesc) {
    unsigned short i16;

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16 & 0xff) );

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16) );

    i16 = *( reinterpret_cast<unsigned short *>( const_cast<char *>(b->read(2))) );
    v->push_back( (unsigned int)(i16) );

    return 6;
}

void INVOKE(Buff *b, vector<int> *v, vector<int> *vdesc, vector<int> *d, unsigned int *min_data) {
    unsigned int nb_arg = (*v)[2];
    unsigned int meth = (*v)[3];
    vector<int>::iterator it;

    if (nb_arg == 5) {
        unsigned int op_1 = (*v)[1];

        it=v->begin()+4;
        v->insert( v->begin()+1, it, it+4+nb_arg );
        v->erase( v->begin()+nb_arg, v->end() );

        v->push_back( op_1 );
        v->push_back( meth );
    }
    else {
        it=v->begin()+4;
        v->insert( v->begin()+1, it, it+4+nb_arg ); 
        v->erase( v->begin()+nb_arg+1, v->end() );

        v->push_back( meth );
    }


    vdesc->push_back( OPVALUE );
    for(int i=1; i < v->size(); i++)
        vdesc->push_back( REGISTER );

    (*vdesc)[ vdesc->size() - 1 ] = METHOD;
}

void FILLEDNEWARRAY(Buff *b, vector<int> *v, vector<int> *vdesc, vector<int> *d, unsigned int *min_data) {
    INVOKE(b, v, vdesc, d, min_data);
    (*vdesc)[ vdesc->size() - 1 ] = TYPE;
}

void INVOKERANGE(Buff *b, vector<int> *v, vector<int> *vdesc, vector<int> *d, unsigned int *min_data) {
    unsigned int nb_arg = (*v)[1];
    unsigned int meth = (*v)[2];
    vector<unsigned int>::iterator it;

    unsigned int NNNN = (*v)[3] + (*v)[1] + 1;

    for(int ii = (*v)[3]+1; ii < NNNN - 1; ii++) {
        v->push_back( ii );
    }

    v->push_back( meth );
    v->erase( v->begin()+1, v->begin()+3 );

    vdesc->push_back( OPVALUE );
    for(int i=1; i < v->size(); i++)
        vdesc->push_back( REGISTER );

    (*vdesc)[ vdesc->size() - 1 ] = METHOD;
}

void FILLEDNEWARRAYRANGE(Buff *b, vector<int> *v, vector<int> *vdesc, vector<int> *d, unsigned int *min_data) {
    INVOKERANGE(b, v, vdesc, d, min_data);
    (*vdesc)[ vdesc->size() - 1 ] = TYPE;
}

void FILLARRAYDATA(Buff *b, vector<int> *v, vector<int> *vdesc, vector<int> *d, unsigned int *min_data) {
    unsigned int value = ((*v)[2] * 2) + b->get_current_idx() - 6;

    //    printf("MIN_DATA = %d %d %d %d %d\n", b->get_end(), b->get_current_idx(), *min_data, (*v)[3], value);
    if (*min_data > value) {
        *min_data = value;
    }

    d->push_back( 0 );
    d->push_back( value );

    (*vdesc)[2] = INTEGER_BRANCH;
}

void SPARSESWITCH(Buff *b, vector<int> *v, vector<int> *vdesc, vector<int> *d, unsigned int *min_data) {
    //    printf("SPARSESWITCH\n"); fflush(stdout);

    unsigned int value = ((*v)[2] * 2) + b->get_current_idx() - 6;

    if (*min_data > value) {
        *min_data = value;
    }

    d->push_back( 1 );
    d->push_back( value );

    (*vdesc)[2] = INTEGER_BRANCH;
}

void PACKEDSWITCH(Buff *b, vector<int> *v, vector<int> *vdesc, vector<int> *d, unsigned int *min_data) {
    //    printf("PACKEDSWITCH\n"); fflush(stdout);

    unsigned int value = ((*v)[2] * 2) + b->get_current_idx() - 6;

    //printf("MIN_DATA = %d %d %d %d %d\n", b->get_end(), b->get_current_idx(), *min_data, (*v)[2], value);
    if (*min_data > value) {
        *min_data = value;
    }

    d->push_back( 2 );
    d->push_back( value );

    (*vdesc)[2] = INTEGER_BRANCH;
}


DBC::DBC(unsigned char value, const char *name, vector<int> *v, vector<int> *vdesc, size_t length) {
    op_value = value;
    op_name = name;
    voperands = v;
    vdescoperands = vdesc;
    op_length = length;
    vstrings = NULL;
}

DBC::~DBC() {
#ifdef DEBUG_DESTRUCTOR
    cout << "~DBC\n";
#endif

    this->voperands->clear();
    this->vdescoperands->clear();

    delete this->voperands;
    delete this->vdescoperands;
    
    if (this->vstrings != NULL) {
        this->vstrings->clear();
        delete this->vstrings;
    }
}

int DBC::get_opvalue() {
    return op_value;
}

const char *DBC::get_opname() {
    return op_name;
}

size_t DBC::get_length() {
    return op_length;
}

FillArrayData::FillArrayData(Buff *b, unsigned int off) {
    memcpy( &fadt, b->readat( off, sizeof(fillarraydata_t) ), sizeof(fillarraydata_t) );
    data_size = fadt.size * fadt.element_width;
    data = (char *)malloc( data_size );
    memcpy(data, b->readat( off + sizeof(fillarraydata_t), data_size ), data_size);
}

FillArrayData::~FillArrayData() {
    if (this->data != NULL)
        free(data);
}

const char *FillArrayData::get_opname() {
    return "FILL-ARRAY-DATA";
}

size_t FillArrayData::get_length() {
    return ((fadt.size * fadt.element_width + 1) / 2 + 4) * 2;
}

size_t FillArrayData::get_type() {
    return 0;
}

SparseSwitch::SparseSwitch(Buff *b, unsigned int off) {
    memcpy( &sst, b->readat( off, sizeof(sparseswitch_t) ), sizeof(sparseswitch_t) );

    int idx = off + sizeof(sparseswitch_t);
    for(int ii=0; ii < sst.size * 4; ii+=4, idx+=4) {
        int si32 = *( reinterpret_cast<signed int *>( const_cast<char *>(b->readat( idx, 4 ))) );
        keys.push_back( si32 );
    }

    for(int ii=0; ii < sst.size * 4; ii+=4, idx+=4) {
        int si32 = *( reinterpret_cast<signed int *>( const_cast<char *>(b->readat( idx, 4 ))) );
        targets.push_back( si32 );
    }
}

SparseSwitch::~SparseSwitch() {
    keys.clear();
    targets.clear();
}

const char *SparseSwitch::get_opname() {
    return "SPARSE-SWITCH";
}

size_t SparseSwitch::get_length() {
    return sizeof(sparseswitch_t) + (sst.size * 4) * 2;
}

size_t SparseSwitch::get_type() {
    return 1;
}

PackedSwitch::PackedSwitch(Buff *b, unsigned int off) {
    memcpy( &pst, b->readat( off, sizeof(packedswitch_t) ), sizeof(packedswitch_t) );

    int idx = off + sizeof(packedswitch_t) ;
    for(int ii=0; ii < pst.size; ii+=1) {
        int si32 = *( reinterpret_cast<signed int *>( const_cast<char *>(b->readat( idx, 4 ))) );
        targets.push_back( si32 );

        idx += 4;
    }
}

PackedSwitch::~PackedSwitch() {
    targets.clear();
}

const char *PackedSwitch::get_opname() {
    return "PACKED-SWITCH";
}

size_t PackedSwitch::get_length() {
    return sizeof(packedswitch_t) + pst.size * 4;
}

size_t PackedSwitch::get_type() {
    return 2;
}

DCode::DCode() {

}

DCode::~DCode() {
#ifdef DEBUG_DESTRUCTOR
    cout << "~DCode\n";
#endif

    for(int ii=0; ii < this->bytecodes.size(); ii++) {
        delete this->bytecodes[ ii ];
    }
    this->bytecodes.clear();

    for(int ii=0; ii < this->bytecodes_spe.size(); ii++) {
        delete this->bytecodes_spe[ ii ];
    }
    this->bytecodes_spe.clear();
}

DCode::DCode(vector<unsigned int(*)(Buff *, vector<int>*, vector<int>*)> *parsebytecodes,
        vector<void (*)(Buff *, vector<int> *, vector<int> *, vector<int> *, unsigned int *)> *postbytecodes,
        vector<const char *> *bytecodes_names,
        Buff *b) {
    unsigned char op_value;
    unsigned int size;

    vector<int> *datas;
    unsigned int min_data = b->get_end();

    datas = new vector<int>;

    while (b->empty() == false) {
        op_value = *( reinterpret_cast<unsigned char *>( const_cast<char *>(b->read_false(1))) );

        vector<int> *v = new vector<int>;
        vector<int> *vdesc = new vector<int>;
        size = (*parsebytecodes)[ op_value ]( b, v, vdesc );

        if ((*postbytecodes)[ op_value ] != NULL)
            (*postbytecodes)[ op_value ]( b, v, vdesc, datas, &min_data );

        bytecodes.push_back( new DBC(op_value, (*bytecodes_names)[ op_value ], v, vdesc, size) );

        /*printf("OP_VALUE %x ---> ", op_value); fflush(stdout);
          for(int ii=0; ii < v->size(); ii++) {
          printf("%d ", (*v)[ii]);
          }                    
          printf(" : "); 
          for(int ii=0; ii < vdesc->size(); ii++) {
          printf("%d ", (*vdesc)[ii]);
          }                    
          printf("\n");
          */

        if (b->get_current_idx() >= min_data) {
            break;
        }
    }

    if (b->empty() == false) {
        for(int ii=0; ii < datas->size(); ii+=2) {
            //printf("SPECIFIC %d %d\n", (*datas)[ii], (*datas)[ii+1]);

            if ((*datas)[ii] == 0) {
                bytecodes_spe.push_back( new FillArrayData( b, (*datas)[ii+1] ) );
            } else if ((*datas)[ii] == 1) {
                bytecodes_spe.push_back( new SparseSwitch( b, (*datas)[ii+1] ) );
            } else if ((*datas)[ii] == 2) {
                bytecodes_spe.push_back( new PackedSwitch( b, (*datas)[ii+1] ) );
            }
        }                    
        //printf("\n");
        //cout << "la" << b->get_end() << " " << b->get_current_idx() << "\n";
    }

    datas->clear();
    delete datas;
}

int DCode::size() {
    return bytecodes.size() + bytecodes_spe.size();
}

DBC *DCode::get_bytecode_at(int i) {
    return bytecodes[ i ];
}

DalvikBytecode::DalvikBytecode() {
    for (int ii=0; ii < 0xff; ii++)
        bytecodes_names.push_back( NULL );

    for (int ii=0; ii < 0xff; ii++)
        bytecodes.push_back( NULL );

    for (int ii=0; ii < 0xff; ii++)
        postbytecodes.push_back( NULL );

    bytecodes_names[ 0x0 ] = "nop";
    bytecodes_names[ 0x0 ] = "nop";
    bytecodes_names[ 0x1 ] = "move";
    bytecodes_names[ 0x2 ] = "move/from16";
    bytecodes_names[ 0x3 ] = "move/16";
    bytecodes_names[ 0x4 ] = "move-wide";
    bytecodes_names[ 0x5 ] = "move-wide/from16";
    bytecodes_names[ 0x6 ] = "move-wide/16";
    bytecodes_names[ 0x7 ] = "move-object";
    bytecodes_names[ 0x8 ] = "move-object/from16";
    bytecodes_names[ 0x9 ] = "move-object/16";
    bytecodes_names[ 0xa ] = "move-result";
    bytecodes_names[ 0xb ] = "move-result-wide";
    bytecodes_names[ 0xc ] = "move-result-object";
    bytecodes_names[ 0xd ] = "move-exception";
    bytecodes_names[ 0xe ] = "return-void";
    bytecodes_names[ 0xf ] = "return";
    bytecodes_names[ 0x10 ] = "return-wide";
    bytecodes_names[ 0x11 ] = "return-object";
    bytecodes_names[ 0x12 ] = "const/4";
    bytecodes_names[ 0x13 ] = "const/16";
    bytecodes_names[ 0x14 ] = "const";
    bytecodes_names[ 0x15 ] = "const/high16";
    bytecodes_names[ 0x16 ] = "const-wide/16";
    bytecodes_names[ 0x17 ] = "const-wide/32";
    bytecodes_names[ 0x18 ] = "const-wide";
    bytecodes_names[ 0x19 ] = "const-wide/high16";
    bytecodes_names[ 0x1a ] = "const-string";
    bytecodes_names[ 0x1b ] = "const-string/jumbo";
    bytecodes_names[ 0x1c ] = "const-class";
    bytecodes_names[ 0x1d ] = "monitor-enter";
    bytecodes_names[ 0x1e ] = "monitor-exit";
    bytecodes_names[ 0x1f ] = "check-cast";
    bytecodes_names[ 0x20 ] = "instance-of";
    bytecodes_names[ 0x21 ] = "array-length";
    bytecodes_names[ 0x22 ] = "new-instance";
    bytecodes_names[ 0x23 ] = "new-array";
    bytecodes_names[ 0x24 ] = "filled-new-array";
    bytecodes_names[ 0x25 ] = "filled-new-array/range";
    bytecodes_names[ 0x26 ] = "fill-array-data";
    bytecodes_names[ 0x27 ] = "throw";
    bytecodes_names[ 0x28 ] = "goto";
    bytecodes_names[ 0x29 ] = "goto/16";
    bytecodes_names[ 0x2a ] = "goto/32";
    bytecodes_names[ 0x2b ] = "packed-switch";
    bytecodes_names[ 0x2c ] = "sparse-switch";
    bytecodes_names[ 0x2d ] = "cmpl-float";
    bytecodes_names[ 0x2e ] = "cmpg-float";
    bytecodes_names[ 0x2f ] = "cmpl-double";
    bytecodes_names[ 0x30 ] = "cmpg-double";
    bytecodes_names[ 0x31 ] = "cmp-long";
    bytecodes_names[ 0x32 ] = "if-eq";
    bytecodes_names[ 0x33 ] = "if-ne";
    bytecodes_names[ 0x34 ] = "if-lt";
    bytecodes_names[ 0x35 ] = "if-ge";
    bytecodes_names[ 0x36 ] = "if-gt";
    bytecodes_names[ 0x37 ] = "if-le";
    bytecodes_names[ 0x38 ] = "if-eqz";
    bytecodes_names[ 0x39 ] = "if-nez";
    bytecodes_names[ 0x3a ] = "if-ltz";
    bytecodes_names[ 0x3b ] = "if-gez";
    bytecodes_names[ 0x3c ] = "if-gtz";
    bytecodes_names[ 0x3d ] = "if-lez";
    bytecodes_names[ 0x3e ] = "nop";
    bytecodes_names[ 0x3f ] = "nop";
    bytecodes_names[ 0x40 ] = "nop";
    bytecodes_names[ 0x41 ] = "nop";
    bytecodes_names[ 0x42 ] = "nop";
    bytecodes_names[ 0x43 ] = "nop";
    bytecodes_names[ 0x44 ] = "aget";
    bytecodes_names[ 0x45 ] = "aget-wide";
    bytecodes_names[ 0x46 ] = "aget-object";
    bytecodes_names[ 0x47 ] = "aget-boolean";
    bytecodes_names[ 0x48 ] = "aget-byte";
    bytecodes_names[ 0x49 ] = "aget-char";
    bytecodes_names[ 0x4a ] = "aget-short";
    bytecodes_names[ 0x4b ] = "aput";
    bytecodes_names[ 0x4c ] = "aput-wide";
    bytecodes_names[ 0x4d ] = "aput-object";
    bytecodes_names[ 0x4e ] = "aput-boolean";
    bytecodes_names[ 0x4f ] = "aput-byte";
    bytecodes_names[ 0x50 ] = "aput-char";
    bytecodes_names[ 0x51 ] = "aput-short";
    bytecodes_names[ 0x52 ] = "iget";
    bytecodes_names[ 0x53 ] = "iget-wide";
    bytecodes_names[ 0x54 ] = "iget-object";
    bytecodes_names[ 0x55 ] = "iget-boolean";
    bytecodes_names[ 0x56 ] = "iget-byte";
    bytecodes_names[ 0x57 ] = "iget-char";
    bytecodes_names[ 0x58 ] = "iget-short";
    bytecodes_names[ 0x59 ] = "iput";
    bytecodes_names[ 0x5a ] = "iput-wide";
    bytecodes_names[ 0x5b ] = "iput-object";
    bytecodes_names[ 0x5c ] = "iput-boolean";
    bytecodes_names[ 0x5d ] = "iput-byte";
    bytecodes_names[ 0x5e ] = "iput-char";
    bytecodes_names[ 0x5f ] = "iput-short";
    bytecodes_names[ 0x60 ] = "sget";
    bytecodes_names[ 0x61 ] = "sget-wide";
    bytecodes_names[ 0x62 ] = "sget-object";
    bytecodes_names[ 0x63 ] = "sget-boolean";
    bytecodes_names[ 0x64 ] = "sget-byte";
    bytecodes_names[ 0x65 ] = "sget-char";
    bytecodes_names[ 0x66 ] = "sget-short";
    bytecodes_names[ 0x67 ] = "sput";
    bytecodes_names[ 0x68 ] = "sput-wide";
    bytecodes_names[ 0x69 ] = "sput-object";
    bytecodes_names[ 0x6a ] = "sput-boolean";
    bytecodes_names[ 0x6b ] = "sput-byte";
    bytecodes_names[ 0x6c ] = "sput-char";
    bytecodes_names[ 0x6d ] = "sput-short";
    bytecodes_names[ 0x6e ] = "invoke-virtual";
    bytecodes_names[ 0x6f ] = "invoke-super";
    bytecodes_names[ 0x70 ] = "invoke-direct";
    bytecodes_names[ 0x71 ] = "invoke-static";
    bytecodes_names[ 0x72 ] = "invoke-interface";
    bytecodes_names[ 0x73 ] = "nop";
    bytecodes_names[ 0x74 ] = "invoke-virtual/range";
    bytecodes_names[ 0x75 ] = "invoke-super/range";
    bytecodes_names[ 0x76 ] = "invoke-direct/range";
    bytecodes_names[ 0x77 ] = "invoke-static/range";
    bytecodes_names[ 0x78 ] = "invoke-interface/range";
    bytecodes_names[ 0x79 ] = "nop";
    bytecodes_names[ 0x7a ] = "nop";
    bytecodes_names[ 0x7b ] = "neg-int";
    bytecodes_names[ 0x7c ] = "not-int";
    bytecodes_names[ 0x7d ] = "neg-long";
    bytecodes_names[ 0x7e ] = "not-long";
    bytecodes_names[ 0x7f ] = "neg-float";
    bytecodes_names[ 0x80 ] = "neg-double";
    bytecodes_names[ 0x81 ] = "int-to-long";
    bytecodes_names[ 0x82 ] = "int-to-float";
    bytecodes_names[ 0x83 ] = "int-to-double";
    bytecodes_names[ 0x84 ] = "long-to-int";
    bytecodes_names[ 0x85 ] = "long-to-float";
    bytecodes_names[ 0x86 ] = "long-to-double";
    bytecodes_names[ 0x87 ] = "float-to-int";
    bytecodes_names[ 0x88 ] = "float-to-long";
    bytecodes_names[ 0x89 ] = "float-to-double";
    bytecodes_names[ 0x8a ] = "double-to-int";
    bytecodes_names[ 0x8b ] = "double-to-long";
    bytecodes_names[ 0x8c ] = "double-to-float";
    bytecodes_names[ 0x8d ] = "int-to-byte";
    bytecodes_names[ 0x8e ] = "int-to-char";
    bytecodes_names[ 0x8f ] = "int-to-short";
    bytecodes_names[ 0x90 ] = "add-int";
    bytecodes_names[ 0x91 ] = "sub-int";
    bytecodes_names[ 0x92 ] = "mul-int";
    bytecodes_names[ 0x93 ] = "div-int";
    bytecodes_names[ 0x94 ] = "rem-int";
    bytecodes_names[ 0x95 ] = "and-int";
    bytecodes_names[ 0x96 ] = "or-int";
    bytecodes_names[ 0x97 ] = "xor-int";
    bytecodes_names[ 0x98 ] = "shl-int";
    bytecodes_names[ 0x99 ] = "shr-int";
    bytecodes_names[ 0x9a ] = "ushr-int";
    bytecodes_names[ 0x9b ] = "add-long";
    bytecodes_names[ 0x9c ] = "sub-long";
    bytecodes_names[ 0x9d ] = "mul-long";
    bytecodes_names[ 0x9e ] = "div-long";
    bytecodes_names[ 0x9f ] = "rem-long";
    bytecodes_names[ 0xa0 ] = "and-long";
    bytecodes_names[ 0xa1 ] = "or-long";
    bytecodes_names[ 0xa2 ] = "xor-long";
    bytecodes_names[ 0xa3 ] = "shl-long";
    bytecodes_names[ 0xa4 ] = "shr-long";
    bytecodes_names[ 0xa5 ] = "ushr-long";
    bytecodes_names[ 0xa6 ] = "add-float";
    bytecodes_names[ 0xa7 ] = "sub-float";
    bytecodes_names[ 0xa8 ] = "mul-float";
    bytecodes_names[ 0xa9 ] = "div-float";
    bytecodes_names[ 0xaa ] = "rem-float";
    bytecodes_names[ 0xab ] = "add-double";
    bytecodes_names[ 0xac ] = "sub-double";
    bytecodes_names[ 0xad ] = "mul-double";
    bytecodes_names[ 0xae ] = "div-double";
    bytecodes_names[ 0xaf ] = "rem-double";
    bytecodes_names[ 0xb0 ] = "add-int/2addr";
    bytecodes_names[ 0xb1 ] = "sub-int/2addr";
    bytecodes_names[ 0xb2 ] = "mul-int/2addr";
    bytecodes_names[ 0xb3 ] = "div-int/2addr";
    bytecodes_names[ 0xb4 ] = "rem-int/2addr";
    bytecodes_names[ 0xb5 ] = "and-int/2addr";
    bytecodes_names[ 0xb6 ] = "or-int/2addr";
    bytecodes_names[ 0xb7 ] = "xor-int/2addr";
    bytecodes_names[ 0xb8 ] = "shl-int/2addr";
    bytecodes_names[ 0xb9 ] = "shr-int/2addr";
    bytecodes_names[ 0xba ] = "ushr-int/2addr";
    bytecodes_names[ 0xbb ] = "add-long/2addr";
    bytecodes_names[ 0xbc ] = "sub-long/2addr";
    bytecodes_names[ 0xbd ] = "mul-long/2addr";
    bytecodes_names[ 0xbe ] = "div-long/2addr";
    bytecodes_names[ 0xbf ] = "rem-long/2addr";
    bytecodes_names[ 0xc0 ] = "and-long/2addr";
    bytecodes_names[ 0xc1 ] = "or-long/2addr";
    bytecodes_names[ 0xc2 ] = "xor-long/2addr";
    bytecodes_names[ 0xc3 ] = "shl-long/2addr";
    bytecodes_names[ 0xc4 ] = "shr-long/2addr";
    bytecodes_names[ 0xc5 ] = "ushr-long/2addr";
    bytecodes_names[ 0xc6 ] = "add-float/2addr";
    bytecodes_names[ 0xc7 ] = "sub-float/2addr";
    bytecodes_names[ 0xc8 ] = "mul-float/2addr";
    bytecodes_names[ 0xc9 ] = "div-float/2addr";
    bytecodes_names[ 0xca ] = "rem-float/2addr";
    bytecodes_names[ 0xcb ] = "add-double/2addr";
    bytecodes_names[ 0xcc ] = "sub-double/2addr";
    bytecodes_names[ 0xcd ] = "mul-double/2addr";
    bytecodes_names[ 0xce ] = "div-double/2addr";
    bytecodes_names[ 0xcf ] = "rem-double/2addr";
    bytecodes_names[ 0xd0 ] = "add-int/lit16";
    bytecodes_names[ 0xd1 ] = "rsub-int";
    bytecodes_names[ 0xd2 ] = "mul-int/lit16";
    bytecodes_names[ 0xd3 ] = "div-int/lit16";
    bytecodes_names[ 0xd4 ] = "rem-int/lit16";
    bytecodes_names[ 0xd5 ] = "and-int/lit16";
    bytecodes_names[ 0xd6 ] = "or-int/lit16";
    bytecodes_names[ 0xd7 ] = "xor-int/lit16";
    bytecodes_names[ 0xd8 ] = "add-int/lit8";
    bytecodes_names[ 0xd9 ] = "rsub-int/lit8";
    bytecodes_names[ 0xda ] = "mul-int/lit8";
    bytecodes_names[ 0xdb ] = "div-int/lit8";
    bytecodes_names[ 0xdc ] = "rem-int/lit8";
    bytecodes_names[ 0xdd ] = "and-int/lit8";
    bytecodes_names[ 0xde ] = "or-int/lit8";
    bytecodes_names[ 0xdf ] = "xor-int/lit8";
    bytecodes_names[ 0xe0 ] = "shl-int/lit8";
    bytecodes_names[ 0xe1 ] = "shr-int/lit8";
    bytecodes_names[ 0xe2 ] = "ushr-int/lit8";
    bytecodes_names[ 0xe3 ] = "nop";
    bytecodes_names[ 0xe4 ] = "nop";
    bytecodes_names[ 0xe5 ] = "nop";
    bytecodes_names[ 0xe6 ] = "nop";
    bytecodes_names[ 0xe7 ] = "nop";
    bytecodes_names[ 0xe8 ] = "nop";
    bytecodes_names[ 0xe9 ] = "nop";
    bytecodes_names[ 0xea ] = "nop";
    bytecodes_names[ 0xeb ] = "nop";
    bytecodes_names[ 0xec ] = "nop";
    bytecodes_names[ 0xed ] = "^throw-verification-error";
    bytecodes_names[ 0xee ] = "nop";
    bytecodes_names[ 0xef ] = "nop";
    bytecodes_names[ 0xf0 ] = "nop";
    bytecodes_names[ 0xf1 ] = "nop";
    bytecodes_names[ 0xf2 ] = "nop";
    bytecodes_names[ 0xf3 ] = "nop";
    bytecodes_names[ 0xf4 ] = "nop";
    bytecodes_names[ 0xf5 ] = "nop";
    bytecodes_names[ 0xf6 ] = "nop";
    bytecodes_names[ 0xf7 ] = "nop";
    bytecodes_names[ 0xf8 ] = "nop";
    bytecodes_names[ 0xf9 ] = "nop";
    bytecodes_names[ 0xfa ] = "nop";
    bytecodes_names[ 0xfb ] = "nop";
    bytecodes_names[ 0xfc ] = "nop";
    bytecodes_names[ 0xfd ] = "nop";
    bytecodes_names[ 0xfe ] = "nop";
    bytecodes_names[ 0xff ] = "nop";

    bytecodes[ 0x0 ] = &OP_00; 

    bytecodes[ 0x1 ] = &B_A_OP; 

    bytecodes[ 0x2 ] = &AA_OP_BBBB; 

    bytecodes[ 0x3 ] = &_00_OP_AAAA_BBBB; 

    bytecodes[ 0x4 ] = &B_A_OP; 
    bytecodes[ 0x5 ] = &AA_OP_BBBB; 

    bytecodes[ 0x6 ] = &_00_OP_AAAA_BBBB; 

    bytecodes[ 0x7 ] = &B_A_OP; 
    bytecodes[ 0x8 ] = &AA_OP_BBBB;

    bytecodes[ 0x9 ] = &_00_OP_AAAA_BBBB;

    bytecodes[ 0xa ] = &AA_OP;
    bytecodes[ 0xb ] = &AA_OP;
    bytecodes[ 0xc ] = &AA_OP;
    bytecodes[ 0xd ] = &AA_OP;

    bytecodes[ 0xe ] = &OP_00;

    bytecodes[ 0xf ] = &AA_OP;

    bytecodes[ 0x10 ] = &AA_OP;
    bytecodes[ 0x11 ] = &AA_OP;
    bytecodes[ 0x12 ] = &SB_A_OP;

    bytecodes[ 0x13 ] = &AA_OP_SBBBB;
    bytecodes[ 0x14 ] = &AA_OP_SBBBB_SBBBB;
    bytecodes[ 0x15 ] = &AA_OP_SBBBB;
    bytecodes[ 0x16 ] = &AA_OP_SBBBB;

    bytecodes[ 0x17 ] = &AA_OP_SBBBB_SBBBB;
    bytecodes[ 0x18 ] = &AA_OP_SBBBB_SBBBB_SBBBB_SBBBB;

    bytecodes[ 0x19 ] = &AA_OP_SBBBB;

    bytecodes[ 0x1a ] = &AA_OP_BBBB_2_STRING;
    bytecodes[ 0x1b ] = &AA_OP_BBBBBBBB_2_STRING; 
    bytecodes[ 0x1c ] = &AA_OP_BBBB_2_TYPE;

    bytecodes[ 0x1d ] = &AA_OP;
    bytecodes[ 0x1e ] = &AA_OP;

    bytecodes[ 0x1f ] = &AA_OP_BBBB_2_TYPE;

    bytecodes[ 0x20 ] = &B_A_OP_CCCC_3_TYPE;
    bytecodes[ 0x21 ] = &B_A_OP;
    bytecodes[ 0x22 ] = &AA_OP_BBBB_2_TYPE;

    bytecodes[ 0x23 ] = &B_A_OP_CCCC_3_TYPE;

    bytecodes[ 0x24 ] = &B_A_OP_CCCC_G_F_E_D; postbytecodes[ 0x24 ] = &FILLEDNEWARRAY;
    bytecodes[ 0x25 ] = &AA_OP_BBBB_CCCC; postbytecodes[ 0x25 ] = &FILLEDNEWARRAYRANGE;

    bytecodes[ 0x26 ] = &AA_OP_SBBBBBBBB; postbytecodes[ 0x26 ] = &FILLARRAYDATA;

    bytecodes[ 0x27 ] = &B_A_OP;

    bytecodes[ 0x28 ] = &OP_SAA_BRANCH;
    bytecodes[ 0x29 ] = &_00_OP_SAAAA_BRANCH;
    bytecodes[ 0x2a ] = &_00_OP_SAAAAAAAA_BRANCH;

    bytecodes[ 0x2b ] = &AA_OP_SBBBBBBBB; postbytecodes[ 0x2b ] = &PACKEDSWITCH;
    bytecodes[ 0x2c ] = &AA_OP_SBBBBBBBB; postbytecodes[ 0x2c ] = &SPARSESWITCH;

    bytecodes[ 0x2d ] = &AA_OP_CC_BB;
    bytecodes[ 0x2e ] = &AA_OP_CC_BB;
    bytecodes[ 0x2f ] = &AA_OP_CC_BB;
    bytecodes[ 0x30 ] = &AA_OP_CC_BB;
    bytecodes[ 0x31 ] = &AA_OP_CC_BB;

    bytecodes[ 0x32 ] = &B_A_OP_SCCCC_BRANCH;  
    bytecodes[ 0x33 ] = &B_A_OP_SCCCC_BRANCH;  
    bytecodes[ 0x34 ] = &B_A_OP_SCCCC_BRANCH;  
    bytecodes[ 0x35 ] = &B_A_OP_SCCCC_BRANCH;  
    bytecodes[ 0x36 ] = &B_A_OP_SCCCC_BRANCH;  
    bytecodes[ 0x37 ] = &B_A_OP_SCCCC_BRANCH;  

    bytecodes[ 0x38 ] = &AA_OP_SBBBB_BRANCH;
    bytecodes[ 0x39 ] = &AA_OP_SBBBB_BRANCH;
    bytecodes[ 0x3a ] = &AA_OP_SBBBB_BRANCH;
    bytecodes[ 0x3b ] = &AA_OP_SBBBB_BRANCH;
    bytecodes[ 0x3c ] = &AA_OP_SBBBB_BRANCH;
    bytecodes[ 0x3d ] = &AA_OP_SBBBB_BRANCH;

    bytecodes[ 0x3e ] = &OP_00;
    bytecodes[ 0x3f ] = &OP_00;
    bytecodes[ 0x40 ] = &OP_00;
    bytecodes[ 0x41 ] = &OP_00;
    bytecodes[ 0x42 ] = &OP_00;
    bytecodes[ 0x43 ] = &OP_00;

    bytecodes[ 0x44 ] = &AA_OP_CC_BB;
    bytecodes[ 0x45 ] = &AA_OP_CC_BB;
    bytecodes[ 0x46 ] = &AA_OP_CC_BB;
    bytecodes[ 0x47 ] = &AA_OP_CC_BB;
    bytecodes[ 0x48 ] = &AA_OP_CC_BB;
    bytecodes[ 0x49 ] = &AA_OP_CC_BB;
    bytecodes[ 0x4a ] = &AA_OP_CC_BB;
    bytecodes[ 0x4b ] = &AA_OP_CC_BB;
    bytecodes[ 0x4c ] = &AA_OP_CC_BB;
    bytecodes[ 0x4d ] = &AA_OP_CC_BB;
    bytecodes[ 0x4e ] = &AA_OP_CC_BB;
    bytecodes[ 0x4f ] = &AA_OP_CC_BB;
    bytecodes[ 0x50 ] = &AA_OP_CC_BB;
    bytecodes[ 0x51 ] = &AA_OP_CC_BB;

    bytecodes[ 0x52 ] = &B_A_OP_CCCC_3_FIELD;
    bytecodes[ 0x53 ] = &B_A_OP_CCCC_3_FIELD;
    bytecodes[ 0x54 ] = &B_A_OP_CCCC_3_FIELD;
    bytecodes[ 0x55 ] = &B_A_OP_CCCC_3_FIELD;
    bytecodes[ 0x56 ] = &B_A_OP_CCCC_3_FIELD;
    bytecodes[ 0x57 ] = &B_A_OP_CCCC_3_FIELD;
    bytecodes[ 0x58 ] = &B_A_OP_CCCC_3_FIELD;
    bytecodes[ 0x59 ] = &B_A_OP_CCCC_3_FIELD;
    bytecodes[ 0x5a ] = &B_A_OP_CCCC_3_FIELD;
    bytecodes[ 0x5b ] = &B_A_OP_CCCC_3_FIELD;
    bytecodes[ 0x5c ] = &B_A_OP_CCCC_3_FIELD;
    bytecodes[ 0x5d ] = &B_A_OP_CCCC_3_FIELD;
    bytecodes[ 0x5e ] = &B_A_OP_CCCC_3_FIELD;
    bytecodes[ 0x5f ] = &B_A_OP_CCCC_3_FIELD;

    bytecodes[ 0x60 ] = &AA_OP_BBBB_2_FIELD;
    bytecodes[ 0x61 ] = &AA_OP_BBBB_2_FIELD;
    bytecodes[ 0x62 ] = &AA_OP_BBBB_2_FIELD;
    bytecodes[ 0x63 ] = &AA_OP_BBBB_2_FIELD;
    bytecodes[ 0x64 ] = &AA_OP_BBBB_2_FIELD;
    bytecodes[ 0x65 ] = &AA_OP_BBBB_2_FIELD;
    bytecodes[ 0x66 ] = &AA_OP_BBBB_2_FIELD;
    bytecodes[ 0x67 ] = &AA_OP_BBBB_2_FIELD;
    bytecodes[ 0x68 ] = &AA_OP_BBBB_2_FIELD;
    bytecodes[ 0x69 ] = &AA_OP_BBBB_2_FIELD;
    bytecodes[ 0x6a ] = &AA_OP_BBBB_2_FIELD;
    bytecodes[ 0x6b ] = &AA_OP_BBBB_2_FIELD;
    bytecodes[ 0x6c ] = &AA_OP_BBBB_2_FIELD;
    bytecodes[ 0x6d ] = &AA_OP_BBBB_2_FIELD;

    bytecodes[ 0x6e ] = &B_A_OP_CCCC_G_F_E_D; postbytecodes[ 0x6e ] = &INVOKE;
    bytecodes[ 0x6f ] = &B_A_OP_CCCC_G_F_E_D; postbytecodes[ 0x6f ] = &INVOKE;
    bytecodes[ 0x70 ] = &B_A_OP_CCCC_G_F_E_D; postbytecodes[ 0x70 ] = &INVOKE;
    bytecodes[ 0x71 ] = &B_A_OP_CCCC_G_F_E_D; postbytecodes[ 0x71 ] = &INVOKE;
    bytecodes[ 0x72 ] = &B_A_OP_CCCC_G_F_E_D; postbytecodes[ 0x72 ] = &INVOKE;

    bytecodes[ 0x73 ] = &OP_00;

    bytecodes[ 0x74 ] = &AA_OP_BBBB_CCCC; postbytecodes[ 0x74 ] = &INVOKERANGE;
    bytecodes[ 0x75 ] = &AA_OP_BBBB_CCCC; postbytecodes[ 0x75 ] = &INVOKERANGE;
    bytecodes[ 0x76 ] = &AA_OP_BBBB_CCCC; postbytecodes[ 0x76 ] = &INVOKERANGE;
    bytecodes[ 0x77 ] = &AA_OP_BBBB_CCCC; postbytecodes[ 0x77 ] = &INVOKERANGE;
    bytecodes[ 0x78 ] = &AA_OP_BBBB_CCCC; postbytecodes[ 0x78 ] = &INVOKERANGE;

    bytecodes[ 0x79 ] = &OP_00;
    bytecodes[ 0x7a ] = &OP_00;

    bytecodes[ 0x7b ] = &B_A_OP;
    bytecodes[ 0x7c ] = &B_A_OP;
    bytecodes[ 0x7d ] = &B_A_OP;
    bytecodes[ 0x7e ] = &B_A_OP;
    bytecodes[ 0x7f ] = &B_A_OP;
    bytecodes[ 0x80 ] = &B_A_OP;
    bytecodes[ 0x81 ] = &B_A_OP;
    bytecodes[ 0x82 ] = &B_A_OP;
    bytecodes[ 0x83 ] = &B_A_OP;
    bytecodes[ 0x84 ] = &B_A_OP;
    bytecodes[ 0x85 ] = &B_A_OP;
    bytecodes[ 0x86 ] = &B_A_OP;
    bytecodes[ 0x87 ] = &B_A_OP;
    bytecodes[ 0x88 ] = &B_A_OP;
    bytecodes[ 0x89 ] = &B_A_OP;
    bytecodes[ 0x8a ] = &B_A_OP;
    bytecodes[ 0x8b ] = &B_A_OP;
    bytecodes[ 0x8c ] = &B_A_OP;
    bytecodes[ 0x8d ] = &B_A_OP;
    bytecodes[ 0x8e ] = &B_A_OP;
    bytecodes[ 0x8f ] = &B_A_OP;

    bytecodes[ 0x90 ] = &AA_OP_CC_BB;
    bytecodes[ 0x91 ] = &AA_OP_CC_BB;
    bytecodes[ 0x92 ] = &AA_OP_CC_BB;
    bytecodes[ 0x93 ] = &AA_OP_CC_BB;
    bytecodes[ 0x94 ] = &AA_OP_CC_BB;
    bytecodes[ 0x95 ] = &AA_OP_CC_BB;
    bytecodes[ 0x96 ] = &AA_OP_CC_BB;
    bytecodes[ 0x97 ] = &AA_OP_CC_BB;
    bytecodes[ 0x98 ] = &AA_OP_CC_BB;
    bytecodes[ 0x99 ] = &AA_OP_CC_BB;
    bytecodes[ 0x9a ] = &AA_OP_CC_BB;
    bytecodes[ 0x9b ] = &AA_OP_CC_BB;
    bytecodes[ 0x9c ] = &AA_OP_CC_BB;
    bytecodes[ 0x9d ] = &AA_OP_CC_BB;
    bytecodes[ 0x9e ] = &AA_OP_CC_BB;
    bytecodes[ 0x9f ] = &AA_OP_CC_BB;
    bytecodes[ 0xa0 ] = &AA_OP_CC_BB;
    bytecodes[ 0xa1 ] = &AA_OP_CC_BB;
    bytecodes[ 0xa2 ] = &AA_OP_CC_BB;
    bytecodes[ 0xa3 ] = &AA_OP_CC_BB;
    bytecodes[ 0xa4 ] = &AA_OP_CC_BB;
    bytecodes[ 0xa5 ] = &AA_OP_CC_BB;
    bytecodes[ 0xa6 ] = &AA_OP_CC_BB;
    bytecodes[ 0xa7 ] = &AA_OP_CC_BB;
    bytecodes[ 0xa8 ] = &AA_OP_CC_BB;
    bytecodes[ 0xa9 ] = &AA_OP_CC_BB;
    bytecodes[ 0xaa ] = &AA_OP_CC_BB;
    bytecodes[ 0xab ] = &AA_OP_CC_BB;
    bytecodes[ 0xac ] = &AA_OP_CC_BB;
    bytecodes[ 0xad ] = &AA_OP_CC_BB;
    bytecodes[ 0xae ] = &AA_OP_CC_BB;
    bytecodes[ 0xaf ] = &AA_OP_CC_BB;

    bytecodes[ 0xb0 ] = &B_A_OP;
    bytecodes[ 0xb1 ] = &B_A_OP;
    bytecodes[ 0xb2 ] = &B_A_OP;
    bytecodes[ 0xb3 ] = &B_A_OP;
    bytecodes[ 0xb4 ] = &B_A_OP;
    bytecodes[ 0xb5 ] = &B_A_OP;
    bytecodes[ 0xb6 ] = &B_A_OP;
    bytecodes[ 0xb7 ] = &B_A_OP;
    bytecodes[ 0xb8 ] = &B_A_OP;
    bytecodes[ 0xb9 ] = &B_A_OP;
    bytecodes[ 0xba ] = &B_A_OP;
    bytecodes[ 0xbb ] = &B_A_OP;
    bytecodes[ 0xbc ] = &B_A_OP;
    bytecodes[ 0xbd ] = &B_A_OP;
    bytecodes[ 0xbe ] = &B_A_OP;
    bytecodes[ 0xbf ] = &B_A_OP;
    bytecodes[ 0xc0 ] = &B_A_OP;
    bytecodes[ 0xc1 ] = &B_A_OP;
    bytecodes[ 0xc2 ] = &B_A_OP;
    bytecodes[ 0xc3 ] = &B_A_OP;
    bytecodes[ 0xc4 ] = &B_A_OP;
    bytecodes[ 0xc5 ] = &B_A_OP;
    bytecodes[ 0xc6 ] = &B_A_OP;
    bytecodes[ 0xc7 ] = &B_A_OP;
    bytecodes[ 0xc8 ] = &B_A_OP;
    bytecodes[ 0xc9 ] = &B_A_OP;
    bytecodes[ 0xca ] = &B_A_OP;
    bytecodes[ 0xcb ] = &B_A_OP;
    bytecodes[ 0xcc ] = &B_A_OP;
    bytecodes[ 0xcd ] = &B_A_OP;
    bytecodes[ 0xce ] = &B_A_OP;
    bytecodes[ 0xcf ] = &B_A_OP;

    bytecodes[ 0xd0 ] = &B_A_OP_SCCCC;  
    bytecodes[ 0xd1 ] = &B_A_OP_SCCCC;  
    bytecodes[ 0xd2 ] = &B_A_OP_SCCCC;  
    bytecodes[ 0xd3 ] = &B_A_OP_SCCCC;  
    bytecodes[ 0xd4 ] = &B_A_OP_SCCCC;  
    bytecodes[ 0xd5 ] = &B_A_OP_SCCCC;  
    bytecodes[ 0xd6 ] = &B_A_OP_SCCCC;  
    bytecodes[ 0xd7 ] = &B_A_OP_SCCCC;  

    bytecodes[ 0xd8 ] = &AA_OP_BB_SCC;
    bytecodes[ 0xd9 ] = &AA_OP_BB_SCC;
    bytecodes[ 0xda ] = &AA_OP_BB_SCC;
    bytecodes[ 0xdb ] = &AA_OP_BB_SCC;
    bytecodes[ 0xdc ] = &AA_OP_BB_SCC;
    bytecodes[ 0xdd ] = &AA_OP_BB_SCC;
    bytecodes[ 0xde ] = &AA_OP_BB_SCC;
    bytecodes[ 0xdf ] = &AA_OP_BB_SCC;
    bytecodes[ 0xe0 ] = &AA_OP_BB_SCC;
    bytecodes[ 0xe1 ] = &AA_OP_BB_SCC;
    bytecodes[ 0xe2 ] = &AA_OP_BB_SCC;

    bytecodes[ 0xe3 ] = &OP_00;
    bytecodes[ 0xe4 ] = &OP_00;
    bytecodes[ 0xe5 ] = &OP_00;
    bytecodes[ 0xe6 ] = &OP_00;
    bytecodes[ 0xe7 ] = &OP_00;
    bytecodes[ 0xe8 ] = &OP_00;
    bytecodes[ 0xe9 ] = &OP_00;
    bytecodes[ 0xea ] = &OP_00;
    bytecodes[ 0xeb ] = &OP_00;
    bytecodes[ 0xec ] = &OP_00;
    
    bytecodes[ 0xed ] = &DAA_OP_DBBBB;

    bytecodes[ 0xee ] = &OP_00;
    bytecodes[ 0xef ] = &OP_00;
    bytecodes[ 0xf0 ] = &OP_00;
    bytecodes[ 0xf1 ] = &OP_00;
    bytecodes[ 0xf2 ] = &OP_00;
    bytecodes[ 0xf3 ] = &OP_00;
    bytecodes[ 0xf4 ] = &OP_00;
    bytecodes[ 0xf5 ] = &OP_00;
    bytecodes[ 0xf6 ] = &OP_00;
    bytecodes[ 0xf7 ] = &OP_00;
    bytecodes[ 0xf8 ] = &OP_00;
    bytecodes[ 0xf9 ] = &OP_00;
    bytecodes[ 0xfa ] = &OP_00;
    bytecodes[ 0xfb ] = &OP_00;
    bytecodes[ 0xfc ] = &OP_00;
    bytecodes[ 0xfd ] = &OP_00;
    bytecodes[ 0xfe ] = &OP_00;
    bytecodes[ 0xff ] = &OP_00;
}

DCode *DalvikBytecode::new_code(const char *data, size_t data_len) {
    Buff b = Buff( data, data_len );
    DCode *d = new DCode( &bytecodes, &postbytecodes, &bytecodes_names, &b );

    return d;
}

/* PYTHON BINDING */
void DBC_dealloc(dvm_DBCObject* self)
{
#ifdef DEBUG_DESTRUCTOR
    cout << "DBC_dealloc\n";
#endif

    delete self->d;
    //Py_DECREF( self->operands );
    self->ob_type->tp_free((PyObject*)self);
}

PyObject *DBC_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    dvm_DBCObject *self;

    self = (dvm_DBCObject *)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->d = NULL;
        self->operands = NULL;
    }

    return (PyObject *)self;
}

int DBC_init(dvm_DBCObject *self, PyObject *args, PyObject *kwds)
{
    return 0;
}

PyObject *DBC_get_opvalue(dvm_DBCObject *self, PyObject* args)
{
    return Py_BuildValue("i", self->d->get_opvalue());
}

PyObject *DBC_get_length(dvm_DBCObject *self, PyObject* args)
{
    return Py_BuildValue("i", self->d->get_length());
}

PyObject *DBC_get_name(dvm_DBCObject *self, PyObject* args)
{
    return PyString_FromString( self->d->get_opname() );
}

PyObject *DBC_get_operands(dvm_DBCObject *self, PyObject* args)
{
    if (self->operands != NULL) {
        Py_INCREF( self->operands );
        return self->operands;
    }

    self->operands = PyList_New( 0 );
    int present; 

    for(int ii=1; ii < self->d->voperands->size(); ii++) {
        PyObject *ioperands = PyList_New( 0 );
        present = -1;

        if ((*self->d->vdescoperands)[ii] == FIELD) {
            PyList_Append( ioperands, PyString_FromString( "field@" ) ); present = 0;
        } else if ((*self->d->vdescoperands)[ii] == METHOD) {
            PyList_Append( ioperands, PyString_FromString( "meth@" ) ); present = 0;
        } else if ((*self->d->vdescoperands)[ii] == TYPE) {
            PyList_Append( ioperands, PyString_FromString( "type@" ) ); present = 0;
        } else if ((*self->d->vdescoperands)[ii] == INTEGER) {
            PyList_Append( ioperands, PyString_FromString( "#+" ) );
        } else if ((*self->d->vdescoperands)[ii] == STRING) {
            PyList_Append( ioperands, PyString_FromString( "string@" ) ); present = 0;
        } else if ((*self->d->vdescoperands)[ii] == INTEGER_BRANCH) {
            PyList_Append( ioperands, PyString_FromString( "+" ) );
        } else {
            PyList_Append( ioperands, PyString_FromString( "v" ) );
        }
        
        PyList_Append( ioperands, PyInt_FromLong( (*self->d->voperands)[ii] ) );
        
        if (present==0 && self->d->vstrings != NULL) {
            for(int jj=0; jj < self->d->vstrings->size(); jj++) {
                PyList_Append( ioperands, PyString_FromString( (*self->d->vstrings)[jj].c_str() ) );
            }

            present = -1;
        }

        Py_INCREF( ioperands );
        PyList_Append( self->operands, ioperands );
    }

    Py_INCREF( self->operands );
    return self->operands;
}

PyObject *DBC_get_type_ins(dvm_DBCObject *self, PyObject* args)
{
    return Py_BuildValue("i", 0);
}

void DBCSpe_dealloc(dvm_DBCSpeObject* self)
{
#ifdef DEBUG_DESTRUCTOR
    cout << "DBCSpe_dealloc\n";
#endif

    delete self->d;
    self->ob_type->tp_free((PyObject*)self);
}

PyObject *DBCSpe_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    dvm_DBCSpeObject *self;

    self = (dvm_DBCSpeObject *)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->d = NULL;
    }

    return (PyObject *)self;
}

int DBCSpe_init(dvm_DBCSpeObject *self, PyObject *args, PyObject *kwds)
{
    return 0;
}

PyObject *DBCSpe_get_opvalue(dvm_DBCSpeObject *self, PyObject* args)
{
    return Py_BuildValue("i", -1);
}

PyObject *DBCSpe_get_name(dvm_DBCSpeObject *self, PyObject* args)
{
    return PyString_FromString( self->d->get_opname() );
}

PyObject *DBCSpe_get_operands(dvm_DBCSpeObject *self, PyObject* args)
{
    if (self->d->get_type() == 0) {
        FillArrayData *fad = reinterpret_cast<FillArrayData *>( self->d );
        return PyString_FromStringAndSize( fad->data, fad->data_size );
    } else if (self->d->get_type() == 1) {
        SparseSwitch *ss = reinterpret_cast<SparseSwitch *>( self->d );
        
        PyObject *operands = PyList_New( 0 );
        
        PyObject *ioperands = PyList_New( 0 );
        for (int ii = 0; ii < ss->keys.size(); ii++)
            PyList_Append( ioperands, PyInt_FromLong( ss->keys[ii] ) );
        PyList_Append( operands, ioperands );
      
        ioperands = PyList_New( 0 );
        for (int ii = 0; ii < ss->targets.size(); ii++)
            PyList_Append( ioperands, PyInt_FromLong( ss->targets[ii] ) );
        PyList_Append( operands, ioperands );

        return operands;
    } else if (self->d->get_type() == 2) {
        PackedSwitch *ps = reinterpret_cast<PackedSwitch *>( self->d );
        
        PyObject *operands = PyList_New( 0 );
        PyList_Append( operands, PyInt_FromLong( ps->pst.first_key ) );
      
        PyObject *ioperands = PyList_New( 0 );
        for (int ii = 0; ii < ps->targets.size(); ii++)
            PyList_Append( ioperands, PyInt_FromLong( ps->targets[ii] ) );
        PyList_Append( operands, ioperands );

        return operands;
    }

    Py_INCREF(Py_None);                                                                                                                                                                      
    return Py_None;
}

PyObject *DBCSpe_get_targets(dvm_DBCSpeObject *self, PyObject* args)
{
    if (self->d->get_type() == 1) {
        SparseSwitch *ss = reinterpret_cast<SparseSwitch *>( self->d );
        
        PyObject *operands = PyList_New( 0 );
        for (int ii = 0; ii < ss->targets.size(); ii++)
            PyList_Append( operands, PyInt_FromLong( ss->targets[ii] ) );

        return operands;
    } else if (self->d->get_type() == 2) {
        PackedSwitch *ps = reinterpret_cast<PackedSwitch *>( self->d );
        
        PyObject *operands = PyList_New( 0 );
        for (int ii = 0; ii < ps->targets.size(); ii++)
            PyList_Append( operands, PyInt_FromLong( ps->targets[ii] ) );

        return operands;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *DBCSpe_get_length(dvm_DBCSpeObject *self, PyObject* args)
{
    return Py_BuildValue("i", self->d->get_length());
}

PyObject *DBCSpe_get_type_ins(dvm_DBCSpeObject *self, PyObject* args)
{
    return Py_BuildValue("i", 1);
}

typedef struct {
    PyObject_HEAD;
    DalvikBytecode *dparent;
    DCode *d;
    PyObject *bytecodes_list;
    PyObject *bytecodes_spe_list;
} dvm_DCodeObject;

static void
DCode_dealloc(dvm_DCodeObject* self)
{
#ifdef DEBUG_DESTRUCTOR
    cout << "DCode_dealloc\n";
#endif
    delete self->d;
    self->ob_type->tp_free((PyObject*)self);
}

static PyObject *DCode_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    dvm_DCodeObject *self;

    self = (dvm_DCodeObject *)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->d = NULL;
        self->bytecodes_list = NULL;
        self->bytecodes_spe_list = NULL;
    }

    return (PyObject *)self;
}

static int
DCode_init(dvm_DCodeObject *self, PyObject *args, PyObject *kwds)
{
    const char *code;
    size_t code_len;

    if (self != NULL) {
        int ok = PyArg_ParseTuple( args, "s#", &code, &code_len);
        if(!ok) return -1;
    

        self->d = self->dparent->new_code( code, code_len );
    }

    return 0;
}

static PyObject *DCode_get_nb_bytecodes(dvm_DCodeObject *self, PyObject* args)
{
    return Py_BuildValue("i", self->d->size());
}

static PyObject *DCode_get_bytecodes(dvm_DCodeObject *self, PyObject* args)
{
    if (self->bytecodes_list != NULL) {
        Py_INCREF( self->bytecodes_list );
        return self->bytecodes_list;
    }

    self->bytecodes_list = PyList_New( 0 );

    for (int ii=0; ii < self->d->bytecodes.size(); ii++) {
        PyObject *nc = DBC_new(&dvm_DBCType, NULL, NULL);
        dvm_DBCObject *dc = (dvm_DBCObject *)nc;

        dc->d = self->d->bytecodes[ii];

        Py_INCREF( nc );

        PyList_Append( self->bytecodes_list, nc );
    }
   
    Py_INCREF( self->bytecodes_list );
    return self->bytecodes_list;
}

static PyObject *DCode_get_bytecodes_spe(dvm_DCodeObject *self, PyObject* args)
{
    if (self->bytecodes_spe_list != NULL) {
        Py_INCREF( self->bytecodes_spe_list );
        return self->bytecodes_spe_list;
    }

    self->bytecodes_spe_list = PyList_New( 0 );
    
    for (int ii=0; ii < self->d->bytecodes_spe.size(); ii++) {
        PyObject *nc = DBCSpe_new(&dvm_DBCSpeType, NULL, NULL);
        dvm_DBCSpeObject *dc = (dvm_DBCSpeObject *)nc;

        dc->d = self->d->bytecodes_spe[ii];

        Py_INCREF( nc );

        PyList_Append( self->bytecodes_spe_list, nc );
    }

    Py_INCREF( self->bytecodes_spe_list );
    return self->bytecodes_spe_list;
}

static PyMethodDef DCode_methods[] = {
    {"get_nb_bytecodes",  (PyCFunction)DCode_get_nb_bytecodes, METH_NOARGS, "get nb bytecodes" },
    {"get_bytecodes",  (PyCFunction)DCode_get_bytecodes, METH_NOARGS, "get nb bytecodes" },
    {"get_bytecodes_spe",  (PyCFunction)DCode_get_bytecodes_spe, METH_NOARGS, "get nb bytecodes" },
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyTypeObject dvm_DCodeType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "dvm.DCode",             /*tp_name*/
    sizeof(dvm_DCodeObject), /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)DCode_dealloc,                         /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,        /*tp_flags*/
    "DCode objects",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    DCode_methods,             /* tp_methods */
    NULL,             /* tp_members */
    NULL,            /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)DCode_init,      /* tp_init */
    0,                         /* tp_alloc */
    DCode_new,                 /* tp_new */
};

typedef struct {
    PyObject_HEAD;
    DalvikBytecode *d;
} dvm_DalvikBytecodeObject;

static void
DalvikBytecode_dealloc(dvm_DalvikBytecodeObject* self)
{
#ifdef DEBUG_DESTRUCTOR
    cout << "DalvikBytecode_dealloc\n";
#endif
    delete self->d;
    self->ob_type->tp_free((PyObject*)self);
}

static PyObject *DalvikBytecode_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    dvm_DalvikBytecodeObject *self;

    self = (dvm_DalvikBytecodeObject *)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->d = NULL;
    }

    return (PyObject *)self;
}

static int
DalvikBytecode_init(dvm_DalvikBytecodeObject *self, PyObject *args, PyObject *kwds)
{
    if (self != NULL)
        self->d = new DalvikBytecode();
    
    return 0;
}

static PyObject *DalvikBytecode_new_code(dvm_DalvikBytecodeObject *self, PyObject* args)
{
    //cout<<"Called new code()\n"; 

    PyObject *nc = DCode_new(&dvm_DCodeType, NULL, NULL);
 
    dvm_DCodeObject *dnc = (dvm_DCodeObject *)nc;

    dnc->dparent = self->d;
    DCode_init( (dvm_DCodeObject *)nc, args, NULL );
   
    return nc;
}

static PyMethodDef DalvikBytecode_methods[] = {
    {"new_code",  (PyCFunction)DalvikBytecode_new_code, METH_VARARGS, "new code" },
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyTypeObject dvm_DalvikBytecodeType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "dvm.DalvikBytecode",             /*tp_name*/
    sizeof(dvm_DalvikBytecodeObject), /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)DalvikBytecode_dealloc,                         /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,        /*tp_flags*/
    "DalvikBytecode objects",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    DalvikBytecode_methods,             /* tp_methods */
    NULL,              /* tp_members */
    NULL,            /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)DalvikBytecode_init,      /* tp_init */
    0,                         /* tp_alloc */
    DalvikBytecode_new,                 /* tp_new */
};

static PyMethodDef dvm_methods[] = {
    {NULL}  /* Sentinel */
};

extern "C" PyMODINIT_FUNC initdvmnative(void) {
    PyObject *m;

    dvm_DalvikBytecodeType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&dvm_DalvikBytecodeType) < 0)
        return;

    dvm_DCodeType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&dvm_DCodeType) < 0)
        return;

    dvm_DBCType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&dvm_DBCType) < 0)
        return;

    dvm_DBCSpeType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&dvm_DBCSpeType) < 0)
        return;
    
    m = Py_InitModule3("dvmnative", dvm_methods, "Example module that creates an extension type.");

    Py_INCREF(&dvm_DalvikBytecodeType);
    PyModule_AddObject(m, "DalvikBytecode", (PyObject *)&dvm_DalvikBytecodeType);
    
    Py_INCREF(&dvm_DCodeType);
    PyModule_AddObject(m, "DCode", (PyObject *)&dvm_DCodeType);
    
    Py_INCREF(&dvm_DBCType);
    PyModule_AddObject(m, "DBC", (PyObject *)&dvm_DBCType);
    
    Py_INCREF(&dvm_DBCSpeType);
    PyModule_AddObject(m, "DBCSpe", (PyObject *)&dvm_DBCSpeType);
}

