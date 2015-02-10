/* 
 This file is part of Androguard.

 Copyright (C) 2011, Anthony Desnos <desnos at t0t0.fr>
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
#ifndef BUFF_H
#define BUFF_H

#ifdef __cplusplus

#if defined __GNUC__ || defined __APPLE__
#include <ext/hash_map>
#else
#include <hash_map>
#endif

#include <iostream>
#include <string>
#include <vector>

using namespace __gnu_cxx;
using namespace std;
using std::cout;
using std::endl;

class Buff {
    public :
        const char *bdata;
        size_t bdata_len;
        size_t bcurrent_idx;

        vector<unsigned int *> DynamicOffsets;
    public :
        Buff();
        Buff(const char *data, size_t data_len);
        Buff(const char *data, size_t data_len, size_t current_idx);
        void setup(const char *data, size_t data_len, size_t current_idx);
        const char *read(size_t len);
        const char *readat(size_t pos, size_t len);
        const char *read_false(size_t len);
        size_t get_current_idx();
        size_t get_end();
        bool empty();
        int register_dynamic_offset(unsigned int *addr);
        int set_idx(unsigned int);
        unsigned char read_uc();
        char read_c();
        unsigned long read_ul();
        unsigned int read_ui();
        unsigned short read_us();
};

#endif

#endif
