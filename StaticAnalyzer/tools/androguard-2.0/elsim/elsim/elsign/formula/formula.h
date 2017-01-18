/* 
   This file is part of Elsim

   Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
   All rights reserved.

   Elsim is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   Elsim is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of  
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with Elsim.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef FORMULA_H
#define FORMULA_H

#ifdef __cplusplus

#include "muParser.h"
#include <math.h>

#include <iostream>
#include <google/sparse_hash_map>
#include <string>
#include <vector>

#if defined __GNUC__ || defined __APPLE__
#include <ext/hash_map>
#else
#include <hash_map>
#endif

using namespace __gnu_cxx;
using namespace std;
using namespace mu;

using google::sparse_hash_map;      // namespace where class lives by default
using std::cout;
using std::endl;

class Formula {
    public :
        string formula_string;
        int nb;
        vector<double *> *map;
        Parser p;

    public :
        Formula(string, int);
        void set_value(int, double);
        void raz();
        int eval();
};

#endif

#endif
