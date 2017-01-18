/* 
   This file is part of Elsim

   Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
   All rights reserved.

   ELsim is free software: you can redistribute it and/or modify
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

#include "formula.h"

Formula::Formula(string a, int nb) {
    this->formula_string = a;
    this->nb = nb;

    this->map = new vector<double *>;
    for(int i=0; i < nb; i++) {
        char tmp = 'a' + i;
        string tmp2;
        tmp2.push_back( tmp );
        //        cout << i << " " << tmp << " " << tmp2 << "\n";

        double *fVal = new double();
        *fVal = 0;
        this->p.DefineVar(tmp2.c_str(), fVal);
        this->map->push_back( fVal );
    }
}

void Formula::set_value(int pos, double value) {
    double *v  = (*this->map)[ pos ];

    //cout << "VALUE " << pos << " " << *v << " " << value << "\n";
    *v = value;
}

void Formula::raz() {
    for(unsigned int ii = 0; ii < this->map->size(); ii++) {
        double *v = (*this->map)[ii];
        *v = 0;
    }
}

int Formula::eval() {
    try
        {
            p.SetExpr(this->formula_string);
            return p.Eval();
        }
        catch (Parser::exception_type &e)
        {
            cout << e.GetMsg() << std::endl;
            return 0;
        }
}
