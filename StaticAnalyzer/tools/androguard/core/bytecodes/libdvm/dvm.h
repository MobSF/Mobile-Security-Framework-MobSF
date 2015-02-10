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
#ifndef DVM_H
#define DVM_H

#include <Python.h>

#ifdef __cplusplus

#include <iostream>
#include <string>
#include <vector>

#if defined __GNUC__ || defined __APPLE__
#include <ext/hash_map>
#else
#include <hash_map>
#endif

#include "buff.h"

#define OPVALUE 0
#define REGISTER 1
#define FIELD 2
#define METHOD 3
#define TYPE 4
#define INTEGER 5
#define STRING 6
#define INTEGER_BRANCH 7


//#define DEBUG_DESTRUCTOR
#undef DEBUG_DESTRUCTOR

using namespace __gnu_cxx;
using namespace std;
using std::cout;
using std::endl;

typedef struct fillarraydata {
    unsigned short ident;
    unsigned short element_width;
    unsigned int size;
} fillarraydata_t;

typedef struct sparseswitch {
    unsigned short ident;
    unsigned short size;
} sparseswitch_t;

typedef struct packedswitch {
    unsigned short ident;
    unsigned short size;
    unsigned int first_key;
} packedswitch_t;

class DBC {
    public :
        unsigned char op_value;
        const char *op_name;
        size_t op_length;
        vector<int> *voperands;
        vector<int> *vdescoperands;
        vector<string> *vstrings;

    public :
        DBC(unsigned char value, const char *name, vector<int> *v, vector<int> *vdesc, size_t length);
        ~DBC();
        int get_opvalue();
        const char *get_opname();
        size_t get_length();
};

class DBCSpe {  
    public :
        virtual const char *get_opname()=0;
        virtual size_t get_length()=0;
        virtual size_t get_type()=0;
};

class FillArrayData : public DBCSpe {
    public : 
        fillarraydata_t fadt;
        char *data;
        size_t data_size;
    public :
        FillArrayData(Buff *b, unsigned int off);
        ~FillArrayData();
        const char *get_opname();
        size_t get_length();
        size_t get_type();
};

class SparseSwitch : public DBCSpe {
    public : 
        sparseswitch_t sst;
        vector<int> keys;
        vector<int> targets;

    public :
        SparseSwitch(Buff *b, unsigned int off);
        ~SparseSwitch();
        const char *get_opname();
        size_t get_length();
        size_t get_type();
};

class PackedSwitch : public DBCSpe {
    public : 
        packedswitch_t pst;
        vector<int> targets;

    public :
        PackedSwitch(Buff *b, unsigned int off);
        ~PackedSwitch();
        const char *get_opname();
        size_t get_length();
        size_t get_type();
};

class DCode {
    public :
        vector<DBC *> bytecodes;
        vector<DBCSpe *> bytecodes_spe;

    public :
        DCode();
        ~DCode();
        DCode(vector<unsigned int(*)(Buff *, vector<int>*, vector<int>*)> *parsebytecodes,
              vector<void (*)(Buff *, vector<int> *, vector<int> *, vector<int> *, unsigned int *)> *postbytecodes,
              vector<const char *> *bytecodes_names,
              Buff *b);
        int size();
        DBC *get_bytecode_at(int i);
};

class DalvikBytecode {
    public :
        vector<unsigned int(*)(Buff *, vector<int>*, vector<int>*)> bytecodes;
        vector<void (*)(Buff *, vector<int> *, vector<int> *, vector<int> *, unsigned int *)> postbytecodes;

        vector<const char *> bytecodes_names;

    public :
        DalvikBytecode();
        DCode *new_code(const char *data, size_t data_len);
};

typedef struct {
    PyObject_HEAD;
    DBC *d;
    PyObject *operands;
} dvm_DBCObject;

PyObject *DBC_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
void DBC_dealloc(dvm_DBCObject* self);
PyObject *DBC_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
int DBC_init(dvm_DBCObject *self, PyObject *args, PyObject *kwds);
PyObject *DBC_get_opvalue(dvm_DBCObject *self, PyObject* args);
PyObject *DBC_get_length(dvm_DBCObject *self, PyObject* args);
PyObject *DBC_get_name(dvm_DBCObject *self, PyObject* args);
PyObject *DBC_get_operands(dvm_DBCObject *self, PyObject* args);
PyObject *DBC_get_type_ins(dvm_DBCObject *self, PyObject* args);

static PyMethodDef DBC_methods[] = {
    {"get_op_value",  (PyCFunction)DBC_get_opvalue, METH_NOARGS, "get nb bytecodes" },
    {"get_length",  (PyCFunction)DBC_get_length, METH_NOARGS, "get nb bytecodes" },
    {"get_name",  (PyCFunction)DBC_get_name, METH_NOARGS, "get nb bytecodes" },
    {"get_operands",  (PyCFunction)DBC_get_operands, METH_NOARGS, "get nb bytecodes" },
    {"get_type_ins",  (PyCFunction)DBC_get_type_ins, METH_NOARGS, "get type ins" },
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyTypeObject dvm_DBCType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "dvm.DBC",             /*tp_name*/
    sizeof(dvm_DBCObject), /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)DBC_dealloc,                         /*tp_dealloc*/
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
    "DBC objects",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    DBC_methods,             /* tp_methods */
    NULL,             /* tp_members */
    NULL,           /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)DBC_init,      /* tp_init */
    0,                         /* tp_alloc */
    DBC_new,                 /* tp_new */
};

typedef struct {
    PyObject_HEAD;
    DBCSpe *d;
} dvm_DBCSpeObject;

void DBCSpe_dealloc(dvm_DBCSpeObject* self);
PyObject *DBCSpe_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
int DBCSpe_init(dvm_DBCSpeObject *self, PyObject *args, PyObject *kwds);
PyObject *DBCSpe_get_opvalue(dvm_DBCSpeObject *self, PyObject* args);
PyObject *DBCSpe_get_name(dvm_DBCSpeObject *self, PyObject* args);
PyObject *DBCSpe_get_operands(dvm_DBCSpeObject *self, PyObject* args);
PyObject *DBCSpe_get_targets(dvm_DBCSpeObject *self, PyObject* args);
PyObject *DBCSpe_get_length(dvm_DBCSpeObject *self, PyObject* args);
PyObject *DBCSpe_get_type_ins(dvm_DBCSpeObject *self, PyObject* args);

static PyMethodDef DBCSpe_methods[] = {
    {"get_name",  (PyCFunction)DBCSpe_get_name, METH_NOARGS, "get nb bytecodes" },
    {"get_op_value",  (PyCFunction)DBCSpe_get_opvalue, METH_NOARGS, "get nb bytecodes" },
    {"get_operands",  (PyCFunction)DBCSpe_get_operands, METH_NOARGS, "get nb bytecodes" },
    {"get_targets",  (PyCFunction)DBCSpe_get_targets, METH_NOARGS, "get nb bytecodes" },
    {"get_length",  (PyCFunction)DBCSpe_get_length, METH_NOARGS, "get nb bytecodes" },
    {"get_type_ins",  (PyCFunction)DBCSpe_get_type_ins, METH_NOARGS, "get type ins" },
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyTypeObject dvm_DBCSpeType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "dvm.DBCSpe",             /*tp_name*/
    sizeof(dvm_DBCSpeObject), /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)DBCSpe_dealloc,                         /*tp_dealloc*/
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
    "DBC objects",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    DBCSpe_methods,             /* tp_methods */
    NULL,             /* tp_members */
    NULL,           /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)DBCSpe_init,      /* tp_init */
    0,                         /* tp_alloc */
    DBCSpe_new,                 /* tp_new */
};


#endif
#endif
