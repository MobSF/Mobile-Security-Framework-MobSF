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

#ifndef ELSIGN_H
#define ELSIGN_H

#include <Python.h>

#ifdef __cplusplus

#include "formula.h"
#include "similarity.h"
#include "aho_corasick.h"
#include "cluster.h"
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
using google::sparse_hash_map;      // namespace where class lives by default
using std::cout;
using std::endl;

#define METHSIM_SIGNATURE 0
#define CLASSSIM_SIGNATURE 1
#define STRING_SIGNATURE 2

#define CACHE_ELEM 10000

class Signature {
    public :
        unsigned int id;
        unsigned int type;
        string value;
        vector<double> *ets;

        const char *input;
        size_t input_size;

        int pos;

        unsigned int link;
        unsigned int used;
};

class MSignature {
    public :
        string *name;
        Formula *formula;
        vector<Signature *> *sub_signatures;
};

class ResultSignature {
    public :
        int link;
        int id;
        int id_cmp;
    
        float value;
    public :
        ResultSignature(int id_link, int id, float value) {
            this->link = id_link;
            this->id = id;
            this->value = value;
        }
        ResultSignature(int id_link, int id, int id_cmp, float value) {
            this->link = id_link;
            this->id = id;
            this->id_cmp = id_cmp;
            this->value = value;
        }
};

class Debug {
    public :
        int log;
        unsigned int cmp;
        unsigned int elem;
        unsigned int nbclusters;
        unsigned int nbcmpclusters;


    public :
        Debug() {
            this->log = 0;
            this->cmp = 0;
            this->elem = 0;
            this->nbclusters = 0;
            this->nbcmpclusters = 0;
        }

        void raz() {
            //this->log = 0;
            this->cmp = 0;
            this->elem = 0;
            this->nbclusters = 0;
            this->nbcmpclusters = 0;
        }
};

struct resultcheck {
    unsigned int id;
    unsigned int rid;
    float value;

    unsigned int start;
    unsigned int end;

    struct resultcheck *next;
};


typedef struct resultcheck resultcheck_t;

class ClusterInfo {
    public :
    sparse_hash_map<int, Signature *> cluster_id_hashmap;
    sparse_hash_map<int, int> sign_clusters;
    vector<int> SScluster;
    int *clusterid;
    int nrows;

    public :
        ClusterInfo() {
            this->clusterid = NULL;
        }

        ~ClusterInfo() {
            if (this->clusterid != NULL)
                free(this->clusterid);
    
            this->sign_clusters.clear();
            this->SScluster.clear();
        }
};

ac_error_code
decref_result_object(void* item, void* data) {
    return AC_SUCCESS;
}

#define NCD_METHOD 0
#define STRING_METHOD 1

class Elsign {
    public :
        int sim_method;
        int cut_element;
        unsigned int minimum_len_signature;

        int nb_signatures;

        float threshold_value_low;
        float threshold_value_high;

        int cluster_npass;
        int cluster_ncols;
        char cluster_dist;
        char cluster_method;
        double *cluster_weight;

        ac_index *aho;

        vector<MSignature *> signatures;
        sparse_hash_map<int, MSignature *> reverse_signatures;

        sparse_hash_map<Signature *, double> entropies_hashmap_sign_ncd;
        sparse_hash_map<Signature *, double> entropies_hashmap_elem;

        sparse_hash_map<string, float> ncd_hashmap;
        sparse_hash_map<string, int> compress_hashmap;

        vector<Signature *> vector_elem_string;

        vector<resultcheck_t *> vector_results;

        int result_signature;
        vector<ResultSignature *> vector_result_signature;

        Debug db;

    public :
        Elsign();
        int set_debug_log(int value);
        int set_weight(double *w, int size);
        int set_distance(char c);
        int set_method(char c);
        void set_npass(int value);

        void set_sim_method(int value);
        
        void set_threshold_low(float value);
        void set_threshold_high(float value);
        
        void set_ncd_compression_algorithm(int value);

        int new_id();
        int add_signature(char *name, unsigned int name_size, char *formula, unsigned int formula_size, vector<Signature *> *sub_signatures);
        Signature *create_sub_signature(const char *input, unsigned int input_size, vector<double> *ets);
        void update_sub_signature(Signature *s, unsigned int id, unsigned int id_link, unsigned int value_link);

        int add_element(const char *input, unsigned int input_size, vector<double> *ets);

        const char *get_name_result();

        //int add_sign_sim(unsigned int id, unsigned int id_link, unsigned int value_link, const char *input, size_t input_size, vector<double> *ets);
        //int add_sign_string(unsigned int id, unsigned int id_link, unsigned int value_link, const char *input, size_t input_size);
        
        int fix();

        int check();
        int check_all();

        int check_string(const char *input, size_t input_size);

        int clustering_init_rows(ClusterInfo *ci);
        int clustering(ClusterInfo *ci);

        int check_sim(ClusterInfo *ci);
        int check_sim_all(ClusterInfo *ci);

        int check_asim();
        
        int raz();
        int raz_results();
        
        float sign_ncd(string s1, string s2, int cache);
        
        int add_elem_sim(unsigned int id, const char *input, size_t input_size, vector<double> *ets);
        
        int check_elem_string(const char *input, size_t input_size);
        int check_elem_ncd(vector <Signature *> SS, Signature *s1);
        int check_elem_ncd_all(vector <Signature *> SS, Signature *s1);
        
        void add_result(unsigned int id);
        void add_result(unsigned int id, float value);
        void add_result(unsigned int id, unsigned int idref, float value);
};
#endif

#endif
