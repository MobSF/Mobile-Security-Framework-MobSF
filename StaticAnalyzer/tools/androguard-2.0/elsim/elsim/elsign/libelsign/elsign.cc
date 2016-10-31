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

#include "elsign.h"

Elsign::Elsign() {
    this->db.log = 0;

    this->nb_signatures = 0;
    
    this->minimum_len_signature = 0;
    this->cut_element = 1;
    
    /* Default values */
    threshold_value_low = 0.2;
    threshold_value_high = 0.3;
    cluster_npass = 1;
    cluster_ncols = 0;
    cluster_dist = 'e';
    cluster_method = 'm';

    cluster_weight = NULL;

    /* Setup aho corasick */
    aho = ac_index_new();
    /* Set the default compressor : Snappy */
    set_compress_type( TYPE_SNAPPY );

    this->raz();
}

const char *Elsign::get_name_result() {
    MSignature *s;

    if (this->reverse_signatures.count( this->result_signature ) > 0 ) {
        s = this->reverse_signatures[ this->result_signature ];
        return s->name->c_str();
    }

    return NULL;
}

void Elsign::set_sim_method(int value) {
    if (this->db.log) {
        printf("SIM METHOD = %d\n", value);
    }

    this->sim_method = value;
}
        
void Elsign::set_ncd_compression_algorithm(int value) {
    set_compress_type( value );
}


int Elsign::set_debug_log(int value) {
    if (value > 0) {
        this->db.log = 1;
    } else {
        this->db.log = 0;
    }

    return 0;
}

int Elsign::set_weight(double *w, int size) {
    int i;

    if (cluster_weight != NULL) {
        free(cluster_weight);
    }

    cluster_ncols = size;
    cluster_weight = (double *)malloc(cluster_ncols*sizeof(double));

    for(i=0; i < size; i++) {
        if (this->db.log) {
            printf("ADD WEIGHT %d -> %f\n", i, w[ i ]);
        }
        cluster_weight[ i ] = w[ i ];
    }

    return 0;
}

int Elsign::set_distance(char c) {
    cluster_dist = c;

    if (this->db.log) {
        printf("DIST = %c\n", cluster_dist);
    }

    return 0;
}

int Elsign::set_method(char c) {
    cluster_method = c;

    if (this->db.log) {
        printf("METHOD = %c\n", cluster_method);
    }

    return 0;
}


void Elsign::set_threshold_low(float value) {
    threshold_value_low = value;

    if (this->db.log) {
        printf("THRESHOLD LOW = %f\n", value);
    }
}

void Elsign::set_threshold_high(float value) {
    threshold_value_high = value;

    if (this->db.log) {
        printf("THRESHOLD HIGH = %f\n", value);
    }
}

void Elsign::set_npass(int value) {
    cluster_npass = value;
}

int Elsign::new_id() {
    return this->nb_signatures++;
}

int Elsign::add_signature(char *name, unsigned int name_size, char *formula, unsigned int formula_size, vector<Signature *> *sub_signatures) {
    MSignature *smain = new MSignature();

    /* (formula == 1) -> signature found */
    smain->formula = new Formula(string(formula, formula_size), sub_signatures->size());

    /* create new id */
    unsigned int id_link = this->new_id();
    unsigned int value_link = (*sub_signatures).size();
    
    if (this->db.log) {
        cout << "ADD SIGN " << name << " " << name_size << " " << id_link << " " << formula <<  "\n";
    }

    /* udpate all signatures with a valid id */
    for (unsigned int ii=0; ii < (*sub_signatures).size(); ii++) {
        unsigned int id = this->new_id();
        Signature *s = (*sub_signatures)[ii];

        this->update_sub_signature( s, id, id_link, value_link );
        s->pos = (int) ii;
    }

    smain->name = new string(name, name_size);
    smain->sub_signatures = sub_signatures;
    this->signatures.push_back( smain );
    this->reverse_signatures[ id_link ] = smain;

    return id_link;
}

Signature *Elsign::create_sub_signature(const char *input, unsigned int input_size, vector<double> *ets) {
    if (this->db.log) {
        cout << "CREATE SUB SIGN " << input_size << "\n";
    }
    
    Signature *s1 = new Signature();
    s1->type = 0;
    s1->value = string(input, input_size);
    
    double elem_entropy = entropy( (void *)input, input_size );
    
    ets->insert( ets->begin(), elem_entropy );
    s1->ets = ets; 
    
    s1->used = 1;

    entropies_hashmap_sign_ncd[ s1 ] = elem_entropy;

    if (this->minimum_len_signature == 0)
        this->minimum_len_signature = input_size;

    if (input_size < this->minimum_len_signature)
        this->minimum_len_signature = input_size;

    return s1;
}

void Elsign::update_sub_signature(Signature *s, unsigned int id, unsigned int id_link, unsigned int value_link) {
    if (this->db.log) {
        cout << "UPDATE SUB SIGN " << id << "\n";
    }
    s->id = id;
    s->link = id_link;
}

int Elsign::add_element(const char *input, unsigned int input_size, vector<double> *ets) {
    
    if (this->db.log) {
        cout << "ADD ELEMENT " << input_size << "\n";
    }
   
    if (this->cut_element) {
        if (input_size < (this->minimum_len_signature * 0.5))
        {
            if (this->db.log) {
                cout << "CUT ELEMENT " << "\n";
            }

            return -1;
        }
    }

    double elem_entropy = entropy( (void *)input, input_size );

    Signature *s1 = new Signature();
    s1->id = this->db.elem; 
    s1->type = 1;
    s1->value = string(input, input_size);
    
    ets->insert( ets->begin(), elem_entropy );
    s1->ets = ets;

    entropies_hashmap_elem[ s1 ] = elem_entropy;

    this->db.elem += 1;

    return s1->id;
}

/*
int Elsign::add_sign_string(unsigned int id, unsigned int id_link, unsigned int value_link, const char *input, size_t input_size) {
    Signature *s1 = new Signature();
    s1->id = id;

    s1->type = 0;
    s1->value = string(input, input_size);
    s1->link = id_link;


    if (dt.log) {
        cout << "ADD SIGN STRING " << s1->id << " " << s1->type << " " << s1->link <<  " " << value_link << "\n";
    }

    ac_index_enter( aho, (ac_symbol *)input, input_size, s1 );

    return 0;
}
*/

int Elsign::fix() {
    /* Fix Aho Corasick algorithm */
    ac_index_fix( aho );
    return 0;
}

int Elsign::check() {
    int ret = -1;

    ClusterInfo *ci = new ClusterInfo();

    if (this->clustering_init_rows(ci) == 0) {
      this->clustering(ci);
      if (this->sim_method == NCD_METHOD) {
          ret = this->check_sim(ci);
      }
      
      delete ci;
    }
   

    return ret;
}

int Elsign::check_all() {
    int ret = -1;

    ClusterInfo *ci = new ClusterInfo();

    if (this->clustering_init_rows(ci) == 0) {
      this->clustering(ci);
      if (this->sim_method == NCD_METHOD) {
        ret = this->check_sim_all(ci);
      } 
    
      delete ci;
    }

    return ret;
}

int Elsign::check_string(const char *input, size_t input_size) {
    int ret = -1;

    ret = check_elem_string( input, input_size );

    return ret;
}

int Elsign::clustering_init_rows(ClusterInfo *ci) {
    if (this->db.log) {
        cout << "Clustering init rows\n";
    }
    
    if (entropies_hashmap_sign_ncd.size() == 0)
        return -1;

    /* Fix Cluster */
    this->set_npass( entropies_hashmap_sign_ncd.size() );
    
    ci->nrows = this->entropies_hashmap_sign_ncd.size() + this->entropies_hashmap_elem.size();
    
    if (this->db.log) {
        cout << "ROWS " << ci->nrows << "\n";
    }
    
    return 0;
}

int Elsign::clustering(ClusterInfo *ci) {
    int ret = -1;
    
    double** data = (double **)malloc(ci->nrows*sizeof(double*));
    int** mask = (int **)malloc(ci->nrows*sizeof(int*));

    if (data == NULL || mask == NULL)
        return -2;

    int i = 0;
    int j = 0;
    for (i = 0; i < ci->nrows; i++)
    { 
        data[i] = (double *)malloc(cluster_ncols*sizeof(double));
        if (data[i] == NULL)
            return -2;

        mask[i] = (int *)malloc(cluster_ncols*sizeof(int));
        if (mask[i] == NULL)
            return -2;
    }

    ////////////////////////////////////////////
    if (this->db.log) {
        cout << "ADD SIGNATURES\n";
    }

    i = 0;
    for (sparse_hash_map<Signature *, double>::const_iterator it = entropies_hashmap_sign_ncd.begin(); it != entropies_hashmap_sign_ncd.end(); ++it) {
        for(unsigned int ii = 0; ii < it->first->ets->size(); ii++) {
            data[ i ][ ii ] = (double)(*it->first->ets)[ ii ];
            mask[ i ][ ii ] = 1;
        }

        ci->cluster_id_hashmap[ i ] = it->first;
        i += 1;
    }

    ///////////////////////////////////////////
    if (this->db.log) {
        cout << "ADD ELEMENTS\n";
    }

    for (sparse_hash_map<Signature *, double>::const_iterator it = entropies_hashmap_elem.begin(); it != entropies_hashmap_elem.end(); ++it) {
        for(unsigned int ii = 0; ii < it->first->ets->size(); ii++) {
            data[ i ][ ii ] = (double)(*it->first->ets)[ ii ];
            mask[ i ][ ii ] = 1;
        }

        ci->cluster_id_hashmap[ i ] = it->first;
        i += 1;
    }

    /* Determine the number of clusters by using a classical formula */
    int nclusters = (int)sqrt( ci->nrows );
    int transpose = 0;
    int ifound = 0;
    double error;
    
    ci->clusterid = (int *)malloc(ci->nrows * sizeof(int));

    if (ci->clusterid == NULL) {
        return -2;
    }

    if (this->db.log) {
        cout << "CLUSTERING .." << ci->nrows << " " << cluster_ncols << "\n";
    }

    this->db.nbclusters = nclusters;
    kcluster(nclusters, ci->nrows, cluster_ncols, data, mask, cluster_weight, transpose, cluster_npass, cluster_method, cluster_dist, ci->clusterid, &error, &ifound);

    if (this->db.log) {
        cout << "Solution found " << ifound << " times; within-cluster sum of distances is " << error << "\n";
        cout << "Cluster assignments:\n";

        for (i = 0; i < ci->nrows; i++)
            cout << "cluster " << ci->clusterid[i] << " " << ci->cluster_id_hashmap[ i ]->id << "\n";
    }

    double **distMatrix;
    distMatrix = distancematrix(ci->nrows, cluster_ncols, data, mask, cluster_weight, 'e', 0);
    if (!distMatrix) {
        return -2;
    }

    for(i=0; i < ci->nrows; i++) {
        for(j=0; j<i; j++) {
            if (distMatrix[i][j] == 0.0) {
                if (ci->cluster_id_hashmap[ i ]->type == 0 ) {
                    if (this->db.log) {
                        cout << "DISTMATRIX ADD CLUSTER " <<  ci->clusterid[i] << "\n";
                    }
                    ci->SScluster.push_back( ci->clusterid[i] );
                    ci->sign_clusters[ ci->clusterid[i] ] = 1;
                }
                else if (ci->cluster_id_hashmap[ j ]->type == 0 ) {
                    if (this->db.log) {
                        cout << "DISTMATRIX ADD CLUSTER " << ci->clusterid[j] << "\n";
                    }
                    ci->SScluster.push_back( ci->clusterid[j] );
                    ci->sign_clusters[ ci->clusterid[j] ] = 1;
                }

            }    
        }                                            
    }

    for(i = 0; i < ci->nrows; i++){
        free(distMatrix[i]);
    }
    free(distMatrix);

    ////////////////////////////////////////////////////////////////////// 

    for (i = 0; i < ci->nrows; i++) {
        if (ci->cluster_id_hashmap[ i ]->type == 0) {
            if (ci->sign_clusters.count( ci->clusterid[i] ) == 1)
                continue;
            ci->SScluster.push_back( ci->clusterid[i] );
            ci->sign_clusters[ ci->clusterid[i] ] = 1;
        }
    }

    this->db.nbcmpclusters = ci->SScluster.size();
    if (this->db.log) {
        cout << "CLUSTER SIZE = " << ci->SScluster.size() << "\n";
    }

    for (i = 0; i < ci->nrows; i++) {   
        free(data[i]);
        free(mask[i]);
    }

    free(data);
    free(mask);

    return ret;
}

int Elsign::check_sim(ClusterInfo *ci) {
    int ret = -1;
    int i;

    for(unsigned int ii=0; ii < ci->SScluster.size(); ii++) {
        vector<Signature *> SSsign;
        vector<Signature *> SSelem;
        for (i = 0; i < ci->nrows; i++) {
            if (ci->clusterid[i] == ci->SScluster[ii]) {
                if (ci->cluster_id_hashmap[ i ]->type == 0) {
                    SSsign.push_back( ci->cluster_id_hashmap[ i ] );
                } else {
                    SSelem.push_back( ci->cluster_id_hashmap[ i ] );
                }
            }
        }

        if (this->db.log) {
            cout << "CLUSTER " << ci->SScluster[ii] << " SIGN " << SSsign.size() << " ELEM " << SSelem.size() << "\n";
        }

        for(unsigned int jj=0; jj < SSelem.size(); jj++) {
            ret = this->check_elem_ncd( SSsign, SSelem[ jj ] );
            if (ret == 0) {
                break;
            }
        }

        /* Ok we found a valid signature !, go out ! */
        if (ret == 0) {
            SSsign.clear();
            SSelem.clear();
            break;
        }

        SSsign.clear();
        SSelem.clear();
    }

    return ret;
}

int Elsign::check_sim_all(ClusterInfo *ci) {
    int ret = -1;
    int i;

    for(unsigned int ii=0; ii < ci->SScluster.size(); ii++) {
        vector<Signature *> SSsign;
        vector<Signature *> SSelem;
        for (i = 0; i < ci->nrows; i++) {
            if (ci->clusterid[i] == ci->SScluster[ii]) {
                if (ci->cluster_id_hashmap[ i ]->type == 0) {
                    SSsign.push_back( ci->cluster_id_hashmap[ i ] );
                } else {
                    SSelem.push_back( ci->cluster_id_hashmap[ i ] );
                }
            }
        }

        if (this->db.log) {
            cout << "CLUSTER " << ci->SScluster[ii] << " SIGN " << SSsign.size() << " ELEM " << SSelem.size() << "\n";
        }

        for(unsigned int jj=0; jj < SSelem.size(); jj++) {
            this->check_elem_ncd_all( SSsign, SSelem[ jj ] );
        }

        SSsign.clear();
        SSelem.clear();
    }

    return ret;
}

int Elsign::raz() {
    /* RAZ debug */
    this->db.raz();

    /* RAZ elements */
    for (sparse_hash_map<Signature *, double>::const_iterator it = entropies_hashmap_elem.begin(); it != entropies_hashmap_elem.end(); ++it) {                                    
        it->first->ets->clear();
        delete it->first->ets;

        /* RAZ element */
        delete it->first;
    }
    entropies_hashmap_elem.clear();

    for (sparse_hash_map<Signature *, double>::const_iterator it = entropies_hashmap_sign_ncd.begin(); it != entropies_hashmap_sign_ncd.end(); ++it) {
        it->first->used = 1;
    }

    /* Clear formula */
    for (unsigned int ii = 0; ii < this->signatures.size(); ii++) {
        MSignature *s = this->signatures[ii];
        s->formula->raz();
    }

    /* Clear caches */
    if (ncd_hashmap.size() > CACHE_ELEM) {
        ncd_hashmap.clear();
    }

    if (compress_hashmap.size() > CACHE_ELEM) {
        compress_hashmap.clear();
    }

    this->raz_results();

    return 0;
}

int Elsign::raz_results() {
    for(unsigned int ii=0; ii < this->vector_result_signature.size(); ii++)
        delete this->vector_result_signature[ ii ];
    this->vector_result_signature.clear();

    this->result_signature = -1;

    return 0;
}

float Elsign::sign_ncd(string s1, string s2, int cache) {
    int ret;
    size_t corig = 0;
    size_t ccmp = 0;

    if (!cache && ncd_hashmap.count( s1 + s2 ) == 1) {
        return ncd_hashmap[ s1 + s2 ];
    }

    libsimilarity_t l1;

    l1.orig = (void *)s1.c_str();
    l1.size_orig = s1.size();

    l1.cmp = (void *)s2.c_str();
    l1.size_cmp = s2.size();

    if (!cache && compress_hashmap.count( s1 ) == 1) {
        corig = compress_hashmap[ s1 ];    
    }

    if (!cache && compress_hashmap.count( s2 ) == 1) {
        ccmp = compress_hashmap[ s2 ];    
    }

    l1.corig = &corig;
    l1.ccmp = &ccmp;

    ret = ncd( 9, &l1 );
    this->db.cmp += 1;

    // Add value in the hash map
    if (!cache && ret == 0) {
        ncd_hashmap[ s1 + s2 ] = l1.res;
        compress_hashmap[ s1 ] = *l1.corig;
        compress_hashmap[ s2 ] = *l1.ccmp;
    }

    return l1.res;
}


int Elsign::check_elem_string(const char *input, size_t input_size) {
    int ret = -1;

    ac_list*      results;
    ac_list_item* result_item = NULL;
    ac_result*    result = NULL;

    results = ac_list_new();
    ac_index_query( aho, (ac_symbol *)input, input_size, results );

    result_item = results->first;

    while (result_item) {
        result = (ac_result*) result_item->item;

        Signature *s1 = (Signature *)(result->object);
        //cout << "START " << result->start << " END " << result->end << " " << s1->id << "\n";

        add_result( s1->id );
        /*                r->id = s1->id;
                          r->value = 0;
                          r->start = result->start;
                          r->end = result->end;
                          r->next = NULL;                
                          */
        result_item = result_item->next;
        /*
           if (result_item) {
           r->next = (resultcheck_t *)malloc( sizeof(resultcheck_t) );
           r = r->next;
           }
           */
        ret = 0;
    }

    return ret;
}

int Elsign::check_elem_ncd(vector <Signature *> SS, Signature *s1) {
    float current_value;
    float min = 1.0;

    unsigned int ii;
    unsigned int pos_ii;
    for(ii=0; ii < SS.size(); ii++) {
        if (SS[ ii ]->used == 0)
            continue;

        current_value = sign_ncd( s1->value, SS[ ii ]->value, 0 );

        //printf("ALL VAL %d(%d) %d(%d) = %f\n", SS[ii]->id, SS[ ii ]->value.length(), s1->id, s1->value.length(), current_value);
        //cout << s1->value << " " << SS[ ii ]->value << "\n";

        if (current_value < min) {
            min = current_value;
            pos_ii = ii;
        }
    }

    if (min <= this->threshold_value_low) {
        this->vector_result_signature.push_back( new ResultSignature( SS[ pos_ii ]->link, SS[ pos_ii ]->id, min ) );
        SS[ pos_ii ]->used = 0;

        //printf("1 MATCH VAL %d(%d) %d(%d) = %f\n", SS[ pos_ii ]->id, SS[ pos_ii ]->value.length(), s1->id, s1->value.length(), current_value);
        
        MSignature *ms = this->reverse_signatures[ SS[ pos_ii ]->link ];
        ms->formula->set_value(SS[ pos_ii ]->pos, 1);
        if (ms->formula->eval() == 1) {
            this->result_signature = SS[ pos_ii ]->link;
            return 0;
        }
    }
    else if (min <= this->threshold_value_high) {
        set_compress_type( TYPE_BZ2 );
        current_value = sign_ncd( s1->value, SS[ pos_ii ]->value, 1 );
        set_compress_type( TYPE_SNAPPY );

        if (current_value <= this->threshold_value_low) {
            this->vector_result_signature.push_back( new ResultSignature( SS[ pos_ii ]->link, SS[ pos_ii ]->id, current_value ) );
            SS[ pos_ii ]->used = 0;

            //printf("2 MATCH VAL %d(%d) %d(%d) = %f\n", SS[ pos_ii ]->id, SS[ pos_ii ]->value.length(), s1->id, s1->value.length(), current_value);
        
            MSignature *ms = this->reverse_signatures[ SS[ pos_ii ]->link ];
            ms->formula->set_value(SS[ pos_ii ]->pos, 1);
            if (ms->formula->eval() == 1) {
                this->result_signature = SS[ pos_ii ]->link;
                return 0;
            }
        }
    }

    if ((min < 1.0) && (SS[ pos_ii ]->value.length() >= 10000)) {
        set_compress_type( TYPE_BZ2 );
        current_value = sign_ncd( s1->value, SS[ pos_ii ]->value, 1 );
        set_compress_type( TYPE_SNAPPY );

        if (current_value <= this->threshold_value_low) {
            this->vector_result_signature.push_back( new ResultSignature( SS[ pos_ii ]->link, SS[ pos_ii ]->id, current_value ) );
            SS[ pos_ii ]->used = 0;

            //printf("MATCH VAL %d(%d) %d(%d) = %f\n", SS[ pos_ii ]->id, SS[ pos_ii ]->value.length(), s1->id, s1->value.length(), current_value);
            MSignature *ms = this->reverse_signatures[ SS[ pos_ii ]->link ];
            ms->formula->set_value(SS[ pos_ii ]->pos, 1);
            if (ms->formula->eval() == 1) {
                this->result_signature = SS[ pos_ii ]->link;
                return 0;
            }
        }
    }

    return -1;
}

int Elsign::check_elem_ncd_all(vector <Signature *> SS, Signature *s1) {
    float current_value;

    unsigned int ii;
    for(ii=0; ii < SS.size(); ii++) {
        current_value = sign_ncd( s1->value, SS[ ii ]->value, 0 );
        if (current_value <= threshold_value_low)
        {
            MSignature *ms = this->reverse_signatures[ SS[ ii ]->link ];
            ms->formula->set_value(SS[ ii ]->pos, 1);
                
            if (ms->formula->eval() == 1) {
                this->vector_result_signature.push_back( new ResultSignature( SS[ ii ]->link, SS[ ii ]->id, s1->id, current_value ) );
                ms->formula->raz();
            }
        }
    }

    return 0;
}

void Elsign::add_result(unsigned int id) {
    resultcheck_t *t = (resultcheck_t *)malloc( sizeof(resultcheck_t) );
    t->id = id;

    vector_results.push_back( t );
}

void Elsign::add_result(unsigned int id, float value) {
    resultcheck_t *t = (resultcheck_t *)malloc( sizeof(resultcheck_t) );
    t->id = id;
    t->value = value;

    vector_results.push_back( t );
}

void Elsign::add_result(unsigned int id, unsigned int idref, float value) {
    resultcheck_t *t = (resultcheck_t *)malloc( sizeof(resultcheck_t) );
    t->id = id;
    t->rid = idref;
    t->value = value;

    vector_results.push_back( t );
}

/* PYTHON BINDING */
typedef struct {
    PyObject_HEAD;
    Elsign *s;
} sign_ElsignObject;

static void Elsign_dealloc(sign_ElsignObject* self)
{
    //cout<<"Called msign dealloc\n";
    delete self->s;
    self->ob_type->tp_free((PyObject*)self);
}

static PyObject *Elsign_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    sign_ElsignObject *self;

    self = (sign_ElsignObject *)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->s = NULL;
    }

    return (PyObject *)self;
}

static int Elsign_init(sign_ElsignObject *self, PyObject *args, PyObject *kwds)
{
    if (self != NULL) 
        self->s = new Elsign();

    return 0;
}

static PyObject *Elsign_set_sim_method(sign_ElsignObject *self, PyObject *args)
{
    int sim_method;

    if (self != NULL) {

        int ok = PyArg_ParseTuple( args, "i", &sim_method );
        if(!ok) return PyInt_FromLong(-1);

        self->s->set_sim_method( sim_method );
        return PyInt_FromLong(0);
    }

    return PyInt_FromLong(-1);
}

static PyObject *Elsign_set_threshold_low(sign_ElsignObject *self, PyObject *args)
{
    double threshold;

    if (self != NULL) {

        int ok = PyArg_ParseTuple( args, "d", &threshold);
        if(!ok) return PyInt_FromLong(-1);

        self->s->set_threshold_low( threshold );
        return PyInt_FromLong(0);
    }

    return PyInt_FromLong(-1);
}

static PyObject *Elsign_set_threshold_high(sign_ElsignObject *self, PyObject *args)
{
    double threshold;

    if (self != NULL) {

        int ok = PyArg_ParseTuple( args, "d", &threshold);
        if(!ok) return PyInt_FromLong(-1);

        self->s->set_threshold_high( threshold );
        return PyInt_FromLong(0);
    }

    return PyInt_FromLong(-1);
}

static PyObject *Elsign_set_distance(sign_ElsignObject *self, PyObject *args)
{
    char dist;

    if (self != NULL) {

        int ok = PyArg_ParseTuple( args, "c", &dist);
        if(!ok) return PyInt_FromLong(-1);

        self->s->set_distance( dist );
        return PyInt_FromLong(0);
    }

    return PyInt_FromLong(-1);
}

static PyObject *Elsign_set_method(sign_ElsignObject *self, PyObject *args)
{
    char method;

    if (self != NULL) {

        int ok = PyArg_ParseTuple( args, "c", &method);
        if(!ok) return PyInt_FromLong(-1);

        self->s->set_method( method );
        return PyInt_FromLong(0);
    }

    return PyInt_FromLong(-1);
}

static PyObject *Elsign_set_weight(sign_ElsignObject *self, PyObject *args)
{
    PyObject *weight_list;

    if (self != NULL) {

        int ok = PyArg_ParseTuple( args, "O", &weight_list);
        if(!ok) return PyInt_FromLong(-1);

        if ( !PyList_Check( weight_list ) ) {

            return PyInt_FromLong(-1);
        }

        int list_size = PyList_Size( weight_list );
        double *datas = (double *)malloc( list_size * sizeof( double ) );

        for(int i=0; i<list_size; i++) {
            PyObject * pyvalue = 0;

            pyvalue = PyList_GetItem(weight_list, i);
            double value = PyFloat_AsDouble( pyvalue );

            datas[ i ] = value;
        }

        self->s->set_weight( datas, list_size );

        free( datas );
        return PyInt_FromLong(0);
    }

    return PyInt_FromLong(-1);
}

static PyObject *Elsign_set_npass(sign_ElsignObject *self, PyObject *args)
{
    int npass;

    if (self != NULL) {

        int ok = PyArg_ParseTuple( args, "i", &npass );
        if(!ok) return PyInt_FromLong(-1);

        self->s->set_npass( npass );
        return PyInt_FromLong(0);
    }

    return PyInt_FromLong(-1);
}

static PyObject *Elsign_set_ncd_compression_algorithm(sign_ElsignObject *self, PyObject *args)
{
    int compression_algorithm;

    if (self != NULL) {

        int ok = PyArg_ParseTuple( args, "i", &compression_algorithm );
        if(!ok) return PyInt_FromLong(-1);

        self->s->set_ncd_compression_algorithm( compression_algorithm );
        return PyInt_FromLong(0);
    }

    return PyInt_FromLong(-1);
}

static PyObject *Elsign_add_signature(sign_ElsignObject *self, PyObject *args)
{
    char *name; unsigned int name_size;
    char *formula; unsigned int formula_size;

    PyObject *sub_list;
    if (self != NULL) {
        
        /* String/String/List */

        int ok = PyArg_ParseTuple( args, "s#s#O", &name, &name_size, &formula, &formula_size, &sub_list );
        if(!ok) return PyInt_FromLong(-1);

        if ( !PyList_Check( sub_list ) ) {
            return PyInt_FromLong(-1);
        }

        vector<Signature *> *sub_vector = new vector<Signature *>;

        int list_size = PyList_Size( sub_list );
        for(int i=0; i < list_size; i++) {
            PyObject *sub_list_item = PyList_GetItem(sub_list, i);

            PyObject *ets_list = PyList_GetItem(sub_list_item, 0);
            PyObject *string_sign = PyList_GetItem(sub_list_item, 1);

            vector<double> *ets_vector = new vector<double>;
            int ets_list_size = PyList_Size( ets_list );
            for(int j=0; j < ets_list_size; j++) {
                PyObject * pyvalue = 0;

                pyvalue = PyList_GetItem(ets_list, j);
                double value = PyFloat_AsDouble( pyvalue );

                ets_vector->push_back( value );
            }

            
            unsigned int input_size = PyString_Size( string_sign );
            char * input = PyString_AsString( string_sign );

            Signature *value = self->s->create_sub_signature( input, input_size, ets_vector );

            sub_vector->push_back( value );
        }

        int id = self->s->add_signature( name, name_size, formula, formula_size, sub_vector );
        return PyInt_FromLong(id);
    }

    return PyInt_FromLong(-1);
}

static PyObject *Elsign_add_element(sign_ElsignObject *self, PyObject *args)
{
    char *input; size_t input_size;
    PyObject *ets_list;

    if (self != NULL) {

        int ok = PyArg_ParseTuple( args, "s#O", &input, &input_size, &ets_list );
        if(!ok) return PyInt_FromLong(-1);

        if ( !PyList_Check( ets_list ) ) {
            return PyInt_FromLong(-1);
        }

        vector<double> *ets_vector = new vector<double>;

        int list_size = PyList_Size( ets_list );
        for(int i=0; i<list_size; i++) {
            PyObject * pyvalue = 0;

            pyvalue = PyList_GetItem(ets_list, i);
            double value = PyFloat_AsDouble( pyvalue );

            ets_vector->push_back( value );
        }

        int id = self->s->add_element( input, input_size, ets_vector );
        return PyInt_FromLong(id);
    }

    return PyInt_FromLong(-1);
}

static PyObject *Elsign_check(sign_ElsignObject *self, PyObject *args)
{
    PyObject *check_list = PyList_New( 0 );

    if (self != NULL) {

        self->s->check();

        const char *name = self->s->get_name_result();

        if (name == NULL) {
            PyList_Append( check_list, Py_None );
        } else {
            PyList_Append( check_list, PyString_FromString( name ) );
        }

        for(unsigned int ii = 0; ii < self->s->vector_result_signature.size(); ii++) {
            PyObject *icheck_list = PyList_New( 0 );

            PyList_Append( icheck_list, PyInt_FromLong( self->s->vector_result_signature[ ii ]->link ) );
            PyList_Append( icheck_list, PyInt_FromLong( self->s->vector_result_signature[ ii ]->id ) );
            PyList_Append( icheck_list, PyFloat_FromDouble( self->s->vector_result_signature[ ii ]->value ) );

            PyList_Append( check_list, icheck_list );
        }

        return check_list;
    }

    return check_list;
}

static PyObject *Elsign_check_all(sign_ElsignObject *self, PyObject *args)
{
    PyObject *check_list = PyList_New( 0 );

    if (self != NULL) {

        self->s->check_all();

        const char *name = self->s->get_name_result();

        if (name == NULL) {
            PyList_Append( check_list, Py_None );
        } else {
            PyList_Append( check_list, PyString_FromString( name ) );
        }

        for(unsigned int ii = 0; ii < self->s->vector_result_signature.size(); ii++) {
            PyObject *icheck_list = PyList_New( 0 );

            PyList_Append( icheck_list, PyInt_FromLong( self->s->vector_result_signature[ ii ]->link ) );
            PyList_Append( icheck_list, PyInt_FromLong( self->s->vector_result_signature[ ii ]->id ) );
            PyList_Append( icheck_list, PyInt_FromLong( self->s->vector_result_signature[ ii ]->id_cmp ) );
            PyList_Append( icheck_list, PyFloat_FromDouble( self->s->vector_result_signature[ ii ]->value ) );

            PyList_Append( check_list, icheck_list );
        }

        return check_list;
    }

    return check_list;
}

static PyObject *Elsign_get_debug(sign_ElsignObject *self, PyObject *args)
{
    PyObject *debug = PyList_New( 0 );

    if (self != NULL) {
        PyList_Append( debug, PyLong_FromLong( self->s->entropies_hashmap_sign_ncd.size() ) );
        PyList_Append( debug, PyLong_FromLong( self->s->db.nbclusters ) );
        PyList_Append( debug, PyLong_FromLong( self->s->db.nbcmpclusters ) );
        PyList_Append( debug, PyLong_FromLong( self->s->db.elem ) );
        PyList_Append( debug, PyLong_FromLong( self->s->db.cmp ) );
    }

    return debug;
}

static PyObject *Elsign_raz(sign_ElsignObject *self, PyObject *args)
{
    if (self != NULL) {
        self->s->raz();
        return PyInt_FromLong( 0 );
    }
    return PyInt_FromLong( -1 );
}

static PyObject *Elsign_raz_results(sign_ElsignObject *self, PyObject *args)
{
    if (self != NULL) {
        self->s->raz_results();
        return PyInt_FromLong( 0 );
    }
    return PyInt_FromLong( -1 );
}

static PyObject *Elsign_fix(sign_ElsignObject *self, PyObject *args)
{
    if (self != NULL) {
        self->s->fix();
        return PyInt_FromLong( 0 );
    }
    return PyInt_FromLong( -1 );
}

static PyObject *Elsign_set_debug_log(sign_ElsignObject *self, PyObject *args)
{
    int value;

    if (self != NULL) {

        int ok = PyArg_ParseTuple( args, "i", &value);
        if(!ok) return PyInt_FromLong(-1);

        self->s->set_debug_log( value );
        return PyInt_FromLong(0);
    }

    return PyInt_FromLong(-1);
}

static PyMethodDef Elsign_methods[] = {
    {"set_sim_method",  (PyCFunction)Elsign_set_sim_method, METH_VARARGS, "set sim method" },
    
    {"set_threshold_low",  (PyCFunction)Elsign_set_threshold_low, METH_VARARGS, "set threshold low" },
    {"set_threshold_high",  (PyCFunction)Elsign_set_threshold_high, METH_VARARGS, "set threshold high" },
    {"set_distance",  (PyCFunction)Elsign_set_distance, METH_VARARGS, "set dist" },
    {"set_method",  (PyCFunction)Elsign_set_method, METH_VARARGS, "set method" },
    {"set_weight",  (PyCFunction)Elsign_set_weight, METH_VARARGS, "set weight" },
    {"set_npass",  (PyCFunction)Elsign_set_npass, METH_VARARGS, "set npass" },
    {"set_debug_log",  (PyCFunction)Elsign_set_debug_log, METH_VARARGS, "set debug log" },
   
    {"set_ncd_compression_algorithm",  (PyCFunction)Elsign_set_ncd_compression_algorithm, METH_VARARGS, "set_ncd_compression_algorithm" },

    {"add_signature",  (PyCFunction)Elsign_add_signature, METH_VARARGS, "add signature" },
    {"add_element",  (PyCFunction)Elsign_add_element, METH_VARARGS, "add element" },
    {"check",  (PyCFunction)Elsign_check, METH_VARARGS, "check" },
    {"check_all",  (PyCFunction)Elsign_check_all, METH_VARARGS, "check_all" },

    {"get_debug",  (PyCFunction)Elsign_get_debug, METH_VARARGS, "get debug" },

    {"fix",  (PyCFunction)Elsign_fix, METH_NOARGS, "fix" },
    {"raz",  (PyCFunction)Elsign_raz, METH_NOARGS, "raz" },
    {"raz_results",  (PyCFunction)Elsign_raz_results, METH_NOARGS, "raz_results" },

    {NULL, NULL, 0, NULL}        /* Sentinel */
};

    static PyTypeObject sign_ElsignType = {
        PyObject_HEAD_INIT(NULL)
            0,                         /*ob_size*/
        "sign.Elsign",             /*tp_name*/
        sizeof(sign_ElsignObject), /*tp_basicsize*/
        0,                         /*tp_itemsize*/
        (destructor)Elsign_dealloc,                         /*tp_dealloc*/
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
        "Elsign objects",           /* tp_doc */
        0,                     /* tp_traverse */
        0,                     /* tp_clear */
        0,                     /* tp_richcompare */
        0,                     /* tp_weaklistoffset */
        0,                     /* tp_iter */
        0,                     /* tp_iternext */
        Elsign_methods,             /* tp_methods */
        NULL,             /* tp_members */
        NULL,           /* tp_getset */
        0,                         /* tp_base */
        0,                         /* tp_dict */
        0,                         /* tp_descr_get */
        0,                         /* tp_descr_set */
        0,                         /* tp_dictoffset */
        (initproc)Elsign_init,      /* tp_init */
        0,                         /* tp_alloc */
        Elsign_new,                 /* tp_new */
    };

PyObject *entropy(PyObject *self, PyObject* args)
{
    char *input; size_t input_size;

    int ok = PyArg_ParseTuple( args, "s#", &input, &input_size );
    if(!ok) return PyInt_FromLong(-1);

    double value = entropy( input, input_size );

    return PyFloat_FromDouble( value );
}

static PyMethodDef sign_methods[] = {
    {"entropy",  (PyCFunction)entropy, METH_VARARGS, "entropy" },
    {NULL}  /* Sentinel */
};

extern "C" PyMODINIT_FUNC initlibelsign(void) {
    PyObject *m;

    sign_ElsignType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&sign_ElsignType) < 0)
        return;

    m = Py_InitModule3("libelsign", sign_methods, "Elsign module.");

    Py_INCREF(&sign_ElsignType);
    PyModule_AddObject(m, "Elsign", (PyObject *)&sign_ElsignType);
}
