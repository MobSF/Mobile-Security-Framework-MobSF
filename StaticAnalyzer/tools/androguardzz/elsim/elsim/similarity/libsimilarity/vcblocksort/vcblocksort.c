#include "vcblocksort.h"

static int *I,                  /* group array, ultimately suffix array.*/
           *V,                          /* inverse array, ultimately inverse of I.*/
           r,                           /* number of symbols aggregated by transform.*/
           h;                           /* length of already-sorted prefixes.*/

#define KEY(p)          (V[*(p)+(h)])
#define SWAP(p, q)      (tmp=*(p), *(p)=*(q), *(q)=tmp)
#define MED3(a, b, c)   (KEY(a)<KEY(b) ?                        \
        (KEY(b)<KEY(c) ? (b) : KEY(a)<KEY(c) ? (c) : (a))       \
        : (KEY(b)>KEY(c) ? (b) : KEY(a)>KEY(c) ? (c) : (a)))

/* Subroutine for select_complearn_sort_split and complearn_sort_split. Sets group numbers for a
   group whose lowest position in I is pl and highest position is pm.*/

static void update_group(int *pl, int *pm)
{
    int g;

    g=pm-I;                      /* group number.*/
    V[*pl]=g;                    /* update group number of first position.*/
    if (pl==pm)
        *pl=-1;                   /* one element, sorted group.*/
    else
        do                        /* more than one element, unsorted group.*/
            V[*++pl]=g;            /* update group numbers.*/
        while (pl<pm);
}

/* Quadratic sorting method to use for small subarrays. To be able to update
   group numbers consistently, a variant of selection sorting is used.*/

static void select_complearn_sort_split(int *p, int n) {
    int *pa, *pb, *pi, *pn;
    int f, v, tmp;

    pa=p;                        /* pa is start of group being picked out.*/
    pn=p+n-1;                    /* pn is last position of subarray.*/
    while (pa<pn) {
        for (pi=pb=pa+1, f=KEY(pa); pi<=pn; ++pi)
            if ((v=KEY(pi))<f) {
                f=v;                /* f is smallest key found.*/
                SWAP(pi, pa);       /* place smallest element at beginning.*/
                pb=pa+1;            /* pb is position for elements equal to f.*/
            } else if (v==f) {     /* if equal to smallest key.*/
                SWAP(pi, pb);       /* place next to other smallest elements.*/
                ++pb;
            }
        update_group(pa, pb-1);   /* update group values for new group.*/
        pa=pb;                    /* continue sorting rest of the subarray.*/
    }
    if (pa==pn) {                /* check if last part is single element.*/
        V[*pa]=pa-I;
        *pa=-1;                   /* sorted group.*/
    }
}

/* Subroutine for complearn_sort_split, algorithm by Bentley & McIlroy.*/

static int choose_pivot(int *p, int n) {
    int *pl, *pm, *pn;
    int s;

    pm=p+(n>>1);                 /* small arrays, middle element.*/
    if (n>7) {
        pl=p;
        pn=p+n-1;
        if (n>40) {               /* big arrays, pseudomedian of 9.*/
            s=n>>3;
            pl=MED3(pl, pl+s, pl+s+s);
            pm=MED3(pm-s, pm, pm+s);
            pn=MED3(pn-s-s, pn-s, pn);
        }
        pm=MED3(pl, pm, pn);      /* midsize arrays, median of 3.*/
    }
    return KEY(pm);
}

/* Sorting routine called for each unsorted group. Sorts the array of integers
   (suffix numbers) of length n starting at p. The algorithm is a ternary-split
   quicksort taken from Bentley & McIlroy, "Engineering a Sort Function",
   Software -- Practice and Experience 23(11), 1249-1265 (November 1993). This
   function is based on Program 7.*/

static void complearn_sort_split(int *p, int n)
{
    int *pa, *pb, *pc, *pd, *pl, *pm, *pn;
    int f, v, s, t, tmp;

    if (n<7) {                   /* multi-selection sort smallest arrays.*/
        select_complearn_sort_split(p, n);
        return;
    }

    v=choose_pivot(p, n);
    pa=pb=p;
    pc=pd=p+n-1;
    while (1) {                  /* split-end partition.*/
        while (pb<=pc && (f=KEY(pb))<=v) {
            if (f==v) {
                SWAP(pa, pb);
                ++pa;
            }
            ++pb;
        }
        while (pc>=pb && (f=KEY(pc))>=v) {
            if (f==v) {
                SWAP(pc, pd);
                --pd;
            }
            --pc;
        }
        if (pb>pc)
            break;
        SWAP(pb, pc);
        ++pb;
        --pc;
    }
    pn=p+n;
    if ((s=pa-p)>(t=pb-pa))
        s=t;
    for (pl=p, pm=pb-s; s; --s, ++pl, ++pm)
        SWAP(pl, pm);
    if ((s=pd-pc)>(t=pn-pd-1))
        s=t;
    for (pl=pb, pm=pn-s; s; --s, ++pl, ++pm)
        SWAP(pl, pm);

    s=pb-pa;
    t=pd-pc;
    if (s>0)
        complearn_sort_split(p, s);
    update_group(p+s, p+n-t-1);
    if (t>0)
        complearn_sort_split(p+n-t, t);
}

/* Bucketsort for first iteration.

Input: x[0...n-1] holds integers in the range 1...k-1, all of which appear
at least once. x[n] is 0. (This is the corresponding output of transform.) k
must be at most n+1. p is array of size n+1 whose contents are disregarded.

Output: x is V and p is I after the initial sorting stage of the refined
suffix sorting algorithm.*/

static void bucketsort(int *x, int *p, int n, int k)
{
    int *pi, i, c, d, g;

    for (pi=p; pi<p+k; ++pi)
        *pi=-1;                   /* mark linked lists empty.*/
    for (i=0; i<=n; ++i) {
        x[i]=p[c=x[i]];           /* insert in linked list.*/
        p[c]=i;
    }
    for (pi=p+k-1, i=n; pi>=p; --pi) {
        d=x[c=*pi];               /* c is position, d is next in list.*/
        x[c]=g=i;                 /* last position equals group number.*/
        if (d>=0) {               /* if more than one element in group.*/
            p[i--]=c;              /* p is permutation for the sorted x.*/
            do {
                d=x[c=d];           /* next in linked list.*/
                x[c]=g;             /* group number in x.*/
                p[i--]=c;           /* permutation in p.*/
            } while (d>=0);
        } else
            p[i--]=-1;             /* one element, sorted group.*/
    }
}

/* Transforms the alphabet of x by attempting to aggregate several symbols into
   one, while preserving the suffix order of x. The alphabet may also be
   compacted, so that x on output comprises all integers of the new alphabet
   with no skipped numbers.

Input: x is an array of size n+1 whose first n elements are positive
integers in the range l...k-1. p is array of size n+1, used for temporary
storage. q controls aggregation and compaction by defining the maximum value
for any symbol during transformation: q must be at least k-l; if q<=n,
compaction is guaranteed; if k-l>n, compaction is never done; if q is
INT_MAX, the maximum number of symbols are aggregated into one.

Output: Returns an integer j in the range 1...q representing the size of the
new alphabet. If j<=n+1, the alphabet is compacted. The global variable r is
set to the number of old symbols grouped into one. Only x[n] is 0.*/

static int transform(int *x, int *p, int n, int k, int l, int q)
{
    int b, c, d, e, i, j, m, s;
    int *pi, *pj;

    for (s=0, i=k-l; i; i>>=1)
        ++s;                      /* s is number of bits in old symbol.*/
    e=INT_MAX>>s;                /* e is for overflow checking.*/
    for (b=d=r=0; r<n && d<=e && (c=d<<s|(k-l))<=q; ++r) {
        b=b<<s|(x[r]-l+1);        /* b is start of x in chunk alphabet.*/
        d=c;                      /* d is max symbol in chunk alphabet.*/
    }
    m=(1<<(r-1)*s)-1;            /* m masks off top old symbol from chunk.*/
    x[n]=l-1;                    /* emulate zero terminator.*/
    if (d<=n) {                  /* if bucketing possible, compact alphabet.*/
        for (pi=p; pi<=p+d; ++pi)
            *pi=0;                 /* zero transformation table.*/
        for (pi=x+r, c=b; pi<=x+n; ++pi) {
            p[c]=1;                /* mark used chunk symbol.*/
            c=(c&m)<<s|(*pi-l+1);  /* shift in next old symbol in chunk.*/
        }
        for (i=1; i<r; ++i) {     /* handle last r-1 positions.*/
            p[c]=1;                /* mark used chunk symbol.*/
            c=(c&m)<<s;            /* shift in next old symbol in chunk.*/
        }
        for (pi=p, j=1; pi<=p+d; ++pi)
            if (*pi)
                *pi=j++;            /* j is new alphabet size.*/
        for (pi=x, pj=x+r, c=b; pj<=x+n; ++pi, ++pj) {
            *pi=p[c];              /* transform to new alphabet.*/
            c=(c&m)<<s|(*pj-l+1);  /* shift in next old symbol in chunk.*/
        }
        while (pi<x+n) {          /* handle last r-1 positions.*/
            *pi++=p[c];            /* transform to new alphabet.*/
            c=(c&m)<<s;            /* shift right-end zero in chunk.*/
        }
    } else {                     /* bucketing not possible, don't compact.*/
        for (pi=x, pj=x+r, c=b; pj<=x+n; ++pi, ++pj) {
            *pi=c;                 /* transform to new alphabet.*/
            c=(c&m)<<s|(*pj-l+1);  /* shift in next old symbol in chunk.*/
        }
        while (pi<x+n) {          /* handle last r-1 positions.*/
            *pi++=c;               /* transform to new alphabet.*/
            c=(c&m)<<s;            /* shift right-end zero in chunk.*/
        }
        j=d+1;                    /* new alphabet size.*/
    }
    x[n]=0;                      /* end-of-string symbol is zero.*/
    return j;                    /* return new alphabet size.*/
}

/* Makes suffix array p of x. x becomes inverse of p. p and x are both of size
   n+1. Contents of x[0...n-1] are integers in the range l...k-1. Original
   contents of x[n] is disregarded, the n-th symbol being regarded as
   end-of-string smaller than all other symbols.*/

void complearn_suffix_sort(int *x, int *p, int n, int k, int l)
{
    int *pi, *pk;
    int i, j, s, sl;

    V=x;                         /* set global values.*/
    I=p;

    if (n>=k-l) {                /* if bucketing possible,*/
        j=transform(V, I, n, k, l, n);
        bucketsort(V, I, n, j);   /* bucketsort on first r positions.*/
    } else {
        transform(V, I, n, k, l, INT_MAX);
        for (i=0; i<=n; ++i)
            I[i]=i;                /* initialize I with suffix numbers.*/
        h=0;
        complearn_sort_split(I, n+1);       /* quicksort on first r positions.*/
    }
    h=r;                         /* number of symbols aggregated by transform.*/

    while (*I>=-n) {
        pi=I;                     /* pi is first position of group.*/
        sl=0;                     /* sl is negated length of sorted groups.*/
        do {
            if ((s=*pi)<0) {
                pi-=s;              /* skip over sorted group.*/
                sl+=s;              /* add negated length to sl.*/
            } else {
                if (sl) {
                    *(pi+sl)=sl;     /* combine sorted groups before pi.*/
                    sl=0;
                }
                pk=I+V[s]+1;        /* pk-1 is last position of unsorted group.*/
                complearn_sort_split(pi, pk-pi);
                pi=pk;              /* next group.*/
            }
        } while (pi<=I+n);
        if (sl)                   /* if the array ends with a sorted group.*/
            *(pi+sl)=sl;           /* combine sorted groups at end of I.*/
        h=2*h;                    /* double sorted-depth.*/
    }

    for (i=0; i<=n; ++i)         /* reconstruct suffix array from inverse.*/
        I[V[i]]=i;
}

static void freeBSCI( struct BlockSortCompressionInstance *bsci)
{
    if (bsci->allocated > 0) {
        free(bsci->x);
        free(bsci->p);
        bsci->allocated = 0;
        bsci->x = NULL;
        bsci->p = NULL;
    }
    free(bsci);
}

static void resetStatistics(struct BlockSortCompressionInstance *bsci)
{
    int i, d, m, s;
    double prev, cur;
    m = 0;
    prev = 0;
    s = 0;
    for (i=0; i<256; i++) {
        cur = log(i+1.0)/log(STATELOGBASE);
        d = (int)cur-(int)prev;
        if (d>1) m+=(d-1);
        s = (int)cur - m;
        bsci->code2state[i] = s;
        prev = cur;
    }
    bsci->nstates = s+1;
    if (bsci->nstates > MAXSTATES) {
        assert(0 && "MAXSTATES should be larger.");
        exit(1);
    }
}

static double bs_compress(struct BlockSortCompressionInstance *CI,
        unsigned char *data, int size) {
    int *x, *p;
    int i, j, mass, av;
    unsigned char code2byte[256];
    int num[256], total[MAXSTATES], state, oldstate;
    int statetrans[MAXSTATES][MAXSTATES], ntrans[MAXSTATES];
    double cl = 0;

    /* Obtain workspace in x and p */
    if (CI->allocated < size+1) {
        CI->allocated = 10 + size * 1.2;
        CI->x = realloc(CI->x, CI->allocated * sizeof(int));
        CI->p = realloc(CI->p, CI->allocated * sizeof(int));
        if (CI->x==NULL || CI->p==NULL) { assert(0 && "blocksort logic error"); }
    }
    x = CI->x;
    p = CI->p;

    /* Suffix sort the data (permutes x and p) */
    for (i=0; i<size; i++) x[i] = data[i];
    complearn_suffix_sort(x, p, size, UCHAR_MAX+1, 0);

    /* Initialise state transition statistics */
    for (j=0; j<MAXSTATES; j++) {
        total[j]  = 0;
        ntrans[j] = MAXSTATES;
        for (i=0; i<MAXSTATES; i++) statetrans[j][i] = 1;
    }
    statetrans[0][0]--; ntrans[0]--;

    /* Initialise the move to front codebook and the symbol frequencies */
    for (i=0; i<256; i++) {
        code2byte[i] = i;
        num[i] = 1;
        total[CI->code2state[i]]++;
    }

    state = CI->nstates-1;

    /* Code the block sorted sequence */
    for (i=0; i<size+1; i++) {
        unsigned char c;
        unsigned char carry1, carry2;
        int code;

        c = p[i] ? data[(p[i]+size)%(size+1)] : code2byte[0];

        /* Move to front:
           - if the symbol is at position 1 of the code book, then move it
           to position 0
           - otherwise move it to position 1.
           (Why? Because it improves compression. Why? No-one knows.)
           */
        code = 0;
        carry2 = code2byte[0];
        if (carry2!=c) {
            carry1 = code2byte[++code];
            if (carry1==c) {
                code2byte[0] = (unsigned char)c;
                code2byte[1] = carry2;
            } else {
                code2byte[1] = (unsigned char)c;
                for (;;) {
                    carry2 = code2byte[++code];
                    code2byte[code] = carry1;
                    if (carry2 == c) break;
                    carry1 = code2byte[++code];
                    code2byte[code] = carry2;
                    if (carry1 == c) break;
                }
            }
        }


        /* Encoding takes place in three stages:

           1. Encode a state transition.
           The state depends on the symbol to be encoded through the
           lookup table CI->code2state[]. We keep statistics on state
           transition frequencies through statetrans[<state>][<state>]
           and ntrans[<state>].

           2. Encode the symbol.
           Decoder already knows it must be one of the symbols that map
           to the current state. We keep statistics on those as well,
           this time through the arrays num[<symbol>] and total[<state>].
           Notice that some states only contain a single symbol; if we are
           in such a state then automatically zero bits are used in this
           stage.

           3. Run length encode zeroes.
           If the symbol was a zero, then encode the number of zeroes that
           follow, instead of coding each of them separately. This is necessary
           because often sequences of zeroes occur that are highly dependent:
           the probability that the next symbol is also a zero is often much
           higher if the previous TWO symbols are zero than if only the
           previous symbol is a zero, etc.

*/

        /* Stage 1. Encode the state transition. */
        oldstate = state;
        state = CI->code2state[code];

        cl += -log(statetrans[oldstate][state])+log(ntrans[oldstate]);
        statetrans[oldstate][state]++;
        ntrans[oldstate]++;

        /* 2. Encode the symbol from the range that belongs to this state */
        cl += -log(num[code])+log(total[state]);

        mass = CREDULITY;
        for (j=code; j>=0 && num[j]*(code-j)<mass; j--)
            mass += num[j];
        av = mass / (code-j);
        for (j++; j<=code; j++) {
            total[CI->code2state[j]] += av - num[j];
            num[j] = av;
        }

        /* Stage 3. Run length encode zeroes.
           We take as a probability distribution on the integers: P(n)=1/(n(n+1))
           It is easy to check that this sums to one for 1 <= n < infinity.
           The corresponding code uses -log P(n) bits to encode n.
Motivation: the codelength is logarithmic in n, so it can never be
extremely inefficient. At the same time, a relatively high probability
is assigned to low numbers.
*/
        if (code==0 && i<size) {
            int runlength = i;
            i++;
            while (i<size+1) {
                if (p[i] && data[(p[i]+size)%(size+1)] != code2byte[0]) break;
                i++;
            };
            runlength = i - runlength;
            i--;

            cl += log(runlength) + log(runlength+1);
        }
    }

    return (cl + log(size)) / M_LN2;
}

int vcblocksortCompress(int level, const unsigned char *data, size_t avail_in, unsigned char *odata, size_t *avail_out)
{
    double result;
    struct BlockSortCompressionInstance *bsci;
    bsci = calloc(sizeof(*bsci), 1);
    resetStatistics(bsci);
    result = bs_compress(bsci, (unsigned char *)data, avail_in);

    freeBSCI(bsci);

    *avail_out = (int)result;
    return 0;
}
