/* The C clustering library.
 * Copyright (C) 2002 Michiel Jan Laurens de Hoon.
 *
 * This library was written at the Laboratory of DNA Information Analysis,
 * Human Genome Center, Institute of Medical Science, University of Tokyo,
 * 4-6-1 Shirokanedai, Minato-ku, Tokyo 108-8639, Japan.
 * Contact: mdehoon 'AT' gsc.riken.jp
 * 
 * Permission to use, copy, modify, and distribute this software and its
 * documentation with or without modifications and for any purpose and
 * without fee is hereby granted, provided that any copyright notices
 * appear in all copies and that both those copyright notices and this
 * permission notice appear in supporting documentation, and that the
 * names of the contributors or copyright holders not be used in
 * advertising or publicity pertaining to distribution of the software
 * without specific prior permission.
 * 
 * THE CONTRIBUTORS AND COPYRIGHT HOLDERS OF THIS SOFTWARE DISCLAIM ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL THE
 * CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY SPECIAL, INDIRECT
 * OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE
 * OR PERFORMANCE OF THIS SOFTWARE.
 * 
 */

#include <time.h>
#include <stdlib.h>
#include <math.h>
#include <float.h>
#include <limits.h>
#include <string.h>
#include "cluster.h"
#ifdef WINDOWS
#  include <windows.h>
#endif

/* ************************************************************************ */

#ifdef WINDOWS
/* Then we make a Windows DLL */
int WINAPI
clusterdll_init (HANDLE h, DWORD reason, void* foo)
{
  return 1;
}
#endif

/* ************************************************************************ */

double mean(int n, double x[])
{ double result = 0.;
  int i;
  for (i = 0; i < n; i++) result += x[i];
  result /= n;
  return result;
}

/* ************************************************************************ */

double median (int n, double x[])
/*
Find the median of X(1), ... , X(N), using as much of the quicksort
algorithm as is needed to isolate it.
N.B. On exit, the array X is partially ordered.
Based on Alan J. Miller's median.f90 routine.
*/

{ int i, j;
  int nr = n / 2;
  int nl = nr - 1;
  int even = 0;
  /* hi & lo are position limits encompassing the median. */
  int lo = 0;
  int hi = n-1;

  if (n==2*nr) even = 1;
  if (n<3)
  { if (n<1) return 0.;
    if (n == 1) return x[0];
    return 0.5*(x[0]+x[1]);
  }

  /* Find median of 1st, middle & last values. */
  do
  { int loop;
    int mid = (lo + hi)/2;
    double result = x[mid];
    double xlo = x[lo];
    double xhi = x[hi];
    if (xhi<xlo)
    { double temp = xlo;
      xlo = xhi;
      xhi = temp;
    }
    if (result>xhi) result = xhi;
    else if (result<xlo) result = xlo;
    /* The basic quicksort algorithm to move all values <= the sort key (XMED)
     * to the left-hand end, and all higher values to the other end.
     */
    i = lo;
    j = hi;
    do
    { while (x[i]<result) i++;
      while (x[j]>result) j--;
      loop = 0;
      if (i<j)
      { double temp = x[i];
        x[i] = x[j];
        x[j] = temp;
        i++;
        j--;
        if (i<=j) loop = 1;
      }
    } while (loop); /* Decide which half the median is in. */

    if (even)
    { if (j==nl && i==nr)
        /* Special case, n even, j = n/2 & i = j + 1, so the median is
         * between the two halves of the series.   Find max. of the first
         * half & min. of the second half, then average.
         */
        { int k;
          double xmax = x[0];
          double xmin = x[n-1];
          for (k = lo; k <= j; k++) xmax = max(xmax,x[k]);
          for (k = i; k <= hi; k++) xmin = min(xmin,x[k]);
          return 0.5*(xmin + xmax);
        }
      if (j<nl) lo = i;
      if (i>nr) hi = j;
      if (i==j)
      { if (i==nl) lo = nl;
        if (j==nr) hi = nr;
      }
    }
    else
    { if (j<nr) lo = i;
      if (i>nr) hi = j;
      /* Test whether median has been isolated. */
      if (i==j && i==nr) return result;
    }
  }
  while (lo<hi-1);

  if (even) return (0.5*(x[nl]+x[nr]));
  if (x[lo]>x[hi])
  { double temp = x[lo];
    x[lo] = x[hi];
    x[hi] = temp;
  }
  return x[nr];
}

/* ********************************************************************** */

static const double* sortdata = NULL; /* used in the quicksort algorithm */

/* ---------------------------------------------------------------------- */

static
int compare(const void* a, const void* b)
/* Helper function for sort. Previously, this was a nested function under
 * sort, which is not allowed under ANSI C.
 */
{ const int i1 = *(const int*)a;
  const int i2 = *(const int*)b;
  const double term1 = sortdata[i1];
  const double term2 = sortdata[i2];
  if (term1 < term2) return -1;
  if (term1 > term2) return +1;
  return 0;
}

/* ---------------------------------------------------------------------- */

void sort(int n, const double data[], int index[])
/* Sets up an index table given the data, such that data[index[]] is in
 * increasing order. Sorting is done on the indices; the array data
 * is unchanged.
 */
{ int i;
  sortdata = data;
  for (i = 0; i < n; i++) index[i] = i;
  qsort(index, n, sizeof(int), compare);
}

/* ********************************************************************** */

static double* getrank (int n, double data[])
/* Calculates the ranks of the elements in the array data. Two elements with
 * the same value get the same rank, equal to the average of the ranks had the
 * elements different values. The ranks are returned as a newly allocated
 * array that should be freed by the calling routine. If getrank fails due to
 * a memory allocation error, it returns NULL.
 */
{ int i;
  double* rank;
  int* index;
  rank = malloc(n*sizeof(double));
  if (!rank) return NULL;
  index = malloc(n*sizeof(int));
  if (!index)
  { free(rank);
    return NULL;
  }
  /* Call sort to get an index table */
  sort (n, data, index);
  /* Build a rank table */
  for (i = 0; i < n; i++) rank[index[i]] = i;
  /* Fix for equal ranks */
  i = 0;
  while (i < n)
  { int m;
    double value = data[index[i]];
    int j = i + 1;
    while (j < n && data[index[j]] == value) j++;
    m = j - i; /* number of equal ranks found */
    value = rank[index[i]] + (m-1)/2.;
    for (j = i; j < i + m; j++) rank[index[j]] = value;
    i += m;
  }
  free (index);
  return rank;
}

/* ---------------------------------------------------------------------- */

static int
makedatamask(int nrows, int ncols, double*** pdata, int*** pmask)
{ int i;
  double** data;
  int** mask;
  data = malloc(nrows*sizeof(double*));
  if(!data) return 0;
  mask = malloc(nrows*sizeof(int*));
  if(!mask)
  { free(data);
    return 0;
  }
  for (i = 0; i < nrows; i++)
  { data[i] = malloc(ncols*sizeof(double));
    if(!data[i]) break;
    mask[i] = malloc(ncols*sizeof(int));
    if(!mask[i])
    { free(data[i]);
      break;
    }
  }
  if (i==nrows) /* break not encountered */
  { *pdata = data;
    *pmask = mask;
    return 1;
  }
  *pdata = NULL;
  *pmask = NULL;
  nrows = i;
  for (i = 0; i < nrows; i++)
  { free(data[i]);
    free(mask[i]);
  }
  free(data);
  free(mask);
  return 0;
}

/* ---------------------------------------------------------------------- */

static void
freedatamask(int n, double** data, int** mask)
{ int i;
  for (i = 0; i < n; i++)
  { free(mask[i]);
    free(data[i]);
  }
  free(mask);
  free(data);
}

/* ---------------------------------------------------------------------- */

static
double find_closest_pair(int n, double** distmatrix, int* ip, int* jp)
/*
This function searches the distance matrix to find the pair with the shortest
distance between them. The indices of the pair are returned in ip and jp; the
distance itself is returned by the function.

n          (input) int
The number of elements in the distance matrix.

distmatrix (input) double**
A ragged array containing the distance matrix. The number of columns in each
row is one less than the row index.

ip         (output) int*
A pointer to the integer that is to receive the first index of the pair with
the shortest distance.

jp         (output) int*
A pointer to the integer that is to receive the second index of the pair with
the shortest distance.
*/
{ int i, j;
  double temp;
  double distance = distmatrix[1][0];
  *ip = 1;
  *jp = 0;
  for (i = 1; i < n; i++)
  { for (j = 0; j < i; j++)
    { temp = distmatrix[i][j];
      if (temp<distance)
      { distance = temp;
        *ip = i;
        *jp = j;
      }
    }
  }
  return distance;
}

/* ********************************************************************* */

static int svd(int m, int n, double** u, double w[], double** vt)
/*
 *   This subroutine is a translation of the Algol procedure svd,
 *   Num. Math. 14, 403-420(1970) by Golub and Reinsch.
 *   Handbook for Auto. Comp., Vol II-Linear Algebra, 134-151(1971).
 *
 *   This subroutine determines the singular value decomposition
 *        t
 *   A=usv  of a real m by n rectangular matrix, where m is greater
 *   than or equal to n.  Householder bidiagonalization and a variant
 *   of the QR algorithm are used.
 *  
 *
 *   On input.
 *
 *      m is the number of rows of A (and u).
 *
 *      n is the number of columns of A (and u) and the order of v.
 *
 *      u contains the rectangular input matrix A to be decomposed.
 *
 *   On output.
 *
 *      the routine returns an integer ierr equal to
 *        0          to indicate a normal return,
 *        k          if the k-th singular value has not been
 *                   determined after 30 iterations,
 *        -1         if memory allocation fails.
 *
 *
 *     w  contains the n (non-negative) singular values of a (the
 *        diagonal elements of s).  they are unordered.  if an
 *        error exit is made, the singular values should be correct
 *        for indices ierr+1,ierr+2,...,n.
 *
 *
 *     u  contains the matrix u (orthogonal column vectors) of the
 *        decomposition.
 *        if an error exit is made, the columns of u corresponding
 *        to indices of correct singular values should be correct.
 *
 *                             t
 *     vt contains the matrix v (orthogonal) of the decomposition.
 *        if an error exit is made, the columns of v corresponding
 *        to indices of correct singular values should be correct.
 *
 *
 *   Questions and comments should be directed to B. S. Garbow,
 *   Applied Mathematics division, Argonne National Laboratory
 *
 *   Modified to eliminate machep
 *
 *   Translated to C by Michiel de Hoon, Human Genome Center,
 *   University of Tokyo, for inclusion in the C Clustering Library.
 *   This routine is less general than the original svd routine, as
 *   it focuses on the singular value decomposition as needed for
 *   clustering. In particular,
 *     - We calculate both u and v in all cases
 *     - We pass the input array A via u; this array is subsequently
 *       overwritten.
 *     - We allocate for the array rv1, used as a working space,
 *       internally in this routine, instead of passing it as an
 *       argument. If the allocation fails, svd returns -1.
 *   2003.06.05
 */
{ int i, j, k, i1, k1, l1, its;
  double c,f,h,s,x,y,z;
  int l = 0;
  int ierr = 0;
  double g = 0.0;
  double scale = 0.0;
  double anorm = 0.0;
  double* rv1 = malloc(n*sizeof(double));
  if (!rv1) return -1;
  if (m >= n)
  { /* Householder reduction to bidiagonal form */
    for (i = 0; i < n; i++)
    { l = i + 1;
      rv1[i] = scale * g;
      g = 0.0;
      s = 0.0;
      scale = 0.0;
      for (k = i; k < m; k++) scale += fabs(u[k][i]);
      if (scale != 0.0)
      { for (k = i; k < m; k++)
        { u[k][i] /= scale;
          s += u[k][i]*u[k][i];
        }
        f = u[i][i];
        g = (f >= 0) ? -sqrt(s) : sqrt(s);
        h = f * g - s;
        u[i][i] = f - g;
        if (i < n-1)
        { for (j = l; j < n; j++)
          { s = 0.0;
            for (k = i; k < m; k++) s += u[k][i] * u[k][j];
            f = s / h;
            for (k = i; k < m; k++) u[k][j] += f * u[k][i];
          }
        }
        for (k = i; k < m; k++) u[k][i] *= scale;
      }
      w[i] = scale * g;
      g = 0.0;
      s = 0.0;
      scale = 0.0;
      if (i<n-1)
      { for (k = l; k < n; k++) scale += fabs(u[i][k]);
        if (scale != 0.0)
        { for (k = l; k < n; k++)
          { u[i][k] /= scale;
            s += u[i][k] * u[i][k];
          }
          f = u[i][l];
          g = (f >= 0) ? -sqrt(s) : sqrt(s);
          h = f * g - s;
          u[i][l] = f - g;
          for (k = l; k < n; k++) rv1[k] = u[i][k] / h;
          for (j = l; j < m; j++)
          { s = 0.0;
            for (k = l; k < n; k++) s += u[j][k] * u[i][k];
            for (k = l; k < n; k++) u[j][k] += s * rv1[k];
          }
          for (k = l; k < n; k++)  u[i][k] *= scale;
        }
      }
      anorm = max(anorm,fabs(w[i])+fabs(rv1[i]));
    }
    /* accumulation of right-hand transformations */
    for (i = n-1; i>=0; i--)
    { if (i < n-1)
      { if (g != 0.0)
        { for (j = l; j < n; j++) vt[i][j] = (u[i][j] / u[i][l]) / g;
          /* double division avoids possible underflow */
          for (j = l; j < n; j++)
          { s = 0.0;
            for (k = l; k < n; k++) s += u[i][k] * vt[j][k];
            for (k = l; k < n; k++) vt[j][k] += s * vt[i][k];
          }
        }
      }
      for (j = l; j < n; j++)
      { vt[j][i] = 0.0;
        vt[i][j] = 0.0;
      }
      vt[i][i] = 1.0;
      g = rv1[i];
      l = i;
    }
    /* accumulation of left-hand transformations */
    for (i = n-1; i >= 0; i--)
    { l = i + 1;
      g = w[i];
      if (i!=n-1)
        for (j = l; j < n; j++) u[i][j] = 0.0;
      if (g!=0.0)
      { if (i!=n-1)
        { for (j = l; j < n; j++)
          { s = 0.0;
            for (k = l; k < m; k++) s += u[k][i] * u[k][j];
            /* double division avoids possible underflow */
            f = (s / u[i][i]) / g;
            for (k = i; k < m; k++) u[k][j] += f * u[k][i];
          }
        }
        for (j = i; j < m; j++) u[j][i] /= g;
      }
      else
        for (j = i; j < m; j++) u[j][i] = 0.0;
      u[i][i] += 1.0;
    }
    /* diagonalization of the bidiagonal form */
    for (k = n-1; k >= 0; k--)
    { k1 = k-1;
      its = 0;
      while(1)
      /* test for splitting */
      { for (l = k; l >= 0; l--)
        { l1 = l-1;
          if (fabs(rv1[l]) + anorm == anorm) break;
          /* rv1[0] is always zero, so there is no exit
           * through the bottom of the loop */
          if (fabs(w[l1]) + anorm == anorm)
          /* cancellation of rv1[l] if l greater than 0 */
          { c = 0.0;
            s = 1.0;
            for (i = l; i <= k; i++)
            { f = s * rv1[i];
              rv1[i] *= c;
              if (fabs(f) + anorm == anorm) break;
              g = w[i];
              h = sqrt(f*f+g*g);
              w[i] = h;
              c = g / h;
              s = -f / h;
              for (j = 0; j < m; j++)
              { y = u[j][l1];
                z = u[j][i];
                u[j][l1] = y * c + z * s;
                u[j][i] = -y * s + z * c;
              }
            }
            break;
          }
        }
        /* test for convergence */
        z = w[k];
        if (l==k) /* convergence */
        { if (z < 0.0)
          /*  w[k] is made non-negative */
          { w[k] = -z;
            for (j = 0; j < n; j++) vt[k][j] = -vt[k][j];
          }
          break;
        }
        else if (its==30)
        { ierr = k;
          break;
        }
        else
        /* shift from bottom 2 by 2 minor */
        { its++;
          x = w[l];
          y = w[k1];
          g = rv1[k1];
          h = rv1[k];
          f = ((y - z) * (y + z) + (g - h) * (g + h)) / (2.0 * h * y);
          g = sqrt(f*f+1.0);
          f = ((x - z) * (x + z) + h * (y / (f + (f >= 0 ? g : -g)) - h)) / x;
          /* next qr transformation */
          c = 1.0;
          s = 1.0;
          for (i1 = l; i1 <= k1; i1++)
          { i = i1 + 1;
            g = rv1[i];
            y = w[i];
            h = s * g;
            g = c * g;
            z = sqrt(f*f+h*h);
            rv1[i1] = z;
            c = f / z;
            s = h / z;
            f = x * c + g * s;
            g = -x * s + g * c;
            h = y * s;
            y = y * c;
            for (j = 0; j < n; j++)
            { x = vt[i1][j];
              z = vt[i][j];
              vt[i1][j] = x * c + z * s;
              vt[i][j] = -x * s + z * c;
            }
            z = sqrt(f*f+h*h);
            w[i1] = z;
            /* rotation can be arbitrary if z is zero */
            if (z!=0.0)
            { c = f / z;
              s = h / z;
            }
            f = c * g + s * y;
            x = -s * g + c * y;
            for (j = 0; j < m; j++)
            { y = u[j][i1];
              z = u[j][i];
              u[j][i1] = y * c + z * s;
              u[j][i] = -y * s + z * c;
            }
          }
          rv1[l] = 0.0;
          rv1[k] = f;
          w[k] = x;
        }
      }
    }
  }
  else /* m < n */
  { /* Householder reduction to bidiagonal form */
    for (i = 0; i < m; i++)
    { l = i + 1;
      rv1[i] = scale * g;
      g = 0.0;
      s = 0.0;
      scale = 0.0;
      for (k = i; k < n; k++) scale += fabs(u[i][k]);
      if (scale != 0.0)
      { for (k = i; k < n; k++)
        { u[i][k] /= scale;
          s += u[i][k]*u[i][k];
        }
        f = u[i][i];
        g = (f >= 0) ? -sqrt(s) : sqrt(s);
        h = f * g - s;
        u[i][i] = f - g;
        if (i < m-1)
        { for (j = l; j < m; j++)
          { s = 0.0;
            for (k = i; k < n; k++) s += u[i][k] * u[j][k];
            f = s / h;
            for (k = i; k < n; k++) u[j][k] += f * u[i][k];
          }
        }
        for (k = i; k < n; k++) u[i][k] *= scale;
      }
      w[i] = scale * g;
      g = 0.0;
      s = 0.0;
      scale = 0.0;
      if (i<m-1)
      { for (k = l; k < m; k++) scale += fabs(u[k][i]);
        if (scale != 0.0)
        { for (k = l; k < m; k++)
          { u[k][i] /= scale;
            s += u[k][i] * u[k][i];
          }
          f = u[l][i];
          g = (f >= 0) ? -sqrt(s) : sqrt(s);
          h = f * g - s;
          u[l][i] = f - g;
          for (k = l; k < m; k++) rv1[k] = u[k][i] / h;
          for (j = l; j < n; j++)
          { s = 0.0;
            for (k = l; k < m; k++) s += u[k][j] * u[k][i];
            for (k = l; k < m; k++) u[k][j] += s * rv1[k];
          }
          for (k = l; k < m; k++)  u[k][i] *= scale;
        }
      }
      anorm = max(anorm,fabs(w[i])+fabs(rv1[i]));
    }
    /* accumulation of right-hand transformations */
    for (i = m-1; i>=0; i--)
    { if (i < m-1)
      { if (g != 0.0)
        { for (j = l; j < m; j++) vt[j][i] = (u[j][i] / u[l][i]) / g;
          /* double division avoids possible underflow */
          for (j = l; j < m; j++)
          { s = 0.0;
            for (k = l; k < m; k++) s += u[k][i] * vt[k][j];
            for (k = l; k < m; k++) vt[k][j] += s * vt[k][i];
          }
        }
      }
      for (j = l; j < m; j++)
      { vt[i][j] = 0.0;
        vt[j][i] = 0.0;
      }
      vt[i][i] = 1.0;
      g = rv1[i];
      l = i;
    }
    /* accumulation of left-hand transformations */
    for (i = m-1; i >= 0; i--)
    { l = i + 1;
      g = w[i];
      if (i!=m-1)
        for (j = l; j < m; j++) u[j][i] = 0.0;
      if (g!=0.0)
      { if (i!=m-1)
        { for (j = l; j < m; j++)
          { s = 0.0;
            for (k = l; k < n; k++) s += u[i][k] * u[j][k];
            /* double division avoids possible underflow */
            f = (s / u[i][i]) / g;
            for (k = i; k < n; k++) u[j][k] += f * u[i][k];
          }
        }
        for (j = i; j < n; j++) u[i][j] /= g;
      }
      else
        for (j = i; j < n; j++) u[i][j] = 0.0;
      u[i][i] += 1.0;
    }
    /* diagonalization of the bidiagonal form */
    for (k = m-1; k >= 0; k--)
    { k1 = k-1;
      its = 0;
      while(1)
      /* test for splitting */
      { for (l = k; l >= 0; l--)
        { l1 = l-1;
          if (fabs(rv1[l]) + anorm == anorm) break;
          /* rv1[0] is always zero, so there is no exit
           * through the bottom of the loop */
          if (fabs(w[l1]) + anorm == anorm)
          /* cancellation of rv1[l] if l greater than 0 */
          { c = 0.0;
            s = 1.0;
            for (i = l; i <= k; i++)
            { f = s * rv1[i];
              rv1[i] *= c;
              if (fabs(f) + anorm == anorm) break;
              g = w[i];
              h = sqrt(f*f+g*g);
              w[i] = h;
              c = g / h;
              s = -f / h;
              for (j = 0; j < n; j++)
              { y = u[l1][j];
                z = u[i][j];
                u[l1][j] = y * c + z * s;
                u[i][j] = -y * s + z * c;
              }
            }
            break;
          }
        }
        /* test for convergence */
        z = w[k];
        if (l==k) /* convergence */
        { if (z < 0.0)
          /*  w[k] is made non-negative */
          { w[k] = -z;
            for (j = 0; j < m; j++) vt[j][k] = -vt[j][k];
          }
          break;
        }
        else if (its==30)
        { ierr = k;
          break;
        }
        else
        /* shift from bottom 2 by 2 minor */
        { its++;
          x = w[l];
          y = w[k1];
          g = rv1[k1];
          h = rv1[k];
          f = ((y - z) * (y + z) + (g - h) * (g + h)) / (2.0 * h * y);
          g = sqrt(f*f+1.0);
          f = ((x - z) * (x + z) + h * (y / (f + (f >= 0 ? g : -g)) - h)) / x;
          /* next qr transformation */
          c = 1.0;
          s = 1.0;
          for (i1 = l; i1 <= k1; i1++)
          { i = i1 + 1;
            g = rv1[i];
            y = w[i];
            h = s * g;
            g = c * g;
            z = sqrt(f*f+h*h);
            rv1[i1] = z;
            c = f / z;
            s = h / z;
            f = x * c + g * s;
            g = -x * s + g * c;
            h = y * s;
            y = y * c;
            for (j = 0; j < m; j++)
            { x = vt[j][i1];
              z = vt[j][i];
              vt[j][i1] = x * c + z * s;
              vt[j][i] = -x * s + z * c;
            }
            z = sqrt(f*f+h*h);
            w[i1] = z;
            /* rotation can be arbitrary if z is zero */
            if (z!=0.0)
            { c = f / z;
              s = h / z;
            }
            f = c * g + s * y;
            x = -s * g + c * y;
            for (j = 0; j < n; j++)
            { y = u[i1][j];
              z = u[i][j];
              u[i1][j] = y * c + z * s;
              u[i][j] = -y * s + z * c;
            }
          }
          rv1[l] = 0.0;
          rv1[k] = f;
          w[k] = x;
        }
      }
    }
  }
  free(rv1);
  return ierr;
}

/* ********************************************************************* */

int pca(int nrows, int ncolumns, double** u, double** v, double* w)
/*
Purpose
=======

This subroutine uses the singular value decomposition to perform principal
components analysis of a real nrows by ncolumns rectangular matrix.

Arguments
=========

nrows     (input) int
The number of rows in the matrix u.

ncolumns  (input) int
The number of columns in the matrix v.

u          (input) double[nrows][ncolumns]
On input, the array containing the data to which the principal component
analysis should be applied. The function assumes that the mean has already been
subtracted of each column, and hence that the mean of each column is zero.
On output, see below.

v          (input) double[n][n], where n = min(nrows, ncolumns)
Not used on input.

w          (input) double[n], where n = min(nrows, ncolumns)
Not used on input.


Return value
============

On output:

If nrows >= ncolumns, then

u contains the coordinates with respect to the principal components;
v contains the principal component vectors.

The dot product u . v reproduces the data that were passed in u.


If nrows < ncolumns, then

u contains the principal component vectors;
v contains the coordinates with respect to the principal components.

The dot product v . u reproduces the data that were passed in u.

The eigenvalues of the covariance matrix are returned in w.

The arrays u, v, and w are sorted according to eigenvalue, with the largest
eigenvalues appearing first.

The function returns 0 if successful, -1 if memory allocation fails, and a
positive integer if the singular value decomposition fails to converge.
*/
{
    int i;
    int j;
    int error;
    int* index = malloc(ncolumns*sizeof(int));
    double* temp = malloc(ncolumns*sizeof(double));
    if (!index || !temp)
    {   if (index) free(index);
        if (temp) free(temp);
        return -1;
    }
    error = svd(nrows, ncolumns, u, w, v);
    if (error==0)
    {
        if (nrows >= ncolumns)
        {   for (j = 0; j < ncolumns; j++)
            {   const double s = w[j];
                for (i = 0; i < nrows; i++) u[i][j] *= s;
            }
            sort(ncolumns, w, index);
            for (i = 0; i < ncolumns/2; i++)
            {   j = index[i];
                index[i] = index[ncolumns-1-i];
                index[ncolumns-1-i] = j;
            }
            for (i = 0; i < nrows; i++)
            {   for (j = 0; j < ncolumns; j++) temp[j] = u[i][index[j]];
                for (j = 0; j < ncolumns; j++) u[i][j] = temp[j];
            }
            for (i = 0; i < ncolumns; i++)
            {   for (j = 0; j < ncolumns; j++) temp[j] = v[index[j]][i];
                for (j = 0; j < ncolumns; j++) v[j][i] = temp[j];
            }
            for (i = 0; i < ncolumns; i++) temp[i] = w[index[i]];
            for (i = 0; i < ncolumns; i++) w[i] = temp[i];
        }
        else /* nrows < ncolumns */
        {   for (j = 0; j < nrows; j++)
            {   const double s = w[j];
                for (i = 0; i < nrows; i++) v[i][j] *= s;
            }
            sort(nrows, w, index);
            for (i = 0; i < nrows/2; i++)
            {   j = index[i];
                index[i] = index[nrows-1-i];
                index[nrows-1-i] = j;
            }
            for (j = 0; j < ncolumns; j++)
            {   for (i = 0; i < nrows; i++) temp[i] = u[index[i]][j];
                for (i = 0; i < nrows; i++) u[i][j] = temp[i];
            }
            for (j = 0; j < nrows; j++)
            {   for (i = 0; i < nrows; i++) temp[i] = v[j][index[i]];
                for (i = 0; i < nrows; i++) v[j][i] = temp[i];
            }
            for (i = 0; i < nrows; i++) temp[i] = w[index[i]];
            for (i = 0; i < nrows; i++) w[i] = temp[i];
        }
    }
    free(index);
    free(temp);
    return error;
}

/* ********************************************************************* */

static
double euclid (int n, double** data1, double** data2, int** mask1, int** mask2,
  const double weight[], int index1, int index2, int transpose)
 
/*
Purpose
=======

The euclid routine calculates the weighted Euclidean distance between two
rows or columns in a matrix.

Arguments
=========

n      (input) int
The number of elements in a row or column. If transpose==0, then n is the number
of columns; otherwise, n is the number of rows.

data1  (input) double array
The data array containing the first vector.

data2  (input) double array
The data array containing the second vector.

mask1  (input) int array
This array which elements in data1 are missing. If mask1[i][j]==0, then
data1[i][j] is missing.

mask2  (input) int array
This array which elements in data2 are missing. If mask2[i][j]==0, then
data2[i][j] is missing.

weight (input) double[n]
The weights that are used to calculate the distance.

index1     (input) int
Index of the first row or column.

index2     (input) int
Index of the second row or column.

transpose (input) int
If transpose==0, the distance between two rows in the matrix is calculated.
Otherwise, the distance between two columns in the matrix is calculated.

============================================================================
*/
{ double result = 0.;
  double tweight = 0;
  int i;
  if (transpose==0) /* Calculate the distance between two rows */
  { for (i = 0; i < n; i++)
    { if (mask1[index1][i] && mask2[index2][i])
      { double term = data1[index1][i] - data2[index2][i];
        result += weight[i]*term*term;
        tweight += weight[i];
      }
    }
  }
  else
  { for (i = 0; i < n; i++)
    { if (mask1[i][index1] && mask2[i][index2])
      { double term = data1[i][index1] - data2[i][index2];
        result += weight[i]*term*term;
        tweight += weight[i];
      }
    }
  }
  if (!tweight) return 0; /* usually due to empty clusters */
  result /= tweight;
  return result;
}

/* ********************************************************************* */

static
double cityblock (int n, double** data1, double** data2, int** mask1,
  int** mask2, const double weight[], int index1, int index2, int transpose)

/*
Purpose
=======

The cityblock routine calculates the weighted "City Block" distance between
two rows or columns in a matrix. City Block distance is defined as the
absolute value of X1-X2 plus the absolute value of Y1-Y2 plus..., which is
equivalent to taking an "up and over" path.

Arguments
=========

n      (input) int
The number of elements in a row or column. If transpose==0, then n is the number
of columns; otherwise, n is the number of rows.

data1  (input) double array
The data array containing the first vector.

data2  (input) double array
The data array containing the second vector.

mask1  (input) int array
This array which elements in data1 are missing. If mask1[i][j]==0, then
data1[i][j] is missing.

mask2  (input) int array
This array which elements in data2 are missing. If mask2[i][j]==0, then
data2[i][j] is missing.

weight (input) double[n]
The weights that are used to calculate the distance.

index1     (input) int
Index of the first row or column.

index2     (input) int
Index of the second row or column.

transpose (input) int
If transpose==0, the distance between two rows in the matrix is calculated.
Otherwise, the distance between two columns in the matrix is calculated.

============================================================================ */
{ double result = 0.;
  double tweight = 0;
  int i;
  if (transpose==0) /* Calculate the distance between two rows */
  { for (i = 0; i < n; i++)
    { if (mask1[index1][i] && mask2[index2][i])
      { double term = data1[index1][i] - data2[index2][i];
        result = result + weight[i]*fabs(term);
        tweight += weight[i];
      }
    }
  }
  else
  { for (i = 0; i < n; i++)
    { if (mask1[i][index1] && mask2[i][index2])
      { double term = data1[i][index1] - data2[i][index2];
        result = result + weight[i]*fabs(term);
        tweight += weight[i];
      }
    }
  }
  if (!tweight) return 0; /* usually due to empty clusters */
  result /= tweight;
  return result;
}

/* ********************************************************************* */

static
double correlation (int n, double** data1, double** data2, int** mask1,
  int** mask2, const double weight[], int index1, int index2, int transpose)
/*
Purpose
=======

The correlation routine calculates the weighted Pearson distance between two
rows or columns in a matrix. We define the Pearson distance as one minus the
Pearson correlation.
This definition yields a semi-metric: d(a,b) >= 0, and d(a,b) = 0 iff a = b.
but the triangular inequality d(a,b) + d(b,c) >= d(a,c) does not hold
(e.g., choose b = a + c).

Arguments
=========

n      (input) int
The number of elements in a row or column. If transpose==0, then n is the number
of columns; otherwise, n is the number of rows.

data1  (input) double array
The data array containing the first vector.

data2  (input) double array
The data array containing the second vector.

mask1  (input) int array
This array which elements in data1 are missing. If mask1[i][j]==0, then
data1[i][j] is missing.

mask2  (input) int array
This array which elements in data2 are missing. If mask2[i][j]==0, then
data2[i][j] is missing.

weight (input) double[n]
The weights that are used to calculate the distance.

index1     (input) int
Index of the first row or column.

index2     (input) int
Index of the second row or column.

transpose (input) int
If transpose==0, the distance between two rows in the matrix is calculated.
Otherwise, the distance between two columns in the matrix is calculated.
============================================================================
*/
{ double result = 0.;
  double sum1 = 0.;
  double sum2 = 0.;
  double denom1 = 0.;
  double denom2 = 0.;
  double tweight = 0.;
  if (transpose==0) /* Calculate the distance between two rows */
  { int i;
    for (i = 0; i < n; i++)
    { if (mask1[index1][i] && mask2[index2][i])
      { double term1 = data1[index1][i];
        double term2 = data2[index2][i];
        double w = weight[i];
        sum1 += w*term1;
        sum2 += w*term2;
        result += w*term1*term2;
        denom1 += w*term1*term1;
        denom2 += w*term2*term2;
        tweight += w;
      }
    }
  }
  else
  { int i;
    for (i = 0; i < n; i++)
    { if (mask1[i][index1] && mask2[i][index2])
      { double term1 = data1[i][index1];
        double term2 = data2[i][index2];
        double w = weight[i];
        sum1 += w*term1;
        sum2 += w*term2;
        result += w*term1*term2;
        denom1 += w*term1*term1;
        denom2 += w*term2*term2;
        tweight += w;
      }
    }
  }
  if (!tweight) return 0; /* usually due to empty clusters */
  result -= sum1 * sum2 / tweight;
  denom1 -= sum1 * sum1 / tweight;
  denom2 -= sum2 * sum2 / tweight;
  if (denom1 <= 0) return 1; /* include '<' to deal with roundoff errors */
  if (denom2 <= 0) return 1; /* include '<' to deal with roundoff errors */
  result = result / sqrt(denom1*denom2);
  result = 1. - result;
  return result;
}

/* ********************************************************************* */

static
double acorrelation (int n, double** data1, double** data2, int** mask1,
  int** mask2, const double weight[], int index1, int index2, int transpose)
/*
Purpose
=======

The acorrelation routine calculates the weighted Pearson distance between two
rows or columns, using the absolute value of the correlation.
This definition yields a semi-metric: d(a,b) >= 0, and d(a,b) = 0 iff a = b.
but the triangular inequality d(a,b) + d(b,c) >= d(a,c) does not hold
(e.g., choose b = a + c).

Arguments
=========

n      (input) int
The number of elements in a row or column. If transpose==0, then n is the number
of columns; otherwise, n is the number of rows.

data1  (input) double array
The data array containing the first vector.

data2  (input) double array
The data array containing the second vector.

mask1  (input) int array
This array which elements in data1 are missing. If mask1[i][j]==0, then
data1[i][j] is missing.

mask2  (input) int array
This array which elements in data2 are missing. If mask2[i][j]==0, then
data2[i][j] is missing.

weight (input) double[n]
The weights that are used to calculate the distance.

index1     (input) int
Index of the first row or column.

index2     (input) int
Index of the second row or column.

transpose (input) int
If transpose==0, the distance between two rows in the matrix is calculated.
Otherwise, the distance between two columns in the matrix is calculated.
============================================================================
*/
{ double result = 0.;
  double sum1 = 0.;
  double sum2 = 0.;
  double denom1 = 0.;
  double denom2 = 0.;
  double tweight = 0.;
  if (transpose==0) /* Calculate the distance between two rows */
  { int i;
    for (i = 0; i < n; i++)
    { if (mask1[index1][i] && mask2[index2][i])
      { double term1 = data1[index1][i];
        double term2 = data2[index2][i];
        double w = weight[i];
        sum1 += w*term1;
        sum2 += w*term2;
        result += w*term1*term2;
        denom1 += w*term1*term1;
        denom2 += w*term2*term2;
        tweight += w;
      }
    }
  }
  else
  { int i;
    for (i = 0; i < n; i++)
    { if (mask1[i][index1] && mask2[i][index2])
      { double term1 = data1[i][index1];
        double term2 = data2[i][index2];
        double w = weight[i];
        sum1 += w*term1;
        sum2 += w*term2;
        result += w*term1*term2;
        denom1 += w*term1*term1;
        denom2 += w*term2*term2;
        tweight += w;
      }
    }
  }
  if (!tweight) return 0; /* usually due to empty clusters */
  result -= sum1 * sum2 / tweight;
  denom1 -= sum1 * sum1 / tweight;
  denom2 -= sum2 * sum2 / tweight;
  if (denom1 <= 0) return 1; /* include '<' to deal with roundoff errors */
  if (denom2 <= 0) return 1; /* include '<' to deal with roundoff errors */
  result = fabs(result) / sqrt(denom1*denom2);
  result = 1. - result;
  return result;
}

/* ********************************************************************* */

static
double ucorrelation (int n, double** data1, double** data2, int** mask1,
  int** mask2, const double weight[], int index1, int index2, int transpose)
/*
Purpose
=======

The ucorrelation routine calculates the weighted Pearson distance between two
rows or columns, using the uncentered version of the Pearson correlation. In the
uncentered Pearson correlation, a zero mean is used for both vectors even if
the actual mean is nonzero.
This definition yields a semi-metric: d(a,b) >= 0, and d(a,b) = 0 iff a = b.
but the triangular inequality d(a,b) + d(b,c) >= d(a,c) does not hold
(e.g., choose b = a + c).

Arguments
=========

n      (input) int
The number of elements in a row or column. If transpose==0, then n is the number
of columns; otherwise, n is the number of rows.

data1  (input) double array
The data array containing the first vector.

data2  (input) double array
The data array containing the second vector.

mask1  (input) int array
This array which elements in data1 are missing. If mask1[i][j]==0, then
data1[i][j] is missing.

mask2  (input) int array
This array which elements in data2 are missing. If mask2[i][j]==0, then
data2[i][j] is missing.

weight (input) double[n]
The weights that are used to calculate the distance.

index1     (input) int
Index of the first row or column.

index2     (input) int
Index of the second row or column.

transpose (input) int
If transpose==0, the distance between two rows in the matrix is calculated.
Otherwise, the distance between two columns in the matrix is calculated.
============================================================================
*/
{ double result = 0.;
  double denom1 = 0.;
  double denom2 = 0.;
  int flag = 0;
  /* flag will remain zero if no nonzero combinations of mask1 and mask2 are
   * found.
   */
  if (transpose==0) /* Calculate the distance between two rows */
  { int i;
    for (i = 0; i < n; i++)
    { if (mask1[index1][i] && mask2[index2][i])
      { double term1 = data1[index1][i];
        double term2 = data2[index2][i];
        double w = weight[i];
        result += w*term1*term2;
        denom1 += w*term1*term1;
        denom2 += w*term2*term2;
        flag = 1;
      }
    }
  }
  else
  { int i;
    for (i = 0; i < n; i++)
    { if (mask1[i][index1] && mask2[i][index2])
      { double term1 = data1[i][index1];
        double term2 = data2[i][index2];
        double w = weight[i];
        result += w*term1*term2;
        denom1 += w*term1*term1;
        denom2 += w*term2*term2;
        flag = 1;
      }
    }
  }
  if (!flag) return 0.;
  if (denom1==0.) return 1.;
  if (denom2==0.) return 1.;
  result = result / sqrt(denom1*denom2);
  result = 1. - result;
  return result;
}

/* ********************************************************************* */

static
double uacorrelation (int n, double** data1, double** data2, int** mask1,
  int** mask2, const double weight[], int index1, int index2, int transpose)
/*
Purpose
=======

The uacorrelation routine calculates the weighted Pearson distance between two
rows or columns, using the absolute value of the uncentered version of the
Pearson correlation. In the uncentered Pearson correlation, a zero mean is used
for both vectors even if the actual mean is nonzero.
This definition yields a semi-metric: d(a,b) >= 0, and d(a,b) = 0 iff a = b.
but the triangular inequality d(a,b) + d(b,c) >= d(a,c) does not hold
(e.g., choose b = a + c).

Arguments
=========

n      (input) int
The number of elements in a row or column. If transpose==0, then n is the number
of columns; otherwise, n is the number of rows.

data1  (input) double array
The data array containing the first vector.

data2  (input) double array
The data array containing the second vector.

mask1  (input) int array
This array which elements in data1 are missing. If mask1[i][j]==0, then
data1[i][j] is missing.

mask2  (input) int array
This array which elements in data2 are missing. If mask2[i][j]==0, then
data2[i][j] is missing.

weight (input) double[n]
The weights that are used to calculate the distance.

index1     (input) int
Index of the first row or column.

index2     (input) int
Index of the second row or column.

transpose (input) int
If transpose==0, the distance between two rows in the matrix is calculated.
Otherwise, the distance between two columns in the matrix is calculated.
============================================================================
*/
{ double result = 0.;
  double denom1 = 0.;
  double denom2 = 0.;
  int flag = 0;
  /* flag will remain zero if no nonzero combinations of mask1 and mask2 are
   * found.
   */
  if (transpose==0) /* Calculate the distance between two rows */
  { int i;
    for (i = 0; i < n; i++)
    { if (mask1[index1][i] && mask2[index2][i])
      { double term1 = data1[index1][i];
        double term2 = data2[index2][i];
        double w = weight[i];
        result += w*term1*term2;
        denom1 += w*term1*term1;
        denom2 += w*term2*term2;
        flag = 1;
      }
    }
  }
  else
  { int i;
    for (i = 0; i < n; i++)
    { if (mask1[i][index1] && mask2[i][index2])
      { double term1 = data1[i][index1];
        double term2 = data2[i][index2];
        double w = weight[i];
        result += w*term1*term2;
        denom1 += w*term1*term1;
        denom2 += w*term2*term2;
        flag = 1;
      }
    }
  }
  if (!flag) return 0.;
  if (denom1==0.) return 1.;
  if (denom2==0.) return 1.;
  result = fabs(result) / sqrt(denom1*denom2);
  result = 1. - result;
  return result;
}

/* *********************************************************************  */

static
double spearman (int n, double** data1, double** data2, int** mask1,
  int** mask2, const double weight[], int index1, int index2, int transpose)
/*
Purpose
=======

The spearman routine calculates the Spearman distance between two rows or
columns. The Spearman distance is defined as one minus the Spearman rank
correlation.

Arguments
=========

n      (input) int
The number of elements in a row or column. If transpose==0, then n is the number
of columns; otherwise, n is the number of rows.

data1  (input) double array
The data array containing the first vector.

data2  (input) double array
The data array containing the second vector.

mask1  (input) int array
This array which elements in data1 are missing. If mask1[i][j]==0, then
data1[i][j] is missing.

mask2  (input) int array
This array which elements in data2 are missing. If mask2[i][j]==0, then
data2[i][j] is missing.

weight (input) double[n]
These weights are ignored, but included for consistency with other distance
measures.

index1     (input) int
Index of the first row or column.

index2     (input) int
Index of the second row or column.

transpose (input) int
If transpose==0, the distance between two rows in the matrix is calculated.
Otherwise, the distance between two columns in the matrix is calculated.
============================================================================
*/
{ int i;
  int m = 0;
  double* rank1;
  double* rank2;
  double result = 0.;
  double denom1 = 0.;
  double denom2 = 0.;
  double avgrank;
  double* tdata1;
  double* tdata2;
  tdata1 = malloc(n*sizeof(double));
  if(!tdata1) return 0.0; /* Memory allocation error */
  tdata2 = malloc(n*sizeof(double));
  if(!tdata2) /* Memory allocation error */
  { free(tdata1);
    return 0.0;
  }
  if (transpose==0)
  { for (i = 0; i < n; i++)
    { if (mask1[index1][i] && mask2[index2][i])
      { tdata1[m] = data1[index1][i];
        tdata2[m] = data2[index2][i];
        m++;
      }
    }
  }
  else
  { for (i = 0; i < n; i++)
    { if (mask1[i][index1] && mask2[i][index2])
      { tdata1[m] = data1[i][index1];
        tdata2[m] = data2[i][index2];
        m++;
      }
    }
  }
  if (m==0)
  { free(tdata1);
    free(tdata2);
    return 0;
  }
  rank1 = getrank(m, tdata1);
  free(tdata1);
  if(!rank1)
  { free(tdata2);
    return 0.0; /* Memory allocation error */
  }
  rank2 = getrank(m, tdata2);
  free(tdata2);
  if(!rank2) /* Memory allocation error */
  { free(rank1);
    return 0.0;
  }
  avgrank = 0.5*(m-1); /* Average rank */
  for (i = 0; i < m; i++)
  { const double value1 = rank1[i];
    const double value2 = rank2[i];
    result += value1 * value2;
    denom1 += value1 * value1;
    denom2 += value2 * value2;
  }
  /* Note: denom1 and denom2 cannot be calculated directly from the number
   * of elements. If two elements have the same rank, the squared sum of
   * their ranks will change.
   */
  free(rank1);
  free(rank2);
  result /= m;
  denom1 /= m;
  denom2 /= m;
  result -= avgrank * avgrank;
  denom1 -= avgrank * avgrank;
  denom2 -= avgrank * avgrank;
  if (denom1 <= 0) return 1; /* include '<' to deal with roundoff errors */
  if (denom2 <= 0) return 1; /* include '<' to deal with roundoff errors */
  result = result / sqrt(denom1*denom2);
  result = 1. - result;
  return result;
}

/* *********************************************************************  */

static
double kendall (int n, double** data1, double** data2, int** mask1, int** mask2,
  const double weight[], int index1, int index2, int transpose)
/*
Purpose
=======

The kendall routine calculates the Kendall distance between two
rows or columns. The Kendall distance is defined as one minus Kendall's tau.

Arguments
=========

n      (input) int
The number of elements in a row or column. If transpose==0, then n is the number
of columns; otherwise, n is the number of rows.

data1  (input) double array
The data array containing the first vector.

data2  (input) double array
The data array containing the second vector.

mask1  (input) int array
This array which elements in data1 are missing. If mask1[i][j]==0, then
data1[i][j] is missing.

mask2  (input) int array
This array which elements in data2 are missing. If mask2[i][j]==0, then
data2[i][j] is missing.

weight (input) double[n]
These weights are ignored, but included for consistency with other distance
measures.

index1     (input) int
Index of the first row or column.

index2     (input) int
Index of the second row or column.

transpose (input) int
If transpose==0, the distance between two rows in the matrix is calculated.
Otherwise, the distance between two columns in the matrix is calculated.
============================================================================
*/
{ int con = 0;
  int dis = 0;
  int exx = 0;
  int exy = 0;
  int flag = 0;
  /* flag will remain zero if no nonzero combinations of mask1 and mask2 are
   * found.
   */
  double denomx;
  double denomy;
  double tau;
  int i, j;
  if (transpose==0)
  { for (i = 0; i < n; i++)
    { if (mask1[index1][i] && mask2[index2][i])
      { for (j = 0; j < i; j++)
        { if (mask1[index1][j] && mask2[index2][j])
          { double x1 = data1[index1][i];
            double x2 = data1[index1][j];
            double y1 = data2[index2][i];
            double y2 = data2[index2][j];
            if (x1 < x2 && y1 < y2) con++;
            if (x1 > x2 && y1 > y2) con++;
            if (x1 < x2 && y1 > y2) dis++;
            if (x1 > x2 && y1 < y2) dis++;
            if (x1 == x2 && y1 != y2) exx++;
            if (x1 != x2 && y1 == y2) exy++;
            flag = 1;
          }
        }
      }
    }
  }
  else
  { for (i = 0; i < n; i++)
    { if (mask1[i][index1] && mask2[i][index2])
      { for (j = 0; j < i; j++)
        { if (mask1[j][index1] && mask2[j][index2])
          { double x1 = data1[i][index1];
            double x2 = data1[j][index1];
            double y1 = data2[i][index2];
            double y2 = data2[j][index2];
            if (x1 < x2 && y1 < y2) con++;
            if (x1 > x2 && y1 > y2) con++;
            if (x1 < x2 && y1 > y2) dis++;
            if (x1 > x2 && y1 < y2) dis++;
            if (x1 == x2 && y1 != y2) exx++;
            if (x1 != x2 && y1 == y2) exy++;
            flag = 1;
          }
        }
      }
    }
  }
  if (!flag) return 0.;
  denomx = con + dis + exx;
  denomy = con + dis + exy;
  if (denomx==0) return 1;
  if (denomy==0) return 1;
  tau = (con-dis)/sqrt(denomx*denomy);
  return 1.-tau;
}

/* *********************************************************************  */

static double(*setmetric(char dist)) 
  (int, double**, double**, int**, int**, const double[], int, int, int)
{ switch(dist)
  { case 'e': return &euclid;
    case 'b': return &cityblock;
    case 'c': return &correlation;
    case 'a': return &acorrelation;
    case 'u': return &ucorrelation;
    case 'x': return &uacorrelation;
    case 's': return &spearman;
    case 'k': return &kendall;
    default: return &euclid;
  }
  return NULL; /* Never get here */
}

/* *********************************************************************  */

static double uniform(void)
/*
Purpose
=======

This routine returns a uniform random number between 0.0 and 1.0. Both 0.0
and 1.0 are excluded. This random number generator is described in:

Pierre l'Ecuyer
Efficient and Portable Combined Random Number Generators
Communications of the ACM, Volume 31, Number 6, June 1988, pages 742-749,774.

The first time this routine is called, it initializes the random number
generator using the current time. First, the current epoch time in seconds is
used as a seed for the random number generator in the C library. The first two
random numbers generated by this generator are used to initialize the random
number generator implemented in this routine.


Arguments
=========

None.


Return value
============

A double-precison number between 0.0 and 1.0.
============================================================================
*/
{ int z;
  static const int m1 = 2147483563;
  static const int m2 = 2147483399;
  const double scale = 1.0/m1;

  static int s1 = 0;
  static int s2 = 0;

  if (s1==0 || s2==0) /* initialize */
  { unsigned int initseed = (unsigned int) time(0);
    srand(initseed);
    s1 = rand();
    s2 = rand();
  }

  do
  { int k;
    k = s1/53668;
    s1 = 40014*(s1-k*53668)-k*12211;
    if (s1 < 0) s1+=m1;
    k = s2/52774;
    s2 = 40692*(s2-k*52774)-k*3791;
    if(s2 < 0) s2+=m2;
    z = s1-s2;
    if(z < 1) z+=(m1-1);
  } while (z==m1); /* To avoid returning 1.0 */

  return z*scale;
}

/* ************************************************************************ */

static int binomial(int n, double p)
/*
Purpose
=======

This routine generates a random number between 0 and n inclusive, following
the binomial distribution with probability p and n trials. The routine is
based on the BTPE algorithm, described in:

Voratas Kachitvichyanukul and Bruce W. Schmeiser:
Binomial Random Variate Generation
Communications of the ACM, Volume 31, Number 2, February 1988, pages 216-222.


Arguments
=========

p          (input) double
The probability of a single event. This probability should be less than or
equal to 0.5.

n          (input) int
The number of trials.


Return value
============

An integer drawn from a binomial distribution with parameters (p, n).

============================================================================
*/
{ const double q = 1 - p;
  if (n*p < 30.0) /* Algorithm BINV */
  { const double s = p/q;
    const double a = (n+1)*s;
    double r = exp(n*log(q)); /* pow() causes a crash on AIX */
    int x = 0;
    double u = uniform();
    while(1)
    { if (u < r) return x;
      u-=r;
      x++;
      r *= (a/x)-s;
    }
  }
  else /* Algorithm BTPE */
  { /* Step 0 */
    const double fm = n*p + p;
    const int m = (int) fm;
    const double p1 = floor(2.195*sqrt(n*p*q) -4.6*q) + 0.5;
    const double xm = m + 0.5;
    const double xl = xm - p1;
    const double xr = xm + p1;
    const double c = 0.134 + 20.5/(15.3+m);
    const double a = (fm-xl)/(fm-xl*p);
    const double b = (xr-fm)/(xr*q);
    const double lambdal = a*(1.0+0.5*a);
    const double lambdar = b*(1.0+0.5*b);
    const double p2 = p1*(1+2*c);
    const double p3 = p2 + c/lambdal;
    const double p4 = p3 + c/lambdar;
    while (1)
    { /* Step 1 */
      int y;
      int k;
      double u = uniform();
      double v = uniform();
      u *= p4;
      if (u <= p1) return (int)(xm-p1*v+u);
      /* Step 2 */
      if (u > p2)
      { /* Step 3 */
        if (u > p3)
        { /* Step 4 */
          y = (int)(xr-log(v)/lambdar);
          if (y > n) continue;
          /* Go to step 5 */
          v = v*(u-p3)*lambdar;
        }
        else
        { y = (int)(xl+log(v)/lambdal);
          if (y < 0) continue;
          /* Go to step 5 */
          v = v*(u-p2)*lambdal;
        }
      }
      else
      { const double x = xl + (u-p1)/c;
        v = v*c + 1.0 - fabs(m-x+0.5)/p1;
        if (v > 1) continue;
        /* Go to step 5 */
        y = (int)x;
      }
      /* Step 5 */
      /* Step 5.0 */
      k = abs(y-m);
      if (k > 20 && k < 0.5*n*p*q-1.0)
      { /* Step 5.2 */
        double rho = (k/(n*p*q))*((k*(k/3.0 + 0.625) + 0.1666666666666)/(n*p*q)+0.5);
        double t = -k*k/(2*n*p*q);
        double A = log(v);
        if (A < t-rho) return y;
        else if (A > t+rho) continue;
        else
        { /* Step 5.3 */
          double x1 = y+1;
          double f1 = m+1;
          double z = n+1-m;
          double w = n-y+1;
          double x2 = x1*x1;
          double f2 = f1*f1;
          double z2 = z*z;
          double w2 = w*w;
          if (A > xm * log(f1/x1) + (n-m+0.5)*log(z/w)
                + (y-m)*log(w*p/(x1*q))
                + (13860.-(462.-(132.-(99.-140./f2)/f2)/f2)/f2)/f1/166320.
                + (13860.-(462.-(132.-(99.-140./z2)/z2)/z2)/z2)/z/166320.
                + (13860.-(462.-(132.-(99.-140./x2)/x2)/x2)/x2)/x1/166320.
                + (13860.-(462.-(132.-(99.-140./w2)/w2)/w2)/w2)/w/166320.)
             continue;
          return y;
        }
      }
      else
      { /* Step 5.1 */
        int i;
        const double s = p/q;
        const double aa = s*(n+1);
        double f = 1.0;
        for (i = m; i < y; f *= (aa/(++i)-s));
        for (i = y; i < m; f /= (aa/(++i)-s));
        if (v > f) continue;
        return y;
      }
    }
  }
  /* Never get here */
  return -1;
}

/* ************************************************************************ */

static void randomassign (int nclusters, int nelements, int clusterid[])
/*
Purpose
=======

The randomassign routine performs an initial random clustering, needed for
k-means or k-median clustering. Elements (genes or microarrays) are randomly
assigned to clusters. The number of elements in each cluster is chosen
randomly, making sure that each cluster will receive at least one element.


Arguments
=========

nclusters  (input) int
The number of clusters.

nelements  (input) int
The number of elements to be clustered (i.e., the number of genes or microarrays
to be clustered).

clusterid  (output) int[nelements]
The cluster number to which an element was assigned.

============================================================================
*/
{ int i, j;
  int k = 0;
  double p;
  int n = nelements-nclusters;
  /* Draw the number of elements in each cluster from a multinomial
   * distribution, reserving ncluster elements to set independently
   * in order to guarantee that none of the clusters are empty.
   */
  for (i = 0; i < nclusters-1; i++)
  { p = 1.0/(nclusters-i);
    j = binomial(n, p);
    n -= j;
    j += k+1; /* Assign at least one element to cluster i */
    for ( ; k < j; k++) clusterid[k] = i;
  }
  /* Assign the remaining elements to the last cluster */
  for ( ; k < nelements; k++) clusterid[k] = i;

  /* Create a random permutation of the cluster assignments */
  for (i = 0; i < nelements; i++)
  { j = (int) (i + (nelements-i)*uniform());
    k = clusterid[j];
    clusterid[j] = clusterid[i];
    clusterid[i] = k;
  }

  return;
}

/* ********************************************************************* */

static void getclustermeans(int nclusters, int nrows, int ncolumns,
  double** data, int** mask, int clusterid[], double** cdata, int** cmask,
  int transpose)
/*
Purpose
=======

The getclustermeans routine calculates the cluster centroids, given to which
cluster each element belongs. The centroid is defined as the mean over all
elements for each dimension.

Arguments
=========

nclusters  (input) int
The number of clusters.

nrows     (input) int
The number of rows in the gene expression data matrix, equal to the number of
genes.

ncolumns  (input) int
The number of columns in the gene expression data matrix, equal to the number of
microarrays.

data       (input) double[nrows][ncolumns]
The array containing the gene expression data.

mask       (input) int[nrows][ncolumns]
This array shows which data values are missing. If mask[i][j]==0, then
data[i][j] is missing.

clusterid  (output) int[nrows] if transpose==0
                    int[ncolumns] if transpose==1
The cluster number to which each element belongs. If transpose==0, then the
dimension of clusterid is equal to nrows (the number of genes). Otherwise, it
is equal to ncolumns (the number of microarrays).

cdata      (output) double[nclusters][ncolumns] if transpose==0
                    double[nrows][nclusters] if transpose==1
On exit of getclustermeans, this array contains the cluster centroids.

cmask      (output) int[nclusters][ncolumns] if transpose==0
                    int[nrows][nclusters] if transpose==1
This array shows which data values of are missing for each centroid. If
cmask[i][j]==0, then cdata[i][j] is missing. A data value is missing for
a centroid if all corresponding data values of the cluster members are missing.

transpose  (input) int
If transpose==0, clusters of rows (genes) are specified. Otherwise, clusters of
columns (microarrays) are specified.

========================================================================
*/
{ int i, j, k;
  if (transpose==0)
  { for (i = 0; i < nclusters; i++)
    { for (j = 0; j < ncolumns; j++)
      { cmask[i][j] = 0;
        cdata[i][j] = 0.;
      }
    }
    for (k = 0; k < nrows; k++)
    { i = clusterid[k];
      for (j = 0; j < ncolumns; j++)
      { if (mask[k][j] != 0)
        { cdata[i][j]+=data[k][j];
          cmask[i][j]++;
        }
      }
    }
    for (i = 0; i < nclusters; i++)
    { for (j = 0; j < ncolumns; j++)
      { if (cmask[i][j]>0)
        { cdata[i][j] /= cmask[i][j];
          cmask[i][j] = 1;
        }
      }
    }
  }
  else
  { for (i = 0; i < nrows; i++)
    { for (j = 0; j < nclusters; j++)
      { cdata[i][j] = 0.;
        cmask[i][j] = 0;
      }
    }
    for (k = 0; k < ncolumns; k++)
    { i = clusterid[k];
      for (j = 0; j < nrows; j++)
      { if (mask[j][k] != 0)
        { cdata[j][i]+=data[j][k];
          cmask[j][i]++;
        }
      }
    }
    for (i = 0; i < nrows; i++)
    { for (j = 0; j < nclusters; j++)
      { if (cmask[i][j]>0)
        { cdata[i][j] /= cmask[i][j];
          cmask[i][j] = 1;
        }
      }
    }
  }
}

/* ********************************************************************* */

static void
getclustermedians(int nclusters, int nrows, int ncolumns,
  double** data, int** mask, int clusterid[], double** cdata, int** cmask,
  int transpose, double cache[])
/*
Purpose
=======

The getclustermedians routine calculates the cluster centroids, given to which
cluster each element belongs. The centroid is defined as the median over all
elements for each dimension.

Arguments
=========

nclusters  (input) int
The number of clusters.

nrows     (input) int
The number of rows in the gene expression data matrix, equal to the number of
genes.

ncolumns  (input) int
The number of columns in the gene expression data matrix, equal to the number of
microarrays.

data       (input) double[nrows][ncolumns]
The array containing the gene expression data.

mask       (input) int[nrows][ncolumns]
This array shows which data values are missing. If mask[i][j]==0, then
data[i][j] is missing.

clusterid  (output) int[nrows] if transpose==0
                    int[ncolumns] if transpose==1
The cluster number to which each element belongs. If transpose==0, then the
dimension of clusterid is equal to nrows (the number of genes). Otherwise, it
is equal to ncolumns (the number of microarrays).

cdata      (output) double[nclusters][ncolumns] if transpose==0
                    double[nrows][nclusters] if transpose==1
On exit of getclustermedians, this array contains the cluster centroids.

cmask      (output) int[nclusters][ncolumns] if transpose==0
                    int[nrows][nclusters] if transpose==1
This array shows which data values of are missing for each centroid. If
cmask[i][j]==0, then cdata[i][j] is missing. A data value is missing for
a centroid if all corresponding data values of the cluster members are missing.

transpose  (input) int
If transpose==0, clusters of rows (genes) are specified. Otherwise, clusters of
columns (microarrays) are specified.

cache      (input) double[nrows] if transpose==0
                   double[ncolumns] if transpose==1
This array should be allocated before calling getclustermedians; its contents
on input is not relevant. This array is used as a temporary storage space when
calculating the medians.

========================================================================
*/
{ int i, j, k;
  if (transpose==0)
  { for (i = 0; i < nclusters; i++)
    { for (j = 0; j < ncolumns; j++)
      { int count = 0;
        for (k = 0; k < nrows; k++)
        { if (i==clusterid[k] && mask[k][j])
          { cache[count] = data[k][j];
            count++;
          }
        }
        if (count>0)
        { cdata[i][j] = median(count,cache);
          cmask[i][j] = 1;
        }
        else
        { cdata[i][j] = 0.;
          cmask[i][j] = 0;
        }
      }
    }
  }
  else
  { for (i = 0; i < nclusters; i++)
    { for (j = 0; j < nrows; j++)
      { int count = 0;
        for (k = 0; k < ncolumns; k++)
        { if (i==clusterid[k] && mask[j][k])
          { cache[count] = data[j][k];
            count++;
          }
        }
        if (count>0)
        { cdata[j][i] = median(count,cache);
          cmask[j][i] = 1;
        }
        else
        { cdata[j][i] = 0.;
          cmask[j][i] = 0;
        }
      }
    }
  }
}
 
/* ********************************************************************* */

int getclustercentroids(int nclusters, int nrows, int ncolumns,
  double** data, int** mask, int clusterid[], double** cdata, int** cmask,
  int transpose, char method)
/*
Purpose
=======

The getclustercentroids routine calculates the cluster centroids, given to
which cluster each element belongs. Depending on the argument method, the
centroid is defined as either the mean or the median for each dimension over
all elements belonging to a cluster.

Arguments
=========

nclusters  (input) int
The number of clusters.

nrows     (input) int
The number of rows in the gene expression data matrix, equal to the number of
genes.

ncolumns  (input) int
The number of columns in the gene expression data matrix, equal to the number of
microarrays.

data       (input) double[nrows][ncolumns]
The array containing the gene expression data.

mask       (input) int[nrows][ncolumns]
This array shows which data values are missing. If mask[i][j]==0, then
data[i][j] is missing.

clusterid  (output) int[nrows] if transpose==0
                    int[ncolumns] if transpose==1
The cluster number to which each element belongs. If transpose==0, then the
dimension of clusterid is equal to nrows (the number of genes). Otherwise, it
is equal to ncolumns (the number of microarrays).

cdata      (output) double[nclusters][ncolumns] if transpose==0
                    double[nrows][nclusters] if transpose==1
On exit of getclustercentroids, this array contains the cluster centroids.

cmask      (output) int[nclusters][ncolumns] if transpose==0
                    int[nrows][nclusters] if transpose==1
This array shows which data values of are missing for each centroid. If
cmask[i][j]==0, then cdata[i][j] is missing. A data value is missing for
a centroid if all corresponding data values of the cluster members are missing.

transpose  (input) int
If transpose==0, clusters of rows (genes) are specified. Otherwise, clusters of
columns (microarrays) are specified.

method     (input) char
For method=='a', the centroid is defined as the mean over all elements
belonging to a cluster for each dimension.
For method=='m', the centroid is defined as the median over all elements
belonging to a cluster for each dimension.

Return value
============

The function returns an integer to indicate success or failure. If a
memory error occurs, or if method is not 'm' or 'a', getclustercentroids
returns 0. If successful, getclustercentroids returns 1.
========================================================================
*/
{ switch(method)
  { case 'm':
    { const int nelements = (transpose==0) ? nrows : ncolumns;
      double* cache = malloc(nelements*sizeof(double));
      if (!cache) return 0;
      getclustermedians(nclusters, nrows, ncolumns, data, mask, clusterid,
                        cdata, cmask, transpose, cache);
      free(cache);
      return 1;
    }
    case 'a':
    { getclustermeans(nclusters, nrows, ncolumns, data, mask, clusterid,
                      cdata, cmask, transpose);
      return 1;
    }
  }
  return 0;
}

/* ********************************************************************* */

void getclustermedoids(int nclusters, int nelements, double** distance,
  int clusterid[], int centroids[], double errors[])
/*
Purpose
=======

The getclustermedoids routine calculates the cluster centroids, given to which
cluster each element belongs. The centroid is defined as the element with the
smallest sum of distances to the other elements.

Arguments
=========

nclusters  (input) int
The number of clusters.

nelements  (input) int
The total number of elements.

distmatrix (input) double array, ragged
  (number of rows is nelements, number of columns is equal to the row number)
The distance matrix. To save space, the distance matrix is given in the
form of a ragged array. The distance matrix is symmetric and has zeros
on the diagonal. See distancematrix for a description of the content.

clusterid  (output) int[nelements]
The cluster number to which each element belongs.

centroid   (output) int[nclusters]
The index of the element that functions as the centroid for each cluster.

errors     (output) double[nclusters]
The within-cluster sum of distances between the items and the cluster
centroid.

========================================================================
*/
{ int i, j, k;
  for (j = 0; j < nclusters; j++) errors[j] = DBL_MAX;
  for (i = 0; i < nelements; i++)
  { double d = 0.0;
    j = clusterid[i];
    for (k = 0; k < nelements; k++)
    { if (i==k || clusterid[k]!=j) continue;
      d += (i < k ? distance[k][i] : distance[i][k]);
      if (d > errors[j]) break;
    }
    if (d < errors[j])
    { errors[j] = d;
      centroids[j] = i;
    }
  }
}

/* ********************************************************************* */

static int
kmeans(int nclusters, int nrows, int ncolumns, double** data, int** mask,
  double weight[], int transpose, int npass, char dist,
  double** cdata, int** cmask, int clusterid[], double* error,
  int tclusterid[], int counts[], int mapping[])
{ int i, j, k;
  const int nelements = (transpose==0) ? nrows : ncolumns;
  const int ndata = (transpose==0) ? ncolumns : nrows;
  int ifound = 1;
  int ipass = 0;
  /* Set the metric function as indicated by dist */
  double (*metric)
    (int, double**, double**, int**, int**, const double[], int, int, int) =
       setmetric(dist);

  /* We save the clustering solution periodically and check if it reappears */
  int* saved = malloc(nelements*sizeof(int));
  if (saved==NULL) return -1;

  *error = DBL_MAX;

  do
  { double total = DBL_MAX;
    int counter = 0;
    int period = 10;

    /* Perform the EM algorithm. First, randomly assign elements to clusters. */
    if (npass!=0) randomassign (nclusters, nelements, tclusterid);

    for (i = 0; i < nclusters; i++) counts[i] = 0;
    for (i = 0; i < nelements; i++) counts[tclusterid[i]]++;

    /* Start the loop */
    while(1)
    { double previous = total;
      total = 0.0;

      if (counter % period == 0) /* Save the current cluster assignments */
      { for (i = 0; i < nelements; i++) saved[i] = tclusterid[i];
        if (period < INT_MAX / 2) period *= 2;
      }
      counter++;

      /* Find the center */
      getclustermeans(nclusters, nrows, ncolumns, data, mask, tclusterid,
                      cdata, cmask, transpose);

      for (i = 0; i < nelements; i++)
      /* Calculate the distances */
      { double distance;
        k = tclusterid[i];
        if (counts[k]==1) continue;
        /* No reassignment if that would lead to an empty cluster */
        /* Treat the present cluster as a special case */
        distance = metric(ndata,data,cdata,mask,cmask,weight,i,k,transpose);
        for (j = 0; j < nclusters; j++)
        { double tdistance;
          if (j==k) continue;
          tdistance = metric(ndata,data,cdata,mask,cmask,weight,i,j,transpose);
          if (tdistance < distance)
          { distance = tdistance;
            counts[tclusterid[i]]--;
            tclusterid[i] = j;
            counts[j]++;
          }
        }
        total += distance;
      }
      if (total>=previous) break;
      /* total>=previous is FALSE on some machines even if total and previous
       * are bitwise identical. */
      for (i = 0; i < nelements; i++)
        if (saved[i]!=tclusterid[i]) break;
      if (i==nelements)
        break; /* Identical solution found; break out of this loop */
    }

    if (npass<=1) 
    { *error = total;
      break;
    }

    for (i = 0; i < nclusters; i++) mapping[i] = -1;
    for (i = 0; i < nelements; i++)
    { j = tclusterid[i];
      k = clusterid[i];
      if (mapping[k] == -1) mapping[k] = j;
      else if (mapping[k] != j)
      { if (total < *error)
        { ifound = 1;
          *error = total;
          for (j = 0; j < nelements; j++) clusterid[j] = tclusterid[j];
        }
        break;
      }
    }
    if (i==nelements) ifound++; /* break statement not encountered */
  } while (++ipass < npass);

  free(saved);
  return ifound;
}

/* ---------------------------------------------------------------------- */

static int
kmedians(int nclusters, int nrows, int ncolumns, double** data, int** mask,
  double weight[], int transpose, int npass, char dist,
  double** cdata, int** cmask, int clusterid[], double* error,
  int tclusterid[], int counts[], int mapping[], double cache[])
{ int i, j, k;
  const int nelements = (transpose==0) ? nrows : ncolumns;
  const int ndata = (transpose==0) ? ncolumns : nrows;
  int ifound = 1;
  int ipass = 0;
  /* Set the metric function as indicated by dist */
  double (*metric)
    (int, double**, double**, int**, int**, const double[], int, int, int) =
       setmetric(dist);

  /* We save the clustering solution periodically and check if it reappears */
  int* saved = malloc(nelements*sizeof(int));
  if (saved==NULL) return -1;

  *error = DBL_MAX;

  do
  { double total = DBL_MAX;
    int counter = 0;
    int period = 10;

    /* Perform the EM algorithm. First, randomly assign elements to clusters. */
    if (npass!=0) randomassign (nclusters, nelements, tclusterid);

    for (i = 0; i < nclusters; i++) counts[i]=0;
    for (i = 0; i < nelements; i++) counts[tclusterid[i]]++;

    /* Start the loop */
    while(1)
    { double previous = total;
      total = 0.0;

      if (counter % period == 0) /* Save the current cluster assignments */
      { for (i = 0; i < nelements; i++) saved[i] = tclusterid[i];
        if (period < INT_MAX / 2) period *= 2;
      }
      counter++;

      /* Find the center */
      getclustermedians(nclusters, nrows, ncolumns, data, mask, tclusterid,
                        cdata, cmask, transpose, cache);

      for (i = 0; i < nelements; i++)
      /* Calculate the distances */
      { double distance;
        k = tclusterid[i];
        if (counts[k]==1) continue;
        /* No reassignment if that would lead to an empty cluster */
        /* Treat the present cluster as a special case */
        distance = metric(ndata,data,cdata,mask,cmask,weight,i,k,transpose);
        for (j = 0; j < nclusters; j++)
        { double tdistance;
          if (j==k) continue;
          tdistance = metric(ndata,data,cdata,mask,cmask,weight,i,j,transpose);
          if (tdistance < distance)
          { distance = tdistance;
            counts[tclusterid[i]]--;
            tclusterid[i] = j;
            counts[j]++;
          }
        }
        total += distance;
      }
      if (total>=previous) break;
      /* total>=previous is FALSE on some machines even if total and previous
       * are bitwise identical. */
      for (i = 0; i < nelements; i++)
        if (saved[i]!=tclusterid[i]) break;
      if (i==nelements)
        break; /* Identical solution found; break out of this loop */
    }

    if (npass<=1) 
    { *error = total;
      break;
    }

    for (i = 0; i < nclusters; i++) mapping[i] = -1;
    for (i = 0; i < nelements; i++)
    { j = tclusterid[i];
      k = clusterid[i];
      if (mapping[k] == -1) mapping[k] = j;
      else if (mapping[k] != j)
      { if (total < *error)
        { ifound = 1;
          *error = total;
          for (j = 0; j < nelements; j++) clusterid[j] = tclusterid[j];
        }
        break;
      }
    }
    if (i==nelements) ifound++; /* break statement not encountered */
  } while (++ipass < npass);

  free(saved);
  return ifound;
}

/* ********************************************************************* */

void kcluster (int nclusters, int nrows, int ncolumns,
  double** data, int** mask, double weight[], int transpose,
  int npass, char method, char dist,
  int clusterid[], double* error, int* ifound)
/*
Purpose
=======

The kcluster routine performs k-means or k-median clustering on a given set of
elements, using the specified distance measure. The number of clusters is given
by the user. Multiple passes are being made to find the optimal clustering
solution, each time starting from a different initial clustering.


Arguments
=========

nclusters  (input) int
The number of clusters to be found.

data       (input) double[nrows][ncolumns]
The array containing the data of the elements to be clustered (i.e., the gene
expression data).

mask       (input) int[nrows][ncolumns]
This array shows which data values are missing. If
mask[i][j] == 0, then data[i][j] is missing.

nrows     (input) int
The number of rows in the data matrix, equal to the number of genes.

ncolumns  (input) int
The number of columns in the data matrix, equal to the number of microarrays.

weight (input) double[n]
The weights that are used to calculate the distance.

transpose  (input) int
If transpose==0, the rows of the matrix are clustered. Otherwise, columns
of the matrix are clustered.

npass      (input) int
The number of times clustering is performed. Clustering is performed npass
times, each time starting from a different (random) initial assignment of 
genes to clusters. The clustering solution with the lowest within-cluster sum
of distances is chosen.
If npass==0, then the clustering algorithm will be run once, where the initial
assignment of elements to clusters is taken from the clusterid array.

method     (input) char
Defines whether the arithmetic mean (method=='a') or the median
(method=='m') is used to calculate the cluster center.

dist       (input) char
Defines which distance measure is used, as given by the table:
dist=='e': Euclidean distance
dist=='b': City-block distance
dist=='c': correlation
dist=='a': absolute value of the correlation
dist=='u': uncentered correlation
dist=='x': absolute uncentered correlation
dist=='s': Spearman's rank correlation
dist=='k': Kendall's tau
For other values of dist, the default (Euclidean distance) is used.

clusterid  (output; input) int[nrows] if transpose==0
                           int[ncolumns] if transpose==1
The cluster number to which a gene or microarray was assigned. If npass==0,
then on input clusterid contains the initial clustering assignment from which
the clustering algorithm starts. On output, it contains the clustering solution
that was found.

error      (output) double*
The sum of distances to the cluster center of each item in the optimal k-means
clustering solution that was found.

ifound     (output) int*
The number of times the optimal clustering solution was
found. The value of ifound is at least 1; its maximum value is npass. If the
number of clusters is larger than the number of elements being clustered,
*ifound is set to 0 as an error code. If a memory allocation error occurs,
*ifound is set to -1.

========================================================================
*/
{ const int nelements = (transpose==0) ? nrows : ncolumns;
  const int ndata = (transpose==0) ? ncolumns : nrows;

  int i;
  int ok;
  int* tclusterid;
  int* mapping = NULL;
  double** cdata;
  int** cmask;
  int* counts;

  if (nelements < nclusters)
  { *ifound = 0;
    return;
  }
  /* More clusters asked for than elements available */

  *ifound = -1;

  /* This will contain the number of elements in each cluster, which is
   * needed to check for empty clusters. */
  counts = malloc(nclusters*sizeof(int));
  if(!counts) return;

  /* Find out if the user specified an initial clustering */
  if (npass<=1) tclusterid = clusterid;
  else
  { tclusterid = malloc(nelements*sizeof(int));
    if (!tclusterid)
    { free(counts);
      return;
    }
    mapping = malloc(nclusters*sizeof(int));
    if (!mapping)
    { free(counts);
      free(tclusterid);
      return;
    }
    for (i = 0; i < nelements; i++) clusterid[i] = 0;
  }

  /* Allocate space to store the centroid data */
  if (transpose==0) ok = makedatamask(nclusters, ndata, &cdata, &cmask);
  else ok = makedatamask(ndata, nclusters, &cdata, &cmask);
  if(!ok)
  { free(counts);
    if(npass>1)
    { free(tclusterid);
      free(mapping);
      return;
    }
  }
  
  if (method=='m')
  { double* cache = malloc(nelements*sizeof(double));
    if(cache)
    { *ifound = kmedians(nclusters, nrows, ncolumns, data, mask, weight,
                         transpose, npass, dist, cdata, cmask, clusterid, error,
                         tclusterid, counts, mapping, cache);
      free(cache);
    }
  }
  else
    *ifound = kmeans(nclusters, nrows, ncolumns, data, mask, weight,
                     transpose, npass, dist, cdata, cmask, clusterid, error,
                     tclusterid, counts, mapping);

  /* Deallocate temporarily used space */
  if (npass > 1)
  { free(mapping);
    free(tclusterid);
  }

  if (transpose==0) freedatamask(nclusters, cdata, cmask);
  else freedatamask(ndata, cdata, cmask);

  free(counts);
}

/* *********************************************************************** */

void kmedoids (int nclusters, int nelements, double** distmatrix,
  int npass, int clusterid[], double* error, int* ifound)
/*
Purpose
=======

The kmedoids routine performs k-medoids clustering on a given set of elements,
using the distance matrix and the number of clusters passed by the user.
Multiple passes are being made to find the optimal clustering solution, each
time starting from a different initial clustering.


Arguments
=========

nclusters  (input) int
The number of clusters to be found.

nelements  (input) int
The number of elements to be clustered.

distmatrix (input) double array, ragged
  (number of rows is nelements, number of columns is equal to the row number)
The distance matrix. To save space, the distance matrix is given in the
form of a ragged array. The distance matrix is symmetric and has zeros
on the diagonal. See distancematrix for a description of the content.

npass      (input) int
The number of times clustering is performed. Clustering is performed npass
times, each time starting from a different (random) initial assignment of genes
to clusters. The clustering solution with the lowest within-cluster sum of
distances is chosen.
If npass==0, then the clustering algorithm will be run once, where the initial
assignment of elements to clusters is taken from the clusterid array.

clusterid  (output; input) int[nelements]
On input, if npass==0, then clusterid contains the initial clustering assignment
from which the clustering algorithm starts; all numbers in clusterid should be
between zero and nelements-1 inclusive. If npass!=0, clusterid is ignored on
input.
On output, clusterid contains the clustering solution that was found: clusterid
contains the number of the cluster to which each item was assigned. On output,
the number of a cluster is defined as the item number of the centroid of the
cluster.

error      (output) double
The sum of distances to the cluster center of each item in the optimal k-medoids
clustering solution that was found.

ifound     (output) int
If kmedoids is successful: the number of times the optimal clustering solution
was found. The value of ifound is at least 1; its maximum value is npass.
If the user requested more clusters than elements available, ifound is set
to 0. If kmedoids fails due to a memory allocation error, ifound is set to -1.

========================================================================
*/
{ int i, j, icluster;
  int* tclusterid;
  int* saved;
  int* centroids;
  double* errors;
  int ipass = 0;

  if (nelements < nclusters)
  { *ifound = 0;
    return;
  } /* More clusters asked for than elements available */

  *ifound = -1;

  /* We save the clustering solution periodically and check if it reappears */
  saved = malloc(nelements*sizeof(int));
  if (saved==NULL) return;

  centroids = malloc(nclusters*sizeof(int));
  if(!centroids)
  { free(saved);
    return;
  }

  errors = malloc(nclusters*sizeof(double));
  if(!errors)
  { free(saved);
    free(centroids);
    return;
  }

  /* Find out if the user specified an initial clustering */
  if (npass<=1) tclusterid = clusterid;
  else
  { tclusterid = malloc(nelements*sizeof(int));
    if(!tclusterid)
    { free(saved);
      free(centroids);
      free(errors);
      return;
    }
  }

  *error = DBL_MAX;
  do /* Start the loop */
  { double total = DBL_MAX;
    int counter = 0;
    int period = 10;

    if (npass!=0) randomassign (nclusters, nelements, tclusterid);
    while(1)
    { double previous = total;
      total = 0.0;

      if (counter % period == 0) /* Save the current cluster assignments */
      { for (i = 0; i < nelements; i++) saved[i] = tclusterid[i];
        if (period < INT_MAX / 2) period *= 2;
      }
      counter++;

      /* Find the center */
      getclustermedoids(nclusters, nelements, distmatrix, tclusterid,
                        centroids, errors);

      for (i = 0; i < nelements; i++)
      /* Find the closest cluster */
      { double distance = DBL_MAX;
        for (icluster = 0; icluster < nclusters; icluster++)
        { double tdistance;
          j = centroids[icluster];
          if (i==j)
          { distance = 0.0;
            tclusterid[i] = icluster;
            break;
          }
          tdistance = (i > j) ? distmatrix[i][j] : distmatrix[j][i];
          if (tdistance < distance)
          { distance = tdistance;
            tclusterid[i] = icluster;
          }
        }
        total += distance;
      }
      if (total>=previous) break;
      /* total>=previous is FALSE on some machines even if total and previous
       * are bitwise identical. */
      for (i = 0; i < nelements; i++)
        if (saved[i]!=tclusterid[i]) break;
      if (i==nelements)
        break; /* Identical solution found; break out of this loop */
    }

    for (i = 0; i < nelements; i++)
    { if (clusterid[i]!=centroids[tclusterid[i]])
      { if (total < *error)
        { *ifound = 1;
          *error = total;
          /* Replace by the centroid in each cluster. */
          for (j = 0; j < nelements; j++)
            clusterid[j] = centroids[tclusterid[j]];
        }
        break;
      }
    }
    if (i==nelements) (*ifound)++; /* break statement not encountered */
  } while (++ipass < npass);

  /* Deallocate temporarily used space */
  if (npass > 1) free(tclusterid);

  free(saved);
  free(centroids);
  free(errors);

  return;
}

/* ******************************************************************** */

double** distancematrix (int nrows, int ncolumns, double** data,
  int** mask, double weights[], char dist, int transpose)
/*
Purpose
=======

The distancematrix routine calculates the distance matrix between genes or
microarrays using their measured gene expression data. Several distance measures
can be used. The routine returns a pointer to a ragged array containing the
distances between the genes. As the distance matrix is symmetric, with zeros on
the diagonal, only the lower triangular half of the distance matrix is saved.
The distancematrix routine allocates space for the distance matrix. If the
parameter transpose is set to a nonzero value, the distances between the columns
(microarrays) are calculated, otherwise distances between the rows (genes) are
calculated.
If sufficient space in memory cannot be allocated to store the distance matrix,
the routine returns a NULL pointer, and all memory allocated so far for the
distance matrix is freed.


Arguments
=========

nrows      (input) int
The number of rows in the gene expression data matrix (i.e., the number of
genes)

ncolumns   (input) int
The number of columns in the gene expression data matrix (i.e., the number of
microarrays)

data       (input) double[nrows][ncolumns]
The array containing the gene expression data.

mask       (input) int[nrows][ncolumns]
This array shows which data values are missing. If mask[i][j]==0, then
data[i][j] is missing.

weight (input) double[n]
The weights that are used to calculate the distance. The length of this vector
is equal to the number of columns if the distances between genes are calculated,
or the number of rows if the distances between microarrays are calculated.

dist       (input) char
Defines which distance measure is used, as given by the table:
dist=='e': Euclidean distance
dist=='b': City-block distance
dist=='c': correlation
dist=='a': absolute value of the correlation
dist=='u': uncentered correlation
dist=='x': absolute uncentered correlation
dist=='s': Spearman's rank correlation
dist=='k': Kendall's tau
For other values of dist, the default (Euclidean distance) is used.

transpose  (input) int
If transpose is equal to zero, the distances between the rows is
calculated. Otherwise, the distances between the columns is calculated.
The former is needed when genes are being clustered; the latter is used
when microarrays are being clustered.

========================================================================
*/
{ /* First determine the size of the distance matrix */
  const int n = (transpose==0) ? nrows : ncolumns;
  const int ndata = (transpose==0) ? ncolumns : nrows;
  int i,j;
  double** matrix;

  /* Set the metric function as indicated by dist */
  double (*metric)
    (int, double**, double**, int**, int**, const double[], int, int, int) =
       setmetric(dist);

  if (n < 2) return NULL;

  /* Set up the ragged array */
  matrix = malloc(n*sizeof(double*));
  if(matrix==NULL) return NULL; /* Not enough memory available */
  matrix[0] = NULL;
  /* The zeroth row has zero columns. We allocate it anyway for convenience.*/
  for (i = 1; i < n; i++)
  { matrix[i] = malloc(i*sizeof(double));
    if (matrix[i]==NULL) break; /* Not enough memory available */
  }
  if (i < n) /* break condition encountered */
  { j = i;
    for (i = 1; i < j; i++) free(matrix[i]);
    return NULL;
  }

  /* Calculate the distances and save them in the ragged array */
  for (i = 1; i < n; i++)
    for (j = 0; j < i; j++)
      matrix[i][j]=metric(ndata,data,data,mask,mask,weights,i,j,transpose);

  return matrix;
}

/* ******************************************************************** */

double* calculate_weights(int nrows, int ncolumns, double** data, int** mask,
  double weights[], int transpose, char dist, double cutoff, double exponent)

/*
Purpose
=======

This function calculates the weights using the weighting scheme proposed by
Michael Eisen:
w[i] = 1.0 / sum_{j where d[i][j]<cutoff} (1 - d[i][j]/cutoff)^exponent
where the cutoff and the exponent are specified by the user.


Arguments
=========

nrows      (input) int
The number of rows in the gene expression data matrix, equal to the number of
genes.

ncolumns   (input) int
The number of columns in the gene expression data matrix, equal to the number of
microarrays.

data       (input) double[nrows][ncolumns]
The array containing the gene expression data.

mask       (input) int[nrows][ncolumns]
This array shows which data values are missing. If mask[i][j]==0, then
data[i][j] is missing.

weight     (input) int[ncolumns] if transpose==0,
                   int[nrows]    if transpose==1
The weights that are used to calculate the distance. The length of this vector
is ncolumns if gene weights are being clustered, and nrows if microarrays
weights are being clustered.

transpose (input) int
If transpose==0, the weights of the rows of the data matrix are calculated.
Otherwise, the weights of the columns of the data matrix are calculated.

dist      (input) char
Defines which distance measure is used, as given by the table:
dist=='e': Euclidean distance
dist=='b': City-block distance
dist=='c': correlation
dist=='a': absolute value of the correlation
dist=='u': uncentered correlation
dist=='x': absolute uncentered correlation
dist=='s': Spearman's rank correlation
dist=='k': Kendall's tau
For other values of dist, the default (Euclidean distance) is used.

cutoff    (input) double
The cutoff to be used to calculate the weights.

exponent  (input) double
The exponent to be used to calculate the weights.


Return value
============

The function returns a pointer to a newly allocated array containing the
calculated weights for the rows (if transpose==0) or columns (if
transpose==1). If not enough memory could be allocated to store the
weights array, the function returns NULL.

========================================================================
*/
{ int i,j;
  const int ndata = (transpose==0) ? ncolumns : nrows;
  const int nelements = (transpose==0) ? nrows : ncolumns;

  /* Set the metric function as indicated by dist */
  double (*metric)
    (int, double**, double**, int**, int**, const double[], int, int, int) =
       setmetric(dist);

  double* result = malloc(nelements*sizeof(double));
  if (!result) return NULL;
  memset(result, 0, nelements*sizeof(double));

  for (i = 0; i < nelements; i++)
  { result[i] += 1.0;
    for (j = 0; j < i; j++)
    { const double distance = metric(ndata, data, data, mask, mask, weights,
                                     i, j, transpose);
      if (distance < cutoff)
      { const double dweight = exp(exponent*log(1-distance/cutoff));
        /* pow() causes a crash on AIX */
        result[i] += dweight;
        result[j] += dweight;
      }
    }
  }
  for (i = 0; i < nelements; i++) result[i] = 1.0/result[i];
  return result;
}

/* ******************************************************************** */

void cuttree (int nelements, Node* tree, int nclusters, int clusterid[]) 

/*
Purpose
=======

The cuttree routine takes the output of a hierarchical clustering routine, and
divides the elements in the tree structure into clusters based on the
hierarchical clustering result. The number of clusters is specified by the user.

Arguments
=========

nelements      (input) int
The number of elements that were clustered.

tree           (input) Node[nelements-1]
The clustering solution. Each node in the array describes one linking event,
with tree[i].left and tree[i].right representig the elements that were joined.
The original elements are numbered 0..nelements-1, nodes are numbered
-1..-(nelements-1).

nclusters      (input) int
The number of clusters to be formed.

clusterid      (output) int[nelements]
The number of the cluster to which each element was assigned. Space for this
array should be allocated before calling the cuttree routine. If a memory
error occured, all elements in clusterid are set to -1.

========================================================================
*/
{ int i, j, k;
  int icluster = 0;
  const int n = nelements-nclusters; /* number of nodes to join */
  int* nodeid;
  for (i = nelements-2; i >= n; i--)
  { k = tree[i].left;
    if (k>=0)
    { clusterid[k] = icluster;
      icluster++;
    }
    k = tree[i].right;
    if (k>=0)
    { clusterid[k] = icluster;
      icluster++;
    }
  }
  nodeid = malloc(n*sizeof(int));
  if(!nodeid)
  { for (i = 0; i < nelements; i++) clusterid[i] = -1;
    return;
  }
  for (i = 0; i < n; i++) nodeid[i] = -1;
  for (i = n-1; i >= 0; i--)
  { if(nodeid[i]<0) 
    { j = icluster;
      nodeid[i] = j;
      icluster++;
    }
    else j = nodeid[i];
    k = tree[i].left;
    if (k<0) nodeid[-k-1] = j; else clusterid[k] = j;
    k = tree[i].right;
    if (k<0) nodeid[-k-1] = j; else clusterid[k] = j;
  }
  free(nodeid);
  return;
}

/* ******************************************************************** */

static
Node* pclcluster (int nrows, int ncolumns, double** data, int** mask,
  double weight[], double** distmatrix, char dist, int transpose)

/*

Purpose
=======

The pclcluster routine performs clustering using pairwise centroid-linking
on a given set of gene expression data, using the distance metric given by dist.

Arguments
=========

nrows     (input) int
The number of rows in the gene expression data matrix, equal to the number of
genes.

ncolumns  (input) int
The number of columns in the gene expression data matrix, equal to the number of
microarrays.

data       (input) double[nrows][ncolumns]
The array containing the gene expression data.

mask       (input) int[nrows][ncolumns]
This array shows which data values are missing. If
mask[i][j] == 0, then data[i][j] is missing.

weight     (input) double[ncolumns] if transpose==0;
                   double[nrows]    if transpose==1
The weights that are used to calculate the distance. The length of this vector
is ncolumns if genes are being clustered, and nrows if microarrays are being
clustered.

transpose  (input) int
If transpose==0, the rows of the matrix are clustered. Otherwise, columns
of the matrix are clustered.

dist       (input) char
Defines which distance measure is used, as given by the table:
dist=='e': Euclidean distance
dist=='b': City-block distance
dist=='c': correlation
dist=='a': absolute value of the correlation
dist=='u': uncentered correlation
dist=='x': absolute uncentered correlation
dist=='s': Spearman's rank correlation
dist=='k': Kendall's tau
For other values of dist, the default (Euclidean distance) is used.

distmatrix (input) double**
The distance matrix. This matrix is precalculated by the calling routine
treecluster. The pclcluster routine modifies the contents of distmatrix, but
does not deallocate it.

Return value
============

A pointer to a newly allocated array of Node structs, describing the
hierarchical clustering solution consisting of nelements-1 nodes. Depending on
whether genes (rows) or microarrays (columns) were clustered, nelements is
equal to nrows or ncolumns. See src/cluster.h for a description of the Node
structure.
If a memory error occurs, pclcluster returns NULL.
========================================================================
*/
{ int i, j;
  const int nelements = (transpose==0) ? nrows : ncolumns;
  int inode;
  const int ndata = transpose ? nrows : ncolumns;
  const int nnodes = nelements - 1;

  /* Set the metric function as indicated by dist */
  double (*metric)
    (int, double**, double**, int**, int**, const double[], int, int, int) =
       setmetric(dist);

  Node* result;
  double** newdata;
  int** newmask;
  int* distid = malloc(nelements*sizeof(int));
  if(!distid) return NULL;
  result = malloc(nnodes*sizeof(Node));
  if(!result)
  { free(distid);
    return NULL;
  }
  if(!makedatamask(nelements, ndata, &newdata, &newmask))
  { free(result);
    free(distid);
    return NULL; 
  }

  for (i = 0; i < nelements; i++) distid[i] = i;
  /* To remember which row/column in the distance matrix contains what */

  /* Storage for node data */
  if (transpose)
  { for (i = 0; i < nelements; i++)
    { for (j = 0; j < ndata; j++)
      { newdata[i][j] = data[j][i];
        newmask[i][j] = mask[j][i];
      }
    }
    data = newdata;
    mask = newmask;
  }
  else
  { for (i = 0; i < nelements; i++)
    { memcpy(newdata[i], data[i], ndata*sizeof(double));
      memcpy(newmask[i], mask[i], ndata*sizeof(int));
    }
    data = newdata;
    mask = newmask;
  }

  for (inode = 0; inode < nnodes; inode++)
  { /* Find the pair with the shortest distance */
    int is = 1;
    int js = 0;
    result[inode].distance = find_closest_pair(nelements-inode, distmatrix, &is, &js);
    result[inode].left = distid[js];
    result[inode].right = distid[is];

    /* Make node js the new node */
    for (i = 0; i < ndata; i++)
    { data[js][i] = data[js][i]*mask[js][i] + data[is][i]*mask[is][i];
      mask[js][i] += mask[is][i];
      if (mask[js][i]) data[js][i] /= mask[js][i];
    }
    free(data[is]);
    free(mask[is]);
    data[is] = data[nnodes-inode];
    mask[is] = mask[nnodes-inode];
  
    /* Fix the distances */
    distid[is] = distid[nnodes-inode];
    for (i = 0; i < is; i++)
      distmatrix[is][i] = distmatrix[nnodes-inode][i];
    for (i = is + 1; i < nnodes-inode; i++)
      distmatrix[i][is] = distmatrix[nnodes-inode][i];

    distid[js] = -inode-1;
    for (i = 0; i < js; i++)
      distmatrix[js][i] = metric(ndata,data,data,mask,mask,weight,js,i,0);
    for (i = js + 1; i < nnodes-inode; i++)
      distmatrix[i][js] = metric(ndata,data,data,mask,mask,weight,js,i,0);
  }

  /* Free temporarily allocated space */
  free(data[0]);
  free(mask[0]);
  free(data);
  free(mask);
  free(distid);
 
  return result;
}

/* ******************************************************************** */

static
int nodecompare(const void* a, const void* b)
/* Helper function for qsort. */
{ const Node* node1 = (const Node*)a;
  const Node* node2 = (const Node*)b;
  const double term1 = node1->distance;
  const double term2 = node2->distance;
  if (term1 < term2) return -1;
  if (term1 > term2) return +1;
  return 0;
}

/* ---------------------------------------------------------------------- */

static
Node* pslcluster (int nrows, int ncolumns, double** data, int** mask,
  double weight[], double** distmatrix, char dist, int transpose)

/*

Purpose
=======

The pslcluster routine performs single-linkage hierarchical clustering, using
either the distance matrix directly, if available, or by calculating the
distances from the data array. This implementation is based on the SLINK
algorithm, described in:
Sibson, R. (1973). SLINK: An optimally efficient algorithm for the single-link
cluster method. The Computer Journal, 16(1): 30-34.
The output of this algorithm is identical to conventional single-linkage
hierarchical clustering, but is much more memory-efficient and faster. Hence,
it can be applied to large data sets, for which the conventional single-
linkage algorithm fails due to lack of memory.


Arguments
=========

nrows     (input) int
The number of rows in the gene expression data matrix, equal to the number of
genes.

ncolumns  (input) int
The number of columns in the gene expression data matrix, equal to the number of
microarrays.

data       (input) double[nrows][ncolumns]
The array containing the gene expression data.

mask       (input) int[nrows][ncolumns]
This array shows which data values are missing. If
mask[i][j] == 0, then data[i][j] is missing.

weight (input) double[n]
The weights that are used to calculate the distance. The length of this vector
is ncolumns if genes are being clustered, and nrows if microarrays are being
clustered.

transpose  (input) int
If transpose==0, the rows of the matrix are clustered. Otherwise, columns
of the matrix are clustered.

dist       (input) char
Defines which distance measure is used, as given by the table:
dist=='e': Euclidean distance
dist=='b': City-block distance
dist=='c': correlation
dist=='a': absolute value of the correlation
dist=='u': uncentered correlation
dist=='x': absolute uncentered correlation
dist=='s': Spearman's rank correlation
dist=='k': Kendall's tau
For other values of dist, the default (Euclidean distance) is used.

distmatrix (input) double**
The distance matrix. If the distance matrix is passed by the calling routine
treecluster, it is used by pslcluster to speed up the clustering calculation.
The pslcluster routine does not modify the contents of distmatrix, and does
not deallocate it. If distmatrix is NULL, the pairwise distances are calculated
by the pslcluster routine from the gene expression data (the data and mask
arrays) and stored in temporary arrays. If distmatrix is passed, the original
gene expression data (specified by the data and mask arguments) are not needed
and are therefore ignored.


Return value
============

A pointer to a newly allocated array of Node structs, describing the
hierarchical clustering solution consisting of nelements-1 nodes. Depending on
whether genes (rows) or microarrays (columns) were clustered, nelements is
equal to nrows or ncolumns. See src/cluster.h for a description of the Node
structure.
If a memory error occurs, pslcluster returns NULL.

========================================================================
*/
{ int i, j, k;
  const int nelements = transpose ? ncolumns : nrows;
  const int nnodes = nelements - 1;
  int* vector;
  double* temp;
  int* index;
  Node* result;
  temp = malloc(nnodes*sizeof(double));
  if(!temp) return NULL;
  index = malloc(nelements*sizeof(int));
  if(!index)
  { free(temp);
    return NULL;
  }
  vector = malloc(nnodes*sizeof(int));
  if(!vector)
  { free(index);
    free(temp);
    return NULL;
  }
  result = malloc(nelements*sizeof(Node));
  if(!result)
  { free(vector);
    free(index);
    free(temp);
    return NULL;
  }

  for (i = 0; i < nnodes; i++) vector[i] = i;

  if(distmatrix)
  { for (i = 0; i < nrows; i++)
    { result[i].distance = DBL_MAX;
      for (j = 0; j < i; j++) temp[j] = distmatrix[i][j];
      for (j = 0; j < i; j++)
      { k = vector[j];
        if (result[j].distance >= temp[j])
        { if (result[j].distance < temp[k]) temp[k] = result[j].distance;
          result[j].distance = temp[j];
          vector[j] = i;
        }
        else if (temp[j] < temp[k]) temp[k] = temp[j];
      }
      for (j = 0; j < i; j++)
      {
        if (result[j].distance >= result[vector[j]].distance) vector[j] = i;
      }
    }
  }
  else
  { const int ndata = transpose ? nrows : ncolumns;
    /* Set the metric function as indicated by dist */
    double (*metric)
      (int, double**, double**, int**, int**, const double[], int, int, int) =
         setmetric(dist);

    for (i = 0; i < nelements; i++)
    { result[i].distance = DBL_MAX;
      for (j = 0; j < i; j++) temp[j] =
        metric(ndata, data, data, mask, mask, weight, i, j, transpose);
      for (j = 0; j < i; j++)
      { k = vector[j];
        if (result[j].distance >= temp[j])
        { if (result[j].distance < temp[k]) temp[k] = result[j].distance;
          result[j].distance = temp[j];
          vector[j] = i;
        }
        else if (temp[j] < temp[k]) temp[k] = temp[j];
      }
      for (j = 0; j < i; j++)
        if (result[j].distance >= result[vector[j]].distance) vector[j] = i;
    }
  }
  free(temp);

  for (i = 0; i < nnodes; i++) result[i].left = i;
  qsort(result, nnodes, sizeof(Node), nodecompare);

  for (i = 0; i < nelements; i++) index[i] = i;
  for (i = 0; i < nnodes; i++)
  { j = result[i].left;
    k = vector[j];
    result[i].left = index[j];
    result[i].right = index[k];
    index[k] = -i-1;
  }
  free(vector);
  free(index);

  result = realloc(result, nnodes*sizeof(Node));

  return result;
}
/* ******************************************************************** */

static Node* pmlcluster (int nelements, double** distmatrix)
/*

Purpose
=======

The pmlcluster routine performs clustering using pairwise maximum- (complete-)
linking on the given distance matrix.

Arguments
=========

nelements     (input) int
The number of elements to be clustered.

distmatrix (input) double**
The distance matrix, with nelements rows, each row being filled up to the
diagonal. The elements on the diagonal are not used, as they are assumed to be
zero. The distance matrix will be modified by this routine.

Return value
============

A pointer to a newly allocated array of Node structs, describing the
hierarchical clustering solution consisting of nelements-1 nodes. Depending on
whether genes (rows) or microarrays (columns) were clustered, nelements is
equal to nrows or ncolumns. See src/cluster.h for a description of the Node
structure.
If a memory error occurs, pmlcluster returns NULL.
========================================================================
*/
{ int j;
  int n;
  int* clusterid;
  Node* result;

  clusterid = malloc(nelements*sizeof(int));
  if(!clusterid) return NULL;
  result = malloc((nelements-1)*sizeof(Node));
  if (!result)
  { free(clusterid);
    return NULL;
  }

  /* Setup a list specifying to which cluster a gene belongs */
  for (j = 0; j < nelements; j++) clusterid[j] = j;

  for (n = nelements; n > 1; n--)
  { int is = 1;
    int js = 0;
    result[nelements-n].distance = find_closest_pair(n, distmatrix, &is, &js);

    /* Fix the distances */
    for (j = 0; j < js; j++)
      distmatrix[js][j] = max(distmatrix[is][j],distmatrix[js][j]);
    for (j = js+1; j < is; j++)
      distmatrix[j][js] = max(distmatrix[is][j],distmatrix[j][js]);
    for (j = is+1; j < n; j++)
      distmatrix[j][js] = max(distmatrix[j][is],distmatrix[j][js]);

    for (j = 0; j < is; j++) distmatrix[is][j] = distmatrix[n-1][j];
    for (j = is+1; j < n-1; j++) distmatrix[j][is] = distmatrix[n-1][j];

    /* Update clusterids */
    result[nelements-n].left = clusterid[is];
    result[nelements-n].right = clusterid[js];
    clusterid[js] = n-nelements-1;
    clusterid[is] = clusterid[n-1];
  }
  free(clusterid);

  return result;
}

/* ******************************************************************* */

static Node* palcluster (int nelements, double** distmatrix)
/*
Purpose
=======

The palcluster routine performs clustering using pairwise average
linking on the given distance matrix.

Arguments
=========

nelements     (input) int
The number of elements to be clustered.

distmatrix (input) double**
The distance matrix, with nelements rows, each row being filled up to the
diagonal. The elements on the diagonal are not used, as they are assumed to be
zero. The distance matrix will be modified by this routine.

Return value
============

A pointer to a newly allocated array of Node structs, describing the
hierarchical clustering solution consisting of nelements-1 nodes. Depending on
whether genes (rows) or microarrays (columns) were clustered, nelements is
equal to nrows or ncolumns. See src/cluster.h for a description of the Node
structure.
If a memory error occurs, palcluster returns NULL.
========================================================================
*/
{ int j;
  int n;
  int* clusterid;
  int* number;
  Node* result;

  clusterid = malloc(nelements*sizeof(int));
  if(!clusterid) return NULL;
  number = malloc(nelements*sizeof(int));
  if(!number)
  { free(clusterid);
    return NULL;
  }
  result = malloc((nelements-1)*sizeof(Node));
  if (!result)
  { free(clusterid);
    free(number);
    return NULL;
  }

  /* Setup a list specifying to which cluster a gene belongs, and keep track
   * of the number of elements in each cluster (needed to calculate the
   * average). */
  for (j = 0; j < nelements; j++)
  { number[j] = 1;
    clusterid[j] = j;
  }

  for (n = nelements; n > 1; n--)
  { int sum;
    int is = 1;
    int js = 0;
    result[nelements-n].distance = find_closest_pair(n, distmatrix, &is, &js);

    /* Save result */
    result[nelements-n].left = clusterid[is];
    result[nelements-n].right = clusterid[js];

    /* Fix the distances */
    sum = number[is] + number[js];
    for (j = 0; j < js; j++)
    { distmatrix[js][j] = distmatrix[is][j]*number[is]
                        + distmatrix[js][j]*number[js];
      distmatrix[js][j] /= sum;
    }
    for (j = js+1; j < is; j++)
    { distmatrix[j][js] = distmatrix[is][j]*number[is]
                        + distmatrix[j][js]*number[js];
      distmatrix[j][js] /= sum;
    }
    for (j = is+1; j < n; j++)
    { distmatrix[j][js] = distmatrix[j][is]*number[is]
                        + distmatrix[j][js]*number[js];
      distmatrix[j][js] /= sum;
    }

    for (j = 0; j < is; j++) distmatrix[is][j] = distmatrix[n-1][j];
    for (j = is+1; j < n-1; j++) distmatrix[j][is] = distmatrix[n-1][j];

    /* Update number of elements in the clusters */
    number[js] = sum;
    number[is] = number[n-1];

    /* Update clusterids */
    clusterid[js] = n-nelements-1;
    clusterid[is] = clusterid[n-1];
  }
  free(clusterid);
  free(number);

  return result;
}

/* ******************************************************************* */

Node* treecluster (int nrows, int ncolumns, double** data, int** mask,
  double weight[], int transpose, char dist, char method, double** distmatrix)
/*
Purpose
=======

The treecluster routine performs hierarchical clustering using pairwise
single-, maximum-, centroid-, or average-linkage, as defined by method, on a
given set of gene expression data, using the distance metric given by dist.
If successful, the function returns a pointer to a newly allocated Tree struct
containing the hierarchical clustering solution, and NULL if a memory error
occurs. The pointer should be freed by the calling routine to prevent memory
leaks.

Arguments
=========

nrows     (input) int
The number of rows in the data matrix, equal to the number of genes.

ncolumns  (input) int
The number of columns in the data matrix, equal to the number of microarrays.

data       (input) double[nrows][ncolumns]
The array containing the data of the vectors to be clustered.

mask       (input) int[nrows][ncolumns]
This array shows which data values are missing. If mask[i][j]==0, then
data[i][j] is missing.

weight (input) double array[n]
The weights that are used to calculate the distance.

transpose  (input) int
If transpose==0, the rows of the matrix are clustered. Otherwise, columns
of the matrix are clustered.

dist       (input) char
Defines which distance measure is used, as given by the table:
dist=='e': Euclidean distance
dist=='b': City-block distance
dist=='c': correlation
dist=='a': absolute value of the correlation
dist=='u': uncentered correlation
dist=='x': absolute uncentered correlation
dist=='s': Spearman's rank correlation
dist=='k': Kendall's tau
For other values of dist, the default (Euclidean distance) is used.

method     (input) char
Defines which hierarchical clustering method is used:
method=='s': pairwise single-linkage clustering
method=='m': pairwise maximum- (or complete-) linkage clustering
method=='a': pairwise average-linkage clustering
method=='c': pairwise centroid-linkage clustering
For the first three, either the distance matrix or the gene expression data is
sufficient to perform the clustering algorithm. For pairwise centroid-linkage
clustering, however, the gene expression data are always needed, even if the
distance matrix itself is available.

distmatrix (input) double**
The distance matrix. If the distance matrix is zero initially, the distance
matrix will be allocated and calculated from the data by treecluster, and
deallocated before treecluster returns. If the distance matrix is passed by the
calling routine, treecluster will modify the contents of the distance matrix as
part of the clustering algorithm, but will not deallocate it. The calling
routine should deallocate the distance matrix after the return from treecluster.

Return value
============

A pointer to a newly allocated array of Node structs, describing the
hierarchical clustering solution consisting of nelements-1 nodes. Depending on
whether genes (rows) or microarrays (columns) were clustered, nelements is
equal to nrows or ncolumns. See src/cluster.h for a description of the Node
structure.
If a memory error occurs, treecluster returns NULL.

========================================================================
*/
{ Node* result = NULL;
  const int nelements = (transpose==0) ? nrows : ncolumns;
  const int ldistmatrix = (distmatrix==NULL && method!='s') ? 1 : 0;

  if (nelements < 2) return NULL;

  /* Calculate the distance matrix if the user didn't give it */
  if(ldistmatrix)
  { distmatrix =
      distancematrix(nrows, ncolumns, data, mask, weight, dist, transpose);
    if (!distmatrix) return NULL; /* Insufficient memory */
  }

  switch(method)
  { case 's':
      result = pslcluster(nrows, ncolumns, data, mask, weight, distmatrix,
                          dist, transpose);
      break;
    case 'm':
      result = pmlcluster(nelements, distmatrix);
      break;
    case 'a':
      result = palcluster(nelements, distmatrix);
      break;
    case 'c':
      result = pclcluster(nrows, ncolumns, data, mask, weight, distmatrix,
                          dist, transpose);
      break;
  }

  /* Deallocate space for distance matrix, if it was allocated by treecluster */
  if(ldistmatrix)
  { int i;
    for (i = 1; i < nelements; i++) free(distmatrix[i]);
    free (distmatrix);
  }
 
  return result;
}

/* ******************************************************************* */

static
void somworker (int nrows, int ncolumns, double** data, int** mask,
  const double weights[], int transpose, int nxgrid, int nygrid,
  double inittau, double*** celldata, int niter, char dist)

{ const int nelements = (transpose==0) ? nrows : ncolumns;
  const int ndata = (transpose==0) ? ncolumns : nrows;
  int i, j;
  double* stddata = calloc(nelements,sizeof(double));
  int** dummymask;
  int ix, iy;
  int* index;
  int iter;
  /* Maximum radius in which nodes are adjusted */
  double maxradius = sqrt(nxgrid*nxgrid+nygrid*nygrid);

  /* Set the metric function as indicated by dist */
  double (*metric)
    (int, double**, double**, int**, int**, const double[], int, int, int) =
       setmetric(dist);

  /* Calculate the standard deviation for each row or column */
  if (transpose==0)
  { for (i = 0; i < nelements; i++)
    { int n = 0;
      for (j = 0; j < ndata; j++)
      { if (mask[i][j])
        { double term = data[i][j];
          term = term * term;
          stddata[i] += term;
          n++;
        }
      }
      if (stddata[i] > 0) stddata[i] = sqrt(stddata[i]/n);
      else stddata[i] = 1;
    }
  }
  else
  { for (i = 0; i < nelements; i++)
    { int n = 0;
      for (j = 0; j < ndata; j++)
      { if (mask[j][i])
        { double term = data[j][i];
          term = term * term;
          stddata[i] += term;
          n++;
        }
      }
      if (stddata[i] > 0) stddata[i] = sqrt(stddata[i]/n);
      else stddata[i] = 1;
    }
  }

  if (transpose==0)
  { dummymask = malloc(nygrid*sizeof(int*));
    for (i = 0; i < nygrid; i++)
    { dummymask[i] = malloc(ndata*sizeof(int));
      for (j = 0; j < ndata; j++) dummymask[i][j] = 1;
    }
  }
  else
  { dummymask = malloc(ndata*sizeof(int*));
    for (i = 0; i < ndata; i++)
    { dummymask[i] = malloc(sizeof(int));
      dummymask[i][0] = 1;
    }
  }

  /* Randomly initialize the nodes */
  for (ix = 0; ix < nxgrid; ix++)
  { for (iy = 0; iy < nygrid; iy++)
    { double sum = 0.;
      for (i = 0; i < ndata; i++)
      { double term = -1.0 + 2.0*uniform();
        celldata[ix][iy][i] = term;
        sum += term * term;
      }
      sum = sqrt(sum/ndata);
      for (i = 0; i < ndata; i++) celldata[ix][iy][i] /= sum;
    }
  }

  /* Randomize the order in which genes or arrays will be used */
  index = malloc(nelements*sizeof(int));
  for (i = 0; i < nelements; i++) index[i] = i;
  for (i = 0; i < nelements; i++)
  { j = (int) (i + (nelements-i)*uniform());
    ix = index[j];
    index[j] = index[i];
    index[i] = ix;
  }

  /* Start the iteration */
  for (iter = 0; iter < niter; iter++)
  { int ixbest = 0;
    int iybest = 0;
    int iobject = iter % nelements;
    iobject = index[iobject];
    if (transpose==0)
    { double closest = metric(ndata,data,celldata[ixbest],
        mask,dummymask,weights,iobject,iybest,transpose);
      double radius = maxradius * (1. - ((double)iter)/((double)niter));
      double tau = inittau * (1. - ((double)iter)/((double)niter));

      for (ix = 0; ix < nxgrid; ix++)
      { for (iy = 0; iy < nygrid; iy++)
        { double distance =
            metric (ndata,data,celldata[ix],
              mask,dummymask,weights,iobject,iy,transpose);
          if (distance < closest)
          { ixbest = ix;
            iybest = iy;
            closest = distance;
          }
        }
      }
      for (ix = 0; ix < nxgrid; ix++)
      { for (iy = 0; iy < nygrid; iy++)
        { if (sqrt((ix-ixbest)*(ix-ixbest)+(iy-iybest)*(iy-iybest))<radius)
          { double sum = 0.;
            for (i = 0; i < ndata; i++)
            { if (mask[iobject][i]==0) continue;
              celldata[ix][iy][i] +=
                tau * (data[iobject][i]/stddata[iobject]-celldata[ix][iy][i]);
            }
            for (i = 0; i < ndata; i++)
            { double term = celldata[ix][iy][i];
              term = term * term;
              sum += term;
            }
            if (sum>0)
            { sum = sqrt(sum/ndata);
              for (i = 0; i < ndata; i++) celldata[ix][iy][i] /= sum;
            }
          }
        }
      }
    }
    else
    { double closest;
      double** celldatavector = malloc(ndata*sizeof(double*));
      double radius = maxradius * (1. - ((double)iter)/((double)niter));
      double tau = inittau * (1. - ((double)iter)/((double)niter));

      for (i = 0; i < ndata; i++)
        celldatavector[i] = &(celldata[ixbest][iybest][i]);
      closest = metric(ndata,data,celldatavector,
        mask,dummymask,weights,iobject,0,transpose);
      for (ix = 0; ix < nxgrid; ix++)
      { for (iy = 0; iy < nygrid; iy++)
        { double distance;
          for (i = 0; i < ndata; i++)
            celldatavector[i] = &(celldata[ixbest][iybest][i]);
          distance =
            metric (ndata,data,celldatavector,
              mask,dummymask,weights,iobject,0,transpose);
          if (distance < closest)
          { ixbest = ix;
            iybest = iy;
            closest = distance;
          }
        }
      }
      free(celldatavector);
      for (ix = 0; ix < nxgrid; ix++)
      { for (iy = 0; iy < nygrid; iy++)
        { if (sqrt((ix-ixbest)*(ix-ixbest)+(iy-iybest)*(iy-iybest))<radius)
          { double sum = 0.;
            for (i = 0; i < ndata; i++)
            { if (mask[i][iobject]==0) continue;
              celldata[ix][iy][i] +=
                tau * (data[i][iobject]/stddata[iobject]-celldata[ix][iy][i]);
            }
            for (i = 0; i < ndata; i++)
            { double term = celldata[ix][iy][i];
              term = term * term;
              sum += term;
            }
            if (sum>0)
            { sum = sqrt(sum/ndata);
              for (i = 0; i < ndata; i++) celldata[ix][iy][i] /= sum;
            }
          }
        }
      }
    }
  }
  if (transpose==0)
    for (i = 0; i < nygrid; i++) free(dummymask[i]);
  else
    for (i = 0; i < ndata; i++) free(dummymask[i]);
  free(dummymask);
  free(stddata);
  free(index);
  return;
}

/* ******************************************************************* */

static
void somassign (int nrows, int ncolumns, double** data, int** mask,
  const double weights[], int transpose, int nxgrid, int nygrid,
  double*** celldata, char dist, int clusterid[][2])
/* Collect clusterids */
{ const int ndata = (transpose==0) ? ncolumns : nrows;
  int i,j;

  /* Set the metric function as indicated by dist */
  double (*metric)
    (int, double**, double**, int**, int**, const double[], int, int, int) =
       setmetric(dist);

  if (transpose==0)
  { int** dummymask = malloc(nygrid*sizeof(int*));
    for (i = 0; i < nygrid; i++)
    { dummymask[i] = malloc(ncolumns*sizeof(int));
      for (j = 0; j < ncolumns; j++) dummymask[i][j] = 1;
    }
    for (i = 0; i < nrows; i++)
    { int ixbest = 0;
      int iybest = 0;
      double closest = metric(ndata,data,celldata[ixbest],
        mask,dummymask,weights,i,iybest,transpose);
      int ix, iy;
      for (ix = 0; ix < nxgrid; ix++)
      { for (iy = 0; iy < nygrid; iy++)
        { double distance =
            metric (ndata,data,celldata[ix],
              mask,dummymask,weights,i,iy,transpose);
          if (distance < closest)
          { ixbest = ix;
            iybest = iy;
            closest = distance;
          }
        }
      }
      clusterid[i][0] = ixbest;
      clusterid[i][1] = iybest;
    }
    for (i = 0; i < nygrid; i++) free(dummymask[i]);
    free(dummymask);
  }
  else
  { double** celldatavector = malloc(ndata*sizeof(double*));
    int** dummymask = malloc(nrows*sizeof(int*));
    int ixbest = 0;
    int iybest = 0;
    for (i = 0; i < nrows; i++)
    { dummymask[i] = malloc(sizeof(int));
      dummymask[i][0] = 1;
    }
    for (i = 0; i < ncolumns; i++)
    { double closest;
      int ix, iy;
      for (j = 0; j < ndata; j++)
        celldatavector[j] = &(celldata[ixbest][iybest][j]);
      closest = metric(ndata,data,celldatavector,
        mask,dummymask,weights,i,0,transpose);
      for (ix = 0; ix < nxgrid; ix++)
      { for (iy = 0; iy < nygrid; iy++)
        { double distance;
          for(j = 0; j < ndata; j++)
            celldatavector[j] = &(celldata[ix][iy][j]);
          distance = metric(ndata,data,celldatavector,
            mask,dummymask,weights,i,0,transpose);
          if (distance < closest)
          { ixbest = ix;
            iybest = iy;
            closest = distance;
          }
        }
      }
      clusterid[i][0] = ixbest;
      clusterid[i][1] = iybest;
    }
    free(celldatavector);
    for (i = 0; i < nrows; i++) free(dummymask[i]);
    free(dummymask);
  }
  return;
}

/* ******************************************************************* */

void somcluster (int nrows, int ncolumns, double** data, int** mask,
  const double weight[], int transpose, int nxgrid, int nygrid,
  double inittau, int niter, char dist, double*** celldata, int clusterid[][2])
/*

Purpose
=======

The somcluster routine implements a self-organizing map (Kohonen) on a
rectangular grid, using a given set of vectors. The distance measure to be
used to find the similarity between genes and nodes is given by dist.

Arguments
=========

nrows     (input) int
The number of rows in the data matrix, equal to the number of genes.

ncolumns  (input) int
The number of columns in the data matrix, equal to the number of microarrays.

data       (input) double[nrows][ncolumns]
The array containing the gene expression data.

mask       (input) int[nrows][ncolumns]
This array shows which data values are missing. If
mask[i][j] == 0, then data[i][j] is missing.

weights    (input) double[ncolumns] if transpose==0;
                   double[nrows]    if transpose==1
The weights that are used to calculate the distance. The length of this vector
is ncolumns if genes are being clustered, or nrows if microarrays are being
clustered.

transpose  (input) int
If transpose==0, the rows (genes) of the matrix are clustered. Otherwise,
columns (microarrays) of the matrix are clustered.

nxgrid    (input) int
The number of grid cells horizontally in the rectangular topology of clusters.

nygrid    (input) int
The number of grid cells horizontally in the rectangular topology of clusters.

inittau    (input) double
The initial value of tau, representing the neighborhood function.

niter      (input) int
The number of iterations to be performed.

dist       (input) char
Defines which distance measure is used, as given by the table:
dist=='e': Euclidean distance
dist=='b': City-block distance
dist=='c': correlation
dist=='a': absolute value of the correlation
dist=='u': uncentered correlation
dist=='x': absolute uncentered correlation
dist=='s': Spearman's rank correlation
dist=='k': Kendall's tau
For other values of dist, the default (Euclidean distance) is used.

celldata (output) double[nxgrid][nygrid][ncolumns] if transpose==0;
                  double[nxgrid][nygrid][nrows]    if tranpose==1
The gene expression data for each node (cell) in the 2D grid. This can be
interpreted as the centroid for the cluster corresponding to that cell. If
celldata is NULL, then the centroids are not returned. If celldata is not
NULL, enough space should be allocated to store the centroid data before callingsomcluster.

clusterid (output), int[nrows][2]    if transpose==0;
                    int[ncolumns][2] if transpose==1
For each item (gene or microarray) that is clustered, the coordinates of the
cell in the 2D grid to which the item was assigned. If clusterid is NULL, the
cluster assignments are not returned. If clusterid is not NULL, enough memory
should be allocated to store the clustering information before calling
somcluster.

========================================================================
*/
{ const int nobjects = (transpose==0) ? nrows : ncolumns;
  const int ndata = (transpose==0) ? ncolumns : nrows;
  int i,j;
  const int lcelldata = (celldata==NULL) ? 0 : 1;

  if (nobjects < 2) return;

  if (lcelldata==0)
  { celldata = malloc(nxgrid*nygrid*ndata*sizeof(double**));
    for (i = 0; i < nxgrid; i++)
    { celldata[i] = malloc(nygrid*ndata*sizeof(double*));
      for (j = 0; j < nygrid; j++)
        celldata[i][j] = malloc(ndata*sizeof(double));
    }
  }

  somworker (nrows, ncolumns, data, mask, weight, transpose, nxgrid, nygrid,
    inittau, celldata, niter, dist);
  if (clusterid)
    somassign (nrows, ncolumns, data, mask, weight, transpose,
      nxgrid, nygrid, celldata, dist, clusterid);
  if(lcelldata==0)
  { for (i = 0; i < nxgrid; i++)
      for (j = 0; j < nygrid; j++)
        free(celldata[i][j]);
    for (i = 0; i < nxgrid; i++)
      free(celldata[i]);
    free(celldata);
  }
  return;
}

/* ******************************************************************** */

double clusterdistance (int nrows, int ncolumns, double** data,
  int** mask, double weight[], int n1, int n2, int index1[], int index2[],
  char dist, char method, int transpose)
              
/*
Purpose
=======

The clusterdistance routine calculates the distance between two clusters
containing genes or microarrays using the measured gene expression vectors. The
distance between clusters, given the genes/microarrays in each cluster, can be
defined in several ways. Several distance measures can be used.

The routine returns the distance in double precision.
If the parameter transpose is set to a nonzero value, the clusters are
interpreted as clusters of microarrays, otherwise as clusters of gene.

Arguments
=========

nrows     (input) int
The number of rows (i.e., the number of genes) in the gene expression data
matrix.

ncolumns      (input) int
The number of columns (i.e., the number of microarrays) in the gene expression
data matrix.

data       (input) double[nrows][ncolumns]
The array containing the data of the vectors.

mask       (input) int[nrows][ncolumns]
This array shows which data values are missing. If mask[i][j]==0, then
data[i][j] is missing.

weight     (input) double[ncolumns] if transpose==0;
                   double[nrows]    if transpose==1
The weights that are used to calculate the distance.

n1         (input) int
The number of elements in the first cluster.

n2         (input) int
The number of elements in the second cluster.

index1     (input) int[n1]
Identifies which genes/microarrays belong to the first cluster.

index2     (input) int[n2]
Identifies which genes/microarrays belong to the second cluster.

dist       (input) char
Defines which distance measure is used, as given by the table:
dist=='e': Euclidean distance
dist=='b': City-block distance
dist=='c': correlation
dist=='a': absolute value of the correlation
dist=='u': uncentered correlation
dist=='x': absolute uncentered correlation
dist=='s': Spearman's rank correlation
dist=='k': Kendall's tau
For other values of dist, the default (Euclidean distance) is used.

method     (input) char
Defines how the distance between two clusters is defined, given which genes
belong to which cluster:
method=='a': the distance between the arithmetic means of the two clusters
method=='m': the distance between the medians of the two clusters
method=='s': the smallest pairwise distance between members of the two clusters
method=='x': the largest pairwise distance between members of the two clusters
method=='v': average of the pairwise distances between members of the clusters

transpose  (input) int
If transpose is equal to zero, the distances between the rows is
calculated. Otherwise, the distances between the columns is calculated.
The former is needed when genes are being clustered; the latter is used
when microarrays are being clustered.

========================================================================
*/
{ /* Set the metric function as indicated by dist */
  double (*metric)
    (int, double**, double**, int**, int**, const double[], int, int, int) =
       setmetric(dist);

  /* if one or both clusters are empty, return */
  if (n1 < 1 || n2 < 1) return -1.0;
  /* Check the indices */
  if (transpose==0)
  { int i;
    for (i = 0; i < n1; i++)
    { int index = index1[i];
      if (index < 0 || index >= nrows) return -1.0;
    }
    for (i = 0; i < n2; i++)
    { int index = index2[i];
      if (index < 0 || index >= nrows) return -1.0;
    }
  }
  else
  { int i;
    for (i = 0; i < n1; i++)
    { int index = index1[i];
      if (index < 0 || index >= ncolumns) return -1.0;
    }
    for (i = 0; i < n2; i++)
    { int index = index2[i];
      if (index < 0 || index >= ncolumns) return -1.0;
    }
  }

  switch (method)
  { case 'a':
    { /* Find the center */
      int i,j,k;
      if (transpose==0)
      { double distance;
        double* cdata[2];
        int* cmask[2];
        int* count[2];
        count[0] = calloc(ncolumns,sizeof(int));
        count[1] = calloc(ncolumns,sizeof(int));
        cdata[0] = calloc(ncolumns,sizeof(double));
        cdata[1] = calloc(ncolumns,sizeof(double));
        cmask[0] = malloc(ncolumns*sizeof(int));
        cmask[1] = malloc(ncolumns*sizeof(int));
        for (i = 0; i < n1; i++)
        { k = index1[i];
          for (j = 0; j < ncolumns; j++)
            if (mask[k][j] != 0)
            { cdata[0][j] = cdata[0][j] + data[k][j];
              count[0][j] = count[0][j] + 1;
            }
        }
        for (i = 0; i < n2; i++)
        { k = index2[i];
          for (j = 0; j < ncolumns; j++)
            if (mask[k][j] != 0)
            { cdata[1][j] = cdata[1][j] + data[k][j];
              count[1][j] = count[1][j] + 1;
            }
        }
        for (i = 0; i < 2; i++)
          for (j = 0; j < ncolumns; j++)
          { if (count[i][j]>0)
            { cdata[i][j] = cdata[i][j] / count[i][j];
              cmask[i][j] = 1;
            }
            else
              cmask[i][j] = 0;
          }
        distance =
          metric (ncolumns,cdata,cdata,cmask,cmask,weight,0,1,0);
        for (i = 0; i < 2; i++)
        { free (cdata[i]);
          free (cmask[i]);
          free (count[i]);
        }
        return distance;
      }
      else
      { double distance;
        int** count = malloc(nrows*sizeof(int*));
        double** cdata = malloc(nrows*sizeof(double*));
        int** cmask = malloc(nrows*sizeof(int*));
        for (i = 0; i < nrows; i++)
        { count[i] = calloc(2,sizeof(int));
          cdata[i] = calloc(2,sizeof(double));
          cmask[i] = malloc(2*sizeof(int));
        }
        for (i = 0; i < n1; i++)
        { k = index1[i];
          for (j = 0; j < nrows; j++)
          { if (mask[j][k] != 0)
            { cdata[j][0] = cdata[j][0] + data[j][k];
              count[j][0] = count[j][0] + 1;
            }
          }
        }
        for (i = 0; i < n2; i++)
        { k = index2[i];
          for (j = 0; j < nrows; j++)
          { if (mask[j][k] != 0)
            { cdata[j][1] = cdata[j][1] + data[j][k];
              count[j][1] = count[j][1] + 1;
            }
          }
        }
        for (i = 0; i < nrows; i++)
          for (j = 0; j < 2; j++)
            if (count[i][j]>0)
            { cdata[i][j] = cdata[i][j] / count[i][j];
              cmask[i][j] = 1;
            }
            else
              cmask[i][j] = 0;
        distance = metric (nrows,cdata,cdata,cmask,cmask,weight,0,1,1);
        for (i = 0; i < nrows; i++)
        { free (count[i]);
          free (cdata[i]);
          free (cmask[i]);
        }
        free (count);
        free (cdata);
        free (cmask);
        return distance;
      }
    }
    case 'm':
    { int i, j, k;
      if (transpose==0)
      { double distance;
        double* temp = malloc(nrows*sizeof(double));
        double* cdata[2];
        int* cmask[2];
        for (i = 0; i < 2; i++)
        { cdata[i] = malloc(ncolumns*sizeof(double));
          cmask[i] = malloc(ncolumns*sizeof(int));
        }
        for (j = 0; j < ncolumns; j++)
        { int count = 0;
          for (k = 0; k < n1; k++)
          { i = index1[k];
            if (mask[i][j])
            { temp[count] = data[i][j];
              count++;
            }
          }
          if (count>0)
          { cdata[0][j] = median (count,temp);
            cmask[0][j] = 1;
          }
          else
          { cdata[0][j] = 0.;
            cmask[0][j] = 0;
          }
        }
        for (j = 0; j < ncolumns; j++)
        { int count = 0;
          for (k = 0; k < n2; k++)
          { i = index2[k];
            if (mask[i][j])
            { temp[count] = data[i][j];
              count++;
            }
          }
          if (count>0)
          { cdata[1][j] = median (count,temp);
            cmask[1][j] = 1;
          }
          else
          { cdata[1][j] = 0.;
            cmask[1][j] = 0;
          }
        }
        distance = metric (ncolumns,cdata,cdata,cmask,cmask,weight,0,1,0);
        for (i = 0; i < 2; i++)
        { free (cdata[i]);
          free (cmask[i]);
        }
        free(temp);
        return distance;
      }
      else
      { double distance;
        double* temp = malloc(ncolumns*sizeof(double));
        double** cdata = malloc(nrows*sizeof(double*));
        int** cmask = malloc(nrows*sizeof(int*));
        for (i = 0; i < nrows; i++)
        { cdata[i] = malloc(2*sizeof(double));
          cmask[i] = malloc(2*sizeof(int));
        }
        for (j = 0; j < nrows; j++)
        { int count = 0;
          for (k = 0; k < n1; k++)
          { i = index1[k];
            if (mask[j][i])
            { temp[count] = data[j][i];
              count++;
            }
          }
          if (count>0)
          { cdata[j][0] = median (count,temp);
            cmask[j][0] = 1;
          }
          else
          { cdata[j][0] = 0.;
            cmask[j][0] = 0;
          }
        }
        for (j = 0; j < nrows; j++)
        { int count = 0;
          for (k = 0; k < n2; k++)
          { i = index2[k];
            if (mask[j][i])
            { temp[count] = data[j][i];
              count++;
            }
          }
          if (count>0)
          { cdata[j][1] = median (count,temp);
            cmask[j][1] = 1;
          }
          else
          { cdata[j][1] = 0.;
            cmask[j][1] = 0;
          }
        }
        distance = metric (nrows,cdata,cdata,cmask,cmask,weight,0,1,1);
        for (i = 0; i < nrows; i++)
        { free (cdata[i]);
          free (cmask[i]);
        }
        free(cdata);
        free(cmask);
        free(temp);
        return distance;
      }
    }
    case 's':
    { int i1, i2, j1, j2;
      const int n = (transpose==0) ? ncolumns : nrows;
      double mindistance = DBL_MAX;
      for (i1 = 0; i1 < n1; i1++)
        for (i2 = 0; i2 < n2; i2++)
        { double distance;
          j1 = index1[i1];
          j2 = index2[i2];
          distance = metric (n,data,data,mask,mask,weight,j1,j2,transpose);
          if (distance < mindistance) mindistance = distance;
        }
      return mindistance;
    }
    case 'x':
    { int i1, i2, j1, j2;
      const int n = (transpose==0) ? ncolumns : nrows;
      double maxdistance = 0;
      for (i1 = 0; i1 < n1; i1++)
        for (i2 = 0; i2 < n2; i2++)
        { double distance;
          j1 = index1[i1];
          j2 = index2[i2];
          distance = metric (n,data,data,mask,mask,weight,j1,j2,transpose);
          if (distance > maxdistance) maxdistance = distance;
        }
      return maxdistance;
    }
    case 'v':
    { int i1, i2, j1, j2;
      const int n = (transpose==0) ? ncolumns : nrows;
      double distance = 0;
      for (i1 = 0; i1 < n1; i1++)
        for (i2 = 0; i2 < n2; i2++)
        { j1 = index1[i1];
          j2 = index2[i2];
          distance += metric (n,data,data,mask,mask,weight,j1,j2,transpose);
        }
      distance /= (n1*n2);
      return distance;
    }
  }
  /* Never get here */
  return -2.0;
}
