/* ac_heap.c - functions used to debug memory allocation
   Copyright (C) 2007 Tideway Systems Limited.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "ac_heap.h"
#include "stdio.h"

static size_t total = 0;

void* ac_malloc(size_t size, char* file, int line) {
    void* result = malloc(size);
    total += size;

    if (result) {
        printf("malloc %p at %s:%d\n", result, file, line);
    } else {
        printf("malloc NULL at %s:%d\n", file, line);
    }
    printf("t %d\n", (int) total);
    return result;
}

void ac_free(void* p, char* file, int line) {
    printf("free %p at %s:%d\n", p, file, line);
    free(p);
}

