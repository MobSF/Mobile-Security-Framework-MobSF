/* ac_list.h - declarations for linked list functions
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

/*
 * Header for linked list implementation.
 */
#include "ac_types.h"

#ifndef AC_LIST_H
#define AC_LIST_H

/** Structure for internal list items. */
typedef struct ac_list_item {
    /** Pointer to the item itself. */
    void*                   item;
    
    /** Pointer to the next ac_list_item or NULL of this is the last item. */
    struct ac_list_item*    next;
} ac_list_item;

/** Structure for linked list. */
typedef struct {
    /** Pointer to first list item. */
    ac_list_item*   first;
    
    /** Pointer to last list item. */
    ac_list_item*   last;
} ac_list;

/**
 * Type for function pointers passed to ac_list_free used for freeing
 * complex item types.
 */
typedef ac_error_code (*ac_list_item_free_function)(void*, void*);

#ifdef __cplusplus
extern "C" ac_list* ac_list_new(void);
#else
ac_list* ac_list_new(void);
ac_error_code ac_list_free(ac_list*, ac_list_item_free_function, void*);
ac_error_code ac_list_add(ac_list*, void*);

/* Simple item freeing methods. */
ac_error_code ac_list_free_simple_item(void*, void*);
ac_error_code ac_list_free_keep_item(void*, void*);
#endif

#endif /* AC_LIST_H */

