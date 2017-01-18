/* ac_list.c - functions for linked lists
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

#include "ac_list.h"
#include "ac_heap.h"

/**
 * Make a new, empty linked list. Returns a pointer to a list or NULL if an
 * error was encountered allocating heap space for the structure.
 */
ac_list*
ac_list_new(void) {
    ac_list* self = NULL;
    
    if ( (self = MALLOC(sizeof(ac_list)))) {
        self->first = NULL;
        self->last  = NULL;
    }
    
    return self;
}

/**
 * Free a list item. Pass a pointer to this function to ac_list_free when you
 * want only the heap space for the list items themselves will be freed.
 * Always returns AC_SUCCESS.
 */
ac_error_code
ac_list_free_simple_item(void* item, void* data) {
    FREE(item);
    return AC_SUCCESS;
}

/**
 * NOP list item free function. Pass a pointer to this function to
 * ac_list_free when you don't want the heap space for the list items to be
 * freed.
 */
ac_error_code
ac_list_free_keep_item(void* item, void* data) {
    return AC_SUCCESS;
}

/**
 * Free the ac_list at self. Heap space allocated for the list will be freed.
 * A function pointer should be provided in free_item for freeing resources
 * allocated for the items themselves. The function at free_item is called
 * once for each item added to the list. It is passed a pointer to the item
 * and workspace data pointer (given to ac_list_free in free_data).
 * passed to ac_list_free in free_data. The free_item function should return
 * AC_SUCCESS if it succeeds or AC_FAILURE if it fails.
 * 
 * Returns AC_SUCCESS if all the free_item calls succeed of AC_FAILURE if self
 * is NULL, or if any of the free_item calls fail.
 */
ac_error_code
ac_list_free(ac_list* self,
             ac_list_item_free_function free_item,
             void* free_data) {

    ac_list_item* list_item = NULL;
    ac_list_item* tmp = NULL;
    ac_error_code result = AC_SUCCESS;
    
    if ( ! self) {
        return AC_FAILURE;
    }
    
    list_item = self->first;
    
    while (list_item) {
        tmp = list_item->next;

        if (free_item(list_item->item, free_data) != AC_SUCCESS) {
            result = AC_FAILURE;
        }

        FREE(list_item);
        list_item = tmp;
    }
    
    FREE(self);
    
    return result;
}

/**
 * Add an item to a list. The item at item is appended to the list at self.
 * Returns AC_SUCCESS if successful or AC_FAILURE if an error is encountered
 * allocating heap space for the internal list item structure.
 */
ac_error_code
ac_list_add(ac_list* self, void* item) {
    ac_list_item* new_list_item;

    if ( ! (new_list_item = MALLOC(sizeof(ac_list_item)))) {
        return AC_FAILURE;
    }
    
    new_list_item->item = item;
    new_list_item->next = NULL;
    
    if ( ! self->first) {
        self->first = new_list_item;
    }
    
    if (self->last) {
        self->last->next = new_list_item;
    }
    
    self->last = new_list_item;
    
    return AC_SUCCESS;
}

