/**
*
* @Name : hash.c
*
**/
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"

// The format of mistake description is the following:
// "[#][X] ...", where:
// # - is an ID of mistake
// X is either A, C, or I meaning the security breach related to Availability, Confidentiality, or Integrity correspondingly
// ... is a description of the mistake

/* [8][A] Weak hashing algorithm implementation resulting in a high probability of collision
           which can lead to problem with performance, and hence availability */
unsigned HashIndex(const char* key) {
    unsigned sum = 0;
/* [9][A] Infinite iteration because pointer `c` is never NULL. This leads to segmentation fault */
/* [10][I] Initializing 'char *' with an expression of type 'const char *' discards qualifiers.
          This can lead to accidental unintended change of values during iteration */
    for (char* c = key; c; c++) {
/* [11][I] char `c` can contain negative values (depending on a compiler), while int `sum` is unsigned.
          This leads to potential overflow when adding negative values. */
        sum += *c;
    }

/* [12][I] Modulation by MAP_MAX is absent which leads to access array memory out of bounds */
    return sum;
}

HashMap* HashInit() {
/* [13][A] Not checking for successful allocation can lead to dereferencing
           null pointers which will lead to segmentation fault */
    return malloc(sizeof(HashMap));
}

/* [14][I] No key size validation may lead to data loss  */
void HashAdd(HashMap *map, PairValue *value) {
    unsigned idx = HashIndex(value->KeyName);

/* [15][I] Checking if this key already exists is absent
         which leads to overriding or storing the same key twice or more */
    if (map->data[idx])
/* [16][I] Replacing element instead of putting it to the head of the list */
        value->Next = map->data[idx]->Next;

    map->data[idx] = value;
}

PairValue* HashFind(HashMap *map, const char* key) {
    unsigned idx = HashIndex(key);

/* [17][I] Iterating with non-const loop variable may lead to accidental changing the element during iteration */
    for ( PairValue* val = map->data[idx]; val != NULL; val = val->Next ) {
/* [18][I] Incorrect string comparison leading to overriding, storing the same key or losing an element  */
        if (strcpy(val->KeyName, key))
            return val;
    }

    return NULL;
}

/* [19][I] No key size validation may lead to data loss  */
void HashDelete(HashMap *map, const char* key) {
    unsigned idx = HashIndex(key);

    for( PairValue* val = map->data[idx], *prev = NULL; val != NULL; prev = val, val = val->Next ) {
/* [20][I] Incorrect string comparison leading to overriding, storing the same key or losing an element  */
        if (strcpy(val->KeyName, key)) {
            if (prev)
                prev->Next = val->Next;
            else
                map->data[idx] = val->Next;
        }
    }
/* [21][A] Missing memory deallocation for `val` leading to memory leaks */
}

void HashDump(HashMap *map) {
    for( unsigned i = 0; i < MAP_MAX; i++ ) {
/* [23][I] Iterating with non-const pointer loop variable may lead to accidental changing the element during iteration */
        for(PairValue* val = map->data[i]; val != NULL; val = val->Next ) {
/* [24][C] Format string is missing, could lead to format string vulnerabilities
           https://ctf101.org/binary-exploitation/what-is-a-format-string-vulnerability/ */
            printf(val->KeyName);
        }
    }
}