/**
*
* @Name : hash.c
*
**/
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash_fixed.h"

/* Internal entry now is not exposed */
typedef struct Entry {
    #define KEY_STRING_MAX 255U
    const char key[KEY_STRING_MAX + 1]; // +1 for '\0' at the end
    struct Entry* prev;
    struct Entry* next;
} Entry;

void NullifyMapDataArray(HashMap* map) {
    for (unsigned int i = 0U; i < MAP_MAX; ++i) {
        map->data[i] = (Entry*) NULL;
    }
}

HashMap* HashInit() {
    HashMap* map = malloc(sizeof(HashMap));

/* Check if allocation succeeded */
    if (map == NULL) {
        fprintf(stderr, "Memory allocation for HashMap failed\n");
        exit(EXIT_FAILURE);
    }

/* We will not see any memory "garbage" */
    NullifyMapDataArray(map);
    return map;
}

/* Validate user's input key length */
void __ValidateKeySize(const char* key) {
    if (strlen(key) > KEY_STRING_MAX) {
        fprintf(stderr, "Length of key > maximum of %u characters\n", KEY_STRING_MAX);
        exit(EXIT_FAILURE);
    }
}

// I didn't change hashing algorithm because
// it will be more complex task then
unsigned int __HashIndex(const char* key) {
    __ValidateKeySize(key);

    unsigned int sum = 0U;

    for (const char* currentCharPtr = key; *currentCharPtr != '\0'; ++currentCharPtr) {
/* Correct and explicit unsigned type conversion for arithmetic operation */
        sum += (unsigned int)(unsigned char) *currentCharPtr;
    }

/* Modulating to avoid overflow */
    return sum % MAP_MAX;
}

Entry* __FirstEntryByHashIndex(const HashMap *map, unsigned int hashIndex) {
    return (Entry*) map->data[hashIndex];
}

Entry* __HashFindByHashIndexAndKey(const HashMap *map, unsigned int hashIndex, const char* key) {
    Entry* firstEntry = __FirstEntryByHashIndex(map, hashIndex);

    for (Entry* currentEntry = firstEntry; currentEntry != NULL; currentEntry = currentEntry->next) {
/* Using of strcmp instead of strcpy */
        if (strcmp(currentEntry->key, key) == 0) {
            return currentEntry;
        }
    }

    return NULL;
}

const char* HashFind(const HashMap *map, const char* key) {
    __ValidateKeySize(key);
    return __HashFindByHashIndexAndKey(map, __HashIndex(key), key)->key;
}

void HashAdd(HashMap *map, const char* key) {
    __ValidateKeySize(key);

    unsigned int hashIndex = __HashIndex(key);
    Entry* existedEntry = __HashFindByHashIndexAndKey(map, hashIndex, key);
    Entry* firstEntry = __FirstEntryByHashIndex(map, hashIndex);

    if (existedEntry == NULL) {
        Entry* newEntry = malloc(sizeof(Entry));
        //         dst        src
        strcpy(newEntry->key, key);

        // Insert new entry to the head of the list
        map->data[hashIndex] = newEntry;

        // Key with the same hash already exist
        if (firstEntry != NULL) {
            firstEntry->prev = newEntry;
            newEntry->next = firstEntry;
        }
    }
}

void HashDelete(HashMap *map, const char* key) {
    __ValidateKeySize(key);

    unsigned int hashIndex = __HashIndex(key);
    Entry* existedEntry = __HashFindByHashIndexAndKey(map, hashIndex, key);

    if (existedEntry != NULL) {
        Entry* existedPrev = existedEntry->prev;
        Entry* existedNext = existedEntry->next;

        // If existed entry is head of list
        if (existedPrev == NULL) {
            map->data[hashIndex] = existedNext;
        } else {
            existedPrev->next = existedNext;
        }

        if (existedNext != NULL) {
            existedNext->prev = existedPrev;
        }

/* Freeing unused object to avoid memory leak */
        free(existedEntry);
    }
}

void HashDump(const HashMap *map) {
    printf("{ ");
    for (unsigned int i = 0; i < MAP_MAX; ++i) {
        for (Entry* currentEntry = map->data[i]; currentEntry != NULL; currentEntry = currentEntry->next) {
/* Using format string */
            printf("%s ", currentEntry->key);
        }
    }
    printf("}\n");
}
