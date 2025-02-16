/**
*
* @Name : hash.h
*
**/
#ifndef __HASH__
#define __HASH__

// The format of mistake description is the following:
// "[#][X] ...", where:
// # - is an ID of mistake
// X is either A, C, or I meaning the security breach related to Availability, Confidentiality, or Integrity correspondingly
// ... is a description of the mistake

/* [1][I] Opening internal entry `PairValue as an interface may result in data corruption
          if someone will assign / remove `Next` by their own */
    typedef struct {
        #define KEY_STRING_MAX 255
		char KeyName[KEY_STRING_MAX];
		int  ValueCount;
        struct PairValue* Next;
	} PairValue;

	typedef struct {
        #define MAP_MAX 128
/* [2][I] Non-const pointer of `data` may lead to data corruption */
/* [3][C] Array is initialized with some left data in memory which can lead to data leak */
		PairValue* data[MAP_MAX];
	} HashMap;

/* [4][I] Non-const pointer of `map` may lead to data corruption */
    HashMap* HashInit();
    void HashAdd(HashMap *map, PairValue *value);
    void HashDelete(HashMap *map, const char* key);
/* [5][I] Non-const pointer of `map` may lead to data corruption */
    PairValue* HashFind(HashMap *map, const char* key);
/* [6][I] Non-const pointer of `map` may lead to data corruption */
    void HashDump(HashMap *map);
#endif