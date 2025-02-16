/**
*
* @Name : hash.h
*
**/
#ifndef __HASH__
#define __HASH__
/**
HashMap with string-type keys
*/

	typedef struct {
        #define MAP_MAX 128U
		void* data[MAP_MAX];
	} HashMap;

    HashMap* HashInit();

    void HashAdd(HashMap *map, const char* key);

    void HashDelete(HashMap *map, const char* key);

    const char* HashFind(const HashMap *map, const char* key);

    void HashDump(const HashMap *map);

#endif