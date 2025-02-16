#include "hash_fixed.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    HashMap* m = HashInit();

    HashAdd(m, "hello");
    HashAdd(m, "elloh");
    HashAdd(m, "llohe");
    HashAdd(m, "lohel");
    HashAdd(m, "hello");
    HashAdd(m, "vanya");

    HashDump(m);

    HashDelete(m, "hello");
    HashDelete(m, "elloh");
    HashDelete(m, "llohe");
    HashDelete(m, "lohel");
    HashDelete(m, "hello");
    HashDelete(m, "vanya");

    HashDump(m);

    return 0;
}
