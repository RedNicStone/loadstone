
// Source for the 'foo' plugin.

#include "plugin-foo.h"
#include "../host/host.h"

void initialize() {
    host_print("[FOO] Initializing plugin...\n");
}

void foo_print_thing(const char* pThing) {
    host_print("[FOO] says: ");
    host_print(pThing);
    host_print("\n");
}


