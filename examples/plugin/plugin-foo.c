
// Source for the 'foo' plugin.

#include "plugin-foo.h"
#include "host.h"

void initialize() {
    host_printf("%s", "[FOO] Initializing plugin...\n");
}

void foo_print_thing(const char* pThing) {
    host_printf("[FOO] says: %s\n", pThing);
}


