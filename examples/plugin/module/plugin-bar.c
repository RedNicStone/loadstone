
// Source for the 'bar' plugin.

#include "../host/host.h"
#include "plugin-foo.h"

void initialize() {
    host_print("[BAR] Initializing plugin...\n");
    foo_print_thing("[BAR] Says hello!");
}
