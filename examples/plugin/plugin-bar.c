
// Source for the 'bar' plugin.

#include "host.h"
#include "plugin-foo.h"

void initialize() {
    host_printf("%s", "[BAR] Initializing plugin...\n");
    foo_print_thing("[BAR] Says hello!");
}
