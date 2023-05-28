#include "../medkit.c"

#include <stdio.h>

MK_Detour detour = { 0 };

static int target(int a, int b) {
    printf("Called target(a = %d, b = %d)\n", a, b);
    return a + b;
}

static int my_detour(int a, int b) {
    printf("Called my_detour(a = %d, b = %d)\n", a, b);

    // call the original function
    mk_uninstall_detour(&detour);
    int result = target(a + 1, b + 1);
    mk_install_detour(&detour);

    return result;
}

int main(void) {
    target(3, 5);

    detour.target       = (uintptr_t)target;
    detour.destination  = (uintptr_t)my_detour;
    if (!mk_install_detour(&detour)) {
        printf("Failed to install detour: %s\n", mk_get_last_error());
    }

    target(3, 5);
}
