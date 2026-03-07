#include <stdint.h>
#include <stdio.h>

struct Point {
    int32_t x;
    int32_t y;
    char tag;
};

struct Wrapper {
    struct Point pt;
    uint64_t magic;
};

struct Point g_point = {11, 22, 'A'};
struct Wrapper g_wrapper = {{33, 44, 'B'}, 0x1122334455667788ULL};
int g_numbers[4] = {7, 42, 1234, -5};
const char g_message[] = "typed fixture says hi";

int sum_point(struct Point *p) {
    return p->x + p->y + p->tag;
}

int use_wrapper(void) {
    if (g_numbers[2] == 1234) {
        return sum_point(&g_wrapper.pt) + (int)(g_wrapper.magic & 0xff);
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc > 1000) {
        puts("unreachable branch");
    }
    printf("%s %d\n", g_message, use_wrapper());
    return 0;
}
