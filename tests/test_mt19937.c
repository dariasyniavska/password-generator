#include "test_util.h"
#include "mt19937.h"

int main(void)
{
    MtState mt;

    mt_seed(&mt, 5489u);
    CHECK(mt_next_u32(&mt) == 3499211612u);

    mt_seed(&mt, 5489u);
    uint32_t x = 0;
    for (int i = 0; i < 10000; i++) {
        x = mt_next_u32(&mt);
    }
    CHECK(x == 4123659995u);

    uint32_t key[4] = {0x123, 0x234, 0x345, 0x456};
    mt_seed_array(&mt, key, 4);
    CHECK(mt_next_u32(&mt) == 1067595299u);
    CHECK(mt_next_u32(&mt) == 955945823u);

    MtState a, b;
    mt_seed(&a, 42u);
    mt_seed(&b, 42u);
    int same = 1;
    for (int i = 0; i < 1000; i++) {
        if (mt_next_u32(&a) != mt_next_u32(&b)) same = 0;
    }
    CHECK(same);

    mt_seed(&mt, 7u);
    int in_range = 1;
    double sum = 0.0;
    for (int i = 0; i < 100000; i++) {
        double d = mt_next_double(&mt);
        if (d < 0.0 || d >= 1.0) in_range = 0;
        sum += d;
    }
    CHECK(in_range);
    CHECK(sum / 100000.0 > 0.49 && sum / 100000.0 < 0.51);  

    return test_summary("test_mt19937");
}
