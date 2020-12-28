
#include "Gold_data.hpp"

int main() {
    Gold_data d1;
    Gold_data d2;

    d1.set_addr(33, 5);

    assert(!d1.has_byte(32));
    assert(d1.has_byte(33));
    assert(d1.has_byte(34));
    assert(d1.has_byte(35));
    assert(d1.has_byte(36));
    assert(d1.has_byte(37));
    assert(!d1.has_byte(38));

    d1.set_data(33, 1, 'h');
    uint64_t d = 'l';
    d <<= 8;
    d |= 'l';
    d <<= 8;
    d |= 'e';
    d1.set_data(34, 3, d);

    d1.set_byte(37, 'o');

    d1.dump();

    d2.set_addr(33, 3);
    d2.set_data(33, 1, 'b');
    d2.set_data(34, 1, 'y');
    d2.set_data(35, 1, 'e');

    d2.add_addr(50, 3);
    d2.set_data(50, 1, 'a');
    d2.set_data(51, 1, 'l');
    d2.set_data(52, 1, 'l');

    d2.dump();

    Gold_data d3 = d1;
    d3.add_newer(d2);

    d3.dump();
}
