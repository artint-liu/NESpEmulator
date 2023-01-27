#include <cassert>

#include <nes/Mirroring.h>

#ifdef STD_STRING_VIEW
std::string_view description(Mirroring mirroring) {
#else
MyStringView description(Mirroring mirroring) {
#endif
    switch (mirroring) {
    case Mirroring::OneScreenLoBank:
        return "one-screen, lower bank";
    case Mirroring::OneScreenUpBank:
        return "one-screen, upper bank";
    case Mirroring::Vertical:
        return "vertical";
    case Mirroring::Horizontal:
        return "horizontal";
    }

    assert(0);
    return "undefined";
}
