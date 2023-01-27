#ifndef OCFBNJ_NES_MIRRORING_H
#define OCFBNJ_NES_MIRRORING_H

#ifdef STD_STRING_VIEW
#include <string_view>
#else
#include "mystring_view.h"
#endif

enum class Mirroring {
    OneScreenLoBank,
    OneScreenUpBank,
    Vertical,
    Horizontal
};

#ifdef STD_STRING_VIEW
std::string_view description(Mirroring mirroring);
#else
MyStringView description(Mirroring mirroring);
#endif

#endif // OCFBNJ_NES_MIRRORING_H
