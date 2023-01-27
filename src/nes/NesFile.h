#ifndef OCFBNJ_NES_NES_FILE_H
#define OCFBNJ_NES_NES_FILE_H

#include <memory>
#include <optional>
#ifdef STD_STRING_VIEW
#include <string_view>
#else
#include "mystring_view.h"
#endif

#include <nes/Cartridge.h>

std::optional<Cartridge> loadNesFile(std::string_view path);

#endif // OCFBNJ_NES_NES_FILE_H
