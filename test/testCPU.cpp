#include <algorithm>
#include <fstream>
#include <iterator>
#include <sstream>

#include <gtest/gtest.h>

#include "NesEmulator/nes/Bus.h"
#include "NesEmulator/nes/CPU.h"
#include "NesEmulator/nes/NesFile.h"

GTEST_TEST(Nes, CPU) {
    auto cartridge = loadNesFile("nestest.nes");
    ASSERT_TRUE(cartridge.has_value());

    Bus bus;
    bus.insert(std::move(cartridge.value()));
    bus.powerUp();

    CPU& cpu = bus.getCPU();

    std::ostringstream oss;
    cpu.testCPU(&oss, 0xC000, 7);

    int cycles = 15274 + 3;

    while (cycles--) {
        cpu.clock();
    }

    oss << std::flush;

    std::string expect;
    std::ifstream file{"nestest.txt", std::ifstream::in};
    file >> std::noskipws;
    std::copy(std::istream_iterator<char>{file}, std::istream_iterator<char>{},
              std::back_inserter(expect));
    ASSERT_TRUE(expect == oss.str());
}
