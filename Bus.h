#ifndef BUS_H
#define BUS_H

#include <array>
#include <cstdint>
#include <memory>

#include "literals.h"

class CPU;
class PPU;
class Mapper;

// CPU gets access to memory (including memory-mapped spaces) using the bus.
// See https://bugzmanov.github.io/nes_ebook/chapter_4.html
class Bus {
public:
    explicit Bus(std::unique_ptr<Mapper> mapper);

    // cpu read and write
    uint8_t read(uint16_t addr);
    void write(uint16_t addr, uint8_t data);
    uint16_t read16(uint16_t addr);
    void write16(uint16_t addr, uint16_t data);

    // fot testing
    CPU& getCPU();

private:
    // See https://bugzmanov.github.io/nes_ebook/images/ch2/image_5_motherboard.png
    std::unique_ptr<Mapper> mapper;
    std::unique_ptr<CPU> cpu;
    std::unique_ptr<PPU> ppu;
    std::array<uint8_t, 2_kb> cpuRam{};
    std::array<uint8_t, 2_kb> ppuRam{};
};

#endif
