#include <cassert>

#include "Mapper2.h"

Mapper2::Mapper2(std::unique_ptr<Cartridge> cartridge) : Mapper(std::move(cartridge)) {}

uint8_t Mapper2::cpuRead(uint16_t addr) {
    uint32_t mappedAddr = 0;

    if (addr >= 0x8000 && addr < 0xC000) {
        mappedAddr = bankSelect * 0x4000 + (addr & 0x3FFF);
    } else if (addr >= 0xC000 && addr <= 0xFFFF) {
        mappedAddr = (prgBanks() - 1) * 0x4000 + (addr & 0x3FFF);
    }

    assert(mappedAddr >= 0 && mappedAddr < cartridge->prgRom.size());
    return cartridge->prgRom[mappedAddr];
}

void Mapper2::cpuWrite(uint16_t addr, uint8_t data) {
    if (addr >= 0x8000 && addr <= 0xFFFF) {
        bankSelect = data & 0b1111;
    }
}

uint8_t Mapper2::ppuRead(uint16_t addr) {
    assert(addr >= 0 && addr < 0x2000);
    return cartridge->chrRom[addr];
}

void Mapper2::ppuWrite(uint16_t addr, uint8_t data) {
    assert(addr >= 0 && addr < 0x2000);
    assert(chrBanks() == 0);
    cartridge->chrRom[addr] = data;
}
