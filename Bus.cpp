#include <utility>

#include "Bus.h"
#include "CPU.h"
#include "Mapper.h"
#include "PPU.h"

Bus::Bus(std::unique_ptr<Mapper> mapper)
    : mapper(std::move(mapper)),
      cpu(std::make_unique<CPU>(*this)),
      ppu(std::make_unique<PPU>(*this)) {}

uint8_t Bus::read(uint16_t addr) {
    if (addr < 0x2000) {
        // CPU RAM
        return cpuRam[addr & 0x07FF];
    } else if (addr < 0x4020) {
        // TODO IO Registers
        if (addr == 0x2000) {
            // PPU Controller Register (write-only)
        } else if (addr == 0x2001) {
            // PPU Mask Register (write-only)
        } else if (addr == 0x2002) {
            // PPU Status Register (read-only )
        } else if (addr == 0x2003) {
            // PPU OAM Address Register
        } else if (addr == 0x2004) {
            // PPU OAM Data Register
        } else if (addr == 0x2005) {
            // PPU Scroll Data Register (write-only)
        } else if (addr == 0x2006) {
            // PPU Address Register
        } else if (addr == 0x2007) {
            // PPU Data Register
        }
    } else if (addr < 0x6000) {
        // Expansion Rom
    } else {
        // Save RAM and PRG ROM that stored in cartridge
        return mapper->read(addr);
    }

    return 0;
}

void Bus::write(uint16_t addr, uint8_t data) {
    if (addr < 0x2000) {
        // CPU RAM
        cpuRam[addr & 0x07FF] = data;
    } else if (addr < 0x4020) {
        // TODO IO Registers
        if (addr == 0x2000) {
            // PPU Controller Register (write-only)
        } else if (addr == 0x2001) {
            // PPU Mask Register (write-only)
        } else if (addr == 0x2002) {
            // PPU Status Register (read-only )
        } else if (addr == 0x2003) {
            // PPU OAM Address Register
        } else if (addr == 0x2004) {
            // PPU OAM Data Register
        } else if (addr == 0x2005) {
            // PPU Scroll Data Register (write-only)
        } else if (addr == 0x2006) {
            // PPU Address Register
        } else if (addr == 0x2007) {
            // PPU Data Register
        }
    } else if (addr < 0x6000) {
        // Expansion Rom
    } else {
        // Save RAM and PRG ROM that stored in cartridge
        mapper->write(addr, data);
    }
}

uint16_t Bus::read16(uint16_t addr) {
    uint16_t lo = read(addr);
    uint16_t hi = read(addr + 1);

    return (hi << 8) | lo;
}

void Bus::write16(uint16_t addr, uint16_t data) {
    write(addr, data & 0xFF);
    write(addr + 1, (data >> 8) & 0xFF);
}

CPU& Bus::getCPU() {
    return *cpu.get();
}
