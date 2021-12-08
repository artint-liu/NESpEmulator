#include <utility>

#include "Bus.h"

Bus::Bus(std::unique_ptr<Mapper> mapper)
    : mapper(std::move(mapper)),
      cpu(std::make_unique<CPU>(*this)),
      ppu(std::make_unique<PPU>(*this)) {}

uint8_t Bus::read(uint16_t addr) {
    if (addr < 0x2000) {
        // CPU RAM
        return cpuRam[addr & 0x07FF];
    } else if (addr < 0x2008) {
        // The PPU exposes eight memory-mapped registers to the CPU
        if (addr == 0x2000) {
            // PPU Controller Register (writeData-only)
        } else if (addr == 0x2001) {
            // PPU Mask Register (writeData-only)
        } else if (addr == 0x2002) {
            // PPU Status Register (readData-only)
            return ppu->readStatus();
        } else if (addr == 0x2003) {
            // PPU OAM Address Register (writeData-only)
        } else if (addr == 0x2004) {
            // PPU OAM Data Register
            return ppu->readOAMData();
        } else if (addr == 0x2005) {
            // PPU Scroll Data Register (writeData-only)
        } else if (addr == 0x2006) {
            // PPU Address Register (writeData-only)
        } else if (addr == 0x2007) {
            // PPU Data Register
            return ppu->readData();
        }
    } else if (addr < 0x4000) {
        // PPU registers mirrors
        uint16_t mirrorDownAddr = addr & 0x2007;
        read(mirrorDownAddr);
    } else if (addr < 0x4018) {
        // TODO	NES APU and I/O registers
    } else if (addr < 0x4020) {
        // APU and I/O functionality that is normally disabled.
        // See https://wiki.nesdev.org/w/index.php?title=CPU_Test_Mode
    } else if (addr < 0x6000) {
        // TODO Expansion Rom
    } else {
        // Save RAM and PRG ROM that stored in cartridge
        return mapper->readPrgRom(addr);
    }

    return 0;
}

void Bus::write(uint16_t addr, uint8_t data) {
    if (addr < 0x2000) {
        // CPU RAM
        cpuRam[addr & 0x07FF] = data;
    } else if (addr < 0x2008) {
        // The PPU exposes eight memory-mapped registers to the CPU
        if (addr == 0x2000) {
            // PPU Controller Register (writeData-only)
            ppu->writeCtrl(data);
        } else if (addr == 0x2001) {
            // PPU Mask Register (writeData-only)
            ppu->writeMask(data);
        } else if (addr == 0x2002) {
            // PPU Status Register (readData-only)
        } else if (addr == 0x2003) {
            // PPU OAM Address Register (writeData-only)
            ppu->writeOAMAddr(data);
        } else if (addr == 0x2004) {
            // PPU OAM Data Register
            ppu->writeOAMData(data);
        } else if (addr == 0x2005) {
            // PPU Scroll Data Register (writeData-only)
            ppu->writeScroll(data);
        } else if (addr == 0x2006) {
            // PPU Address Register (writeData-only)
            ppu->writeAddr(data);
        } else if (addr == 0x2007) {
            // PPU Data Register
            ppu->writeData(data);
        }
    } else if (addr < 0x4000) {
        // PPU registers mirrors
        uint16_t mirrorDownAddr = addr & 0x2007;
        write(mirrorDownAddr, data);
    } else if (addr < 0x4018) {
        // TODO	NES APU and I/O registers
        if (addr == 0x4014) {
            // Writing $XX will upload 256 bytes of data from CPU page $XX00-$XXFF to the internal PPU OAM
            std::array<uint8_t, 256> buffer{};
            uint16_t hi = uint16_t(data) << 8;
            for (int i = 0x00; i != 0xFF; i++) {
                buffer[i] = read(hi | i);
            }

            ppu->writeOAMDMA(buffer);
        }
    } else if (addr < 0x4020) {
        // APU and I/O functionality that is normally disabled.
        // See https://wiki.nesdev.org/w/index.php?title=CPU_Test_Mode
    } else if (addr < 0x6000) {
        // TODO Expansion Rom
    } else {
        // Save RAM and PRG ROM that stored in cartridge
        mapper->writePrgRom(addr, data);
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

uint8_t Bus::ppuRead(uint16_t addr) {
    if (addr < 0x2000) {
        // CHR ROM (readData-only)
        return mapper->readChrRom(addr);
    } else if (addr < 0x3000) {
        // PPU RAM
        return ppuRam[mirrorVramAddr(addr)];
    }

    return 0;
}

void Bus::ppuWrite(uint16_t addr, uint8_t data) {
    if (addr < 0x2000) {
        // CHR ROM (readData-only)
    } else if (addr < 0x3000) {
        // PPU RAM
        ppuRam[mirrorVramAddr(addr)] = data;
    }
}

CPU& Bus::getCPU() {
    return *cpu;
}

PPU& Bus::getPPU() {
    return *ppu;
}

auto Bus::vRam() const -> const std::array<uint8_t, 2 * Kb>& {
    return ppuRam;
}

const std::vector<uint8_t>& Bus::chrRom() const {
    return mapper->chrRom();
}

Mirroring Bus::mirroring() const {
    return mapper->mirroring();
}

uint16_t Bus::mirrorVramAddr(uint16_t addr) const {
    uint16_t mirroredVram = addr & 0x2fff;
    uint16_t vramIndex = mirroredVram - 0x2000;
    uint16_t nameTable = vramIndex / 0x0400;

    if (mirroring() == Mirroring::Vertical && (nameTable == 2 || nameTable == 3)) {
        vramIndex -= 0x0800;
    } else if (mirroring() == Mirroring::Horizontal) {
        if (nameTable == 1 || nameTable == 2) {
            vramIndex -= 0x0400;
        } else if (nameTable == 3) {
            vramIndex -= 0x0800;
        }
    }

    return vramIndex;
}
