#ifndef EMULATOR_H
#define EMULATOR_H

#include <string_view>

#include "NesEmulator/nes/Bus.h"
#include "NesEmulator/pixel_engine/PixelEngine.h"

class Emulator : public PixelEngine {
public:
    explicit Emulator(std::string_view nesFile);

    void onUpdate(float elapsedTime) override;

private:
    void renderFrame(const PPU::Frame& frame);
    void checkKeyboard();

    Bus bus;

    float freeTime = 0.0f;
};

#endif
