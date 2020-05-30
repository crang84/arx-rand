#include <io.h>
#include <fcntl.h>
#include <windows.h>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <vector>
#include <cstdint>
#include <cmath>

#include <CLI/CLI.hpp>

#include "hexcodec.h"

#include <CLI/CLI.hpp>

struct arx_ctx {
    uint8_t ctx[0x2500];
};

typedef void (*pArxSeed)(void *arx_ctx, uint8_t iv[8]);
typedef void (*pArxGenRandom)(void *arx_ctx, void *buf, uint64_t size);

/// Validate the argument is a number
class Hex : public CLI::Validator {
   public:
    Hex(int length) : CLI::Validator("HEX") {
        func_ = [=](std::string &hex_str) {
            if (hex_str.size() != 16) {
                return std::string("Expected string length is " + std::to_string(length * 2) + " (got ") +
                       std::to_string(hex_str.size()) + ')';
            }
            if (!std::all_of(hex_str.begin(), hex_str.end(), [](char ch) -> bool { return std::isxdigit(ch); })) {
                return std::string("Failed parsing as a hex (") + hex_str + ')';
            }
            return std::string();
        };
    }
};

int main(int argc, char const *argv[]) {
    try {
        CLI::App app{"ARX rng"};
        int64_t length;
        std::string seed, out = "-";
        app.add_option("-s,--seed", seed, "Seed (8 bytes hex)")->required()->check(Hex(8));
        app.add_option("-l,--len", length, "Output file size")->required()->check(CLI::Range(4096LL, INT64_MAX));
        app.add_option("-o,--out", out, "Output file (use '-' to output to stdout)", true);
        CLI11_PARSE(app, argc, argv);

        HMODULE hLib = LoadLibrary(L"ARX.DLL");
        if (hLib == nullptr) {
            auto err = GetLastError();
            throw std::runtime_error("Failed to load ARX.DLL, error " + std::to_string(err));
        }
        auto ArxSeed = (pArxSeed)GetProcAddress(hLib, "ArxSeed");
        if (ArxSeed == nullptr) {
            auto err = GetLastError();
            throw std::runtime_error("Failed to resolve ArxSeed export symbol in ARX.DLL, error " +
                                     std::to_string(err));
        }
        auto ArxGenRandom = (pArxGenRandom)GetProcAddress(hLib, "ArxGenRandom");
        if (ArxGenRandom == nullptr) {
            auto err = GetLastError();
            throw std::runtime_error("Failed to resolve ArxGenRandom export symbol in ARX.DLL, error " +
                                     std::to_string(err));
        }

        arx_ctx ctx;
        ZeroMemory(&ctx, sizeof(ctx));

        uint8_t iv[8];
        hex_decode(reinterpret_cast<char *>(iv), reinterpret_cast<unsigned char *>(seed.data()), seed.size());

        ArxSeed(&ctx, iv);

        std::ofstream ofs;
        if (out == "-") {
            _setmode(_fileno(stdout), _O_BINARY);
        } else {
            ofs.open(out, ofs.binary | ofs.trunc);
            if (!ofs) {
                throw std::runtime_error("Failed to create file " + out);
            }
        }

        std::vector rnd(length, 0);
        for (int64_t i = 0; i < length; i += rnd.size()) {
            ArxGenRandom(&ctx, rnd.data(), rnd.size());
            if (out == "-") {
                std::cout.write(reinterpret_cast<char *>(rnd.data()),  //
                                std::min(static_cast<int64_t>(rnd.size()), length - i));
            } else {
                ofs.write(reinterpret_cast<char *>(rnd.data()),  //
                          std::min(static_cast<int64_t>(rnd.size()), length - i));
            }
        }

        if (out == "-") {
            _setmode(_fileno(stdout), _O_TEXT);
        } else {
            ofs.close();
        }
    } catch (const std::exception &e) {
        std::cerr << "Exception " << e.what() << "\n";
    } catch (...) {
        std::cerr << "Unknown exception\n";
    }
    return 0;
}
