#include <io.h>
#include <fcntl.h>
#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <vector>
#include <thread>
#include <atomic>
#include <cstdint>
#include <cmath>

#include <CLI/CLI.hpp>

#include "hexcodec.h"

#pragma comment(lib, "crypt32.lib")

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
        int64_t length, block_size = 819200LL;
        std::string seed, out = "nul";
        bool quiet = false;
        app.add_option("-s,--seed", seed, "Seed (8 bytes hex)")->check(Hex(8));
        app.add_option("-l,--len", length, "Output file size")->required()->check(CLI::Range(1LL, INT64_MAX));
        app.add_option("-o,--out", out, "Output file (use '-' to output to stdout)", true);
        app.add_option("-b,--bs", block_size, "Block size", true)->check(CLI::Range(8192LL, INT64_MAX));
        app.add_flag("-q,--quiet", quiet, "Don't print benchmark to stderr");
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

        uint8_t raw_seed[8];
        if (seed.empty()) {
            HCRYPTPROV hCryptProv;
            if (CryptAcquireContext(&hCryptProv, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) != TRUE) {
                auto err = GetLastError();
                throw std::runtime_error("CryptAcquireContext failed, error " + std::to_string(err));
            }
            if (CryptGenRandom(hCryptProv, 8, raw_seed) != TRUE) {
                auto err = GetLastError();
                CryptReleaseContext(hCryptProv, 0);
                throw std::runtime_error("CryptGenRandom failed, error " + std::to_string(err));
            }
            CryptReleaseContext(hCryptProv, 0);
        } else {
            hex_decode(reinterpret_cast<char *>(raw_seed), reinterpret_cast<uint8_t *>(seed.data()), seed.size());
        }

        if (!quiet) {
            seed.resize(16);
            hex_encode(reinterpret_cast<uint8_t *>(seed.data()), raw_seed, 8);
            std::cerr << "SEED " << seed << "\n";
        }

        arx_ctx ctx;
        ZeroMemory(&ctx, sizeof(ctx));
        ArxSeed(&ctx, raw_seed);

        std::ofstream ofs;
        bool stdout_sink = (out == "-");
        if (stdout_sink) {
            _setmode(_fileno(stdout), _O_BINARY);
        } else {
            ofs.open(out, ofs.binary | ofs.trunc);
            if (!ofs) {
                throw std::runtime_error("Failed to create file " + out);
            }
        }
        std::ostream &ost = stdout_sink ? std::cout : ofs;

        if (!quiet) {
            std::cerr << "BYTES        TIME        SPEED\n";
        }

        std::atomic_bool bench_stop = false;
        std::atomic_int64_t rng_bytes = 0;


        LARGE_INTEGER StartingTime, EndingTime, ElapsedMicroseconds, Frequency;
        QueryPerformanceFrequency(&Frequency);
        QueryPerformanceCounter(&StartingTime);

        auto print_stats = [&]() {
            QueryPerformanceCounter(&EndingTime);
            ElapsedMicroseconds.QuadPart = EndingTime.QuadPart - StartingTime.QuadPart;
            ElapsedMicroseconds.QuadPart *= 1000000;
            ElapsedMicroseconds.QuadPart /= Frequency.QuadPart;
            int64_t bytes = rng_bytes.load();
            double elapsed_sec = double(ElapsedMicroseconds.QuadPart) / 1000000L;
            std::cerr << bytes << " " << elapsed_sec << " " << (double(bytes) / 1048576L / elapsed_sec) << " MB/s\n";
        };

        std::thread bench_thread([&]() {
            if (!quiet) {
                Sleep(1000);
                while (!bench_stop.load()) {
                    print_stats();
                    Sleep(1000);
                }
            }
        });

        char *block = reinterpret_cast<char *>(_aligned_malloc(block_size, 4096));
        for (; rng_bytes < length; rng_bytes += block_size) {
            ArxGenRandom(&ctx, block, block_size);
            ost.write(block, std::min(block_size, length - rng_bytes));
        }
        _aligned_free(block);

        bench_stop.store(true);

        if (!quiet) {
            print_stats();
        }

        bench_thread.join();

        if (!stdout_sink) {
            ofs.close();
        }
    } catch (const std::exception &e) {
        std::cerr << "Exception " << e.what() << "\n";
    } catch (...) {
        std::cerr << "Unknown exception\n";
    }
    return 0;
}
