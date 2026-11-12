// SPDX-FileCopyrightText: 2026 KytyPS5Plus contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//
// pkg_extractor <file.pkg> [output_dir] [--check-type] [--type base|patch|dlc]
//
// Same contract as the ShadPs4Plus extractor this project is modelled on:
//   * 2nd argument is the output folder; without it the package is extracted next to the file.
//   * --check-type does not extract; it exits with 101 (base game), 102 (update), 103 (DLC),
//     or 0 if the file could not be read. install_pkg.sh/.bat rely on these codes.
//   * With a single argument (drag and drop on Windows) the window waits for [enter] at the end.
//
// Extraction exit codes: 0 = everything written, 3 = written but incomplete (inner PFS image
// and/or encrypted entries were not extracted), 1 = failure.

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "pkg.h"

namespace fs = std::filesystem;
using kyty::Pkg;
using kyty::PkgType;

namespace {

constexpr int kExitOk = 0;
constexpr int kExitFail = 1;
constexpr int kExitIncomplete = 3;

void PrintUsage() {
    std::cout << "KytyPS5Plus PKG extractor\n"
                 "usage: pkg_extractor <file.pkg> [output_dir] [--check-type] [--info] [--dump O L] [--type base|patch|dlc]\n"
                 "  output_dir    where to extract (default: next to the pkg file)\n"
                 "  --info        print header fields, flags, entries and raw header bytes, then exit\n"
                 "  --dump O L    hex-dump L bytes (max 65536) at offset O (decimal or 0x hex); repeatable\n"
                 "  --check-type  do not extract; exit with 101 base / 102 update / 103 dlc (0 = error)\n"
                 "  --type        override the detected package type\n";
}

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string> positional;
    bool check_type = false;
    bool info = false;
    std::vector<std::pair<uint64_t, uint64_t>> dumps; // (offset, length) from --dump
    std::optional<PkgType> forced_type;

    for (int i = 1; i < argc; i++) {
        const std::string arg = argv[i];
        if (arg == "--check-type") {
            check_type = true;
        } else if (arg == "--info") {
            info = true;
        } else if (arg == "--dump") {
            uint64_t values[2] = {};
            bool ok = i + 2 < argc;
            for (int k = 0; ok && k < 2; k++) {
                const char* text = argv[i + 1 + k];
                char* end = nullptr;
                errno = 0;
                values[k] = std::strtoull(text, &end, 0); // accepts 0x... hex and decimal
                ok = errno == 0 && end != text && *end == '\0' && text[0] != '-';
            }
            if (!ok) {
                std::cout << "--dump needs two numbers: <offset> <length> (decimal or 0x hex)" << std::endl;
                return check_type ? 0 : kExitFail;
            }
            dumps.emplace_back(values[0], values[1]);
            i += 2;
        } else if (arg == "--type" && i + 1 < argc) {
            const std::string v = argv[++i];
            if (v == "base") forced_type = PkgType::Base;
            else if (v == "patch") forced_type = PkgType::Patch;
            else if (v == "dlc") forced_type = PkgType::Dlc;
            else {
                std::cout << "unknown --type value: " << v << std::endl;
                return check_type ? 0 : kExitFail;
            }
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage();
            return kExitOk;
        } else {
            positional.push_back(arg);
        }
    }

    const bool drag_and_drop = (argc == 2);
    const int error_code = check_type ? 0 : kExitFail;
    int result = error_code;

    auto finish = [&](const fs::path& file) {
        std::cout << "\nTHE END " << file << std::endl;
        if (drag_and_drop) {
            std::cout << "\nPress [enter] to exit." << std::endl;
            std::cin.get();
        }
        return result;
    };

    if (positional.empty()) {
        PrintUsage();
        return error_code;
    }

    const fs::path file = positional[0];

    if (!Pkg::IsPkg(file)) {
        std::cout << file << " doesn't appear to be a valid PKG file" << std::endl;
        return finish(file);
    }
    std::cout << file << " is a valid PKG\n" << std::endl;

    Pkg pkg;
    std::string fail;
    if (!pkg.Open(file, fail)) {
        std::cout << "Cannot open PKG file : " << fail << std::endl;
        return finish(file);
    }

    // --check-type is the machine interface used by the install scripts, so it always wins.
    if ((info || !dumps.empty()) && !check_type) {
        if (info) pkg.PrintInfo(std::cout);
        result = kExitOk;
        for (const auto& [offset, length] : dumps)
            if (!pkg.DumpRegion(std::cout, offset, length)) result = kExitFail;
        return finish(file);
    }

    const PkgType type = forced_type.value_or(pkg.GetType());
    std::cout << pkg.TypeDescription(type) << "  (" << pkg.TypeReason() << ")" << std::endl;

    if (check_type) {
        result = static_cast<int>(type);
        return result; // no pause: this mode is called from scripts
    }

    fs::path out = positional.size() > 1 ? fs::path(positional[1]) : file.parent_path();
    out /= pkg.TitleId();
    if (type == PkgType::Patch) {
        out += "-patch";
    } else if (type == PkgType::Dlc) {
        const std::string label = pkg.EntitlementLabel();
        if (label.empty()) {
            std::cout << "content id has no entitlement label, extracting into the title folder" << std::endl;
        } else {
            out /= label;
        }
    }

    std::cout << "Extracting pkg to " << out << std::endl;

    kyty::ExtractReport report;
    const bool ok = pkg.Extract(out, report, fail, [](size_t done, size_t total) {
        std::cout << "\r      Extracting file " << done << " of " << total << std::flush;
    });
    std::cout << std::endl;

    if (!ok) {
        std::cout << "Cannot extract PKG file : " << fail << std::endl;
        result = kExitFail;
        return finish(file);
    }

    std::cout << report.written << " file(s) written" << std::endl;
    if (report.skipped_encrypted)
        std::cout << "NOTE: " << report.skipped_encrypted << " encrypted entr"
                  << (report.skipped_encrypted == 1 ? "y" : "ies") << " skipped (no key handling)" << std::endl;
    if (report.skipped_out_of_bounds)
        std::cout << "WARNING: " << report.skipped_out_of_bounds
                  << " entr" << (report.skipped_out_of_bounds == 1 ? "y points" : "ies point")
                  << " outside the file (truncated or corrupt package)" << std::endl;
    if (report.inner_image_present)
        std::cout << "NOTE: the inner PFS image (" << report.inner_image_size
                  << " bytes) was NOT extracted; this build only extracts package metadata entries." << std::endl;

    result = report.Complete() ? kExitOk : kExitIncomplete;
    return finish(file);
}
