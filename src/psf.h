// SPDX-FileCopyrightText: 2026 KytyPS5Plus contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace kyty {

/// Minimal read-only PARAM.SFO ("\0PSF") parser. Only the lookups the extractor needs.
class Psf {
public:
    bool Open(const std::vector<uint8_t>& buffer);
    std::optional<std::string> GetString(const std::string& key) const;
    std::optional<int32_t> GetInteger(const std::string& key) const;

private:
    struct Entry {
        std::string key;
        uint16_t fmt = 0;
        std::vector<uint8_t> data;
    };
    std::vector<Entry> entries_;
};

} // namespace kyty
