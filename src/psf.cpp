// SPDX-FileCopyrightText: 2026 KytyPS5Plus contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "psf.h"

#include <cstring>

#include "endian.h"

namespace kyty {

namespace {
constexpr uint32_t kPsfMagic = 0x00505346; // "\0PSF"
constexpr size_t kHeaderSize = 0x14;
constexpr size_t kRawEntrySize = 0x10;
constexpr uint16_t kFmtText = 0x0204;
constexpr uint16_t kFmtInteger = 0x0404;
} // namespace

bool Psf::Open(const std::vector<uint8_t>& buf) {
    entries_.clear();
    if (buf.size() < kHeaderSize) return false;
    const uint8_t* p = buf.data();
    if (be32(p) != kPsfMagic) return false;
    const uint32_t version = le32(p + 4);
    if (version != 0x100 && version != 0x101) return false;
    const uint32_t key_table = le32(p + 8);
    const uint32_t data_table = le32(p + 12);
    const uint32_t count = le32(p + 16);
    if (count > 4096) return false;
    if (kHeaderSize + static_cast<uint64_t>(count) * kRawEntrySize > buf.size()) return false;
    if (key_table > buf.size() || data_table > buf.size()) return false;

    for (uint32_t i = 0; i < count; i++) {
        const uint8_t* e = p + kHeaderSize + static_cast<size_t>(i) * kRawEntrySize;
        const uint16_t key_off = le16(e);
        const uint16_t fmt = be16(e + 2);
        const uint32_t len = le32(e + 4);
        const uint32_t data_off = le32(e + 12);

        const uint64_t key_pos = static_cast<uint64_t>(key_table) + key_off;
        const uint64_t data_pos = static_cast<uint64_t>(data_table) + data_off;
        if (key_pos >= buf.size() || data_pos + len > buf.size()) return false;

        Entry entry;
        const char* key = reinterpret_cast<const char*>(p + key_pos);
        const size_t max_key = buf.size() - static_cast<size_t>(key_pos);
        entry.key.assign(key, strnlen(key, max_key));
        entry.fmt = fmt;
        entry.data.assign(p + data_pos, p + data_pos + len);
        entries_.push_back(std::move(entry));
    }
    return true;
}

std::optional<std::string> Psf::GetString(const std::string& key) const {
    for (const Entry& e : entries_) {
        if (e.key == key && e.fmt == kFmtText) {
            const char* s = reinterpret_cast<const char*>(e.data.data());
            return std::string(s, strnlen(s, e.data.size()));
        }
    }
    return std::nullopt;
}

std::optional<int32_t> Psf::GetInteger(const std::string& key) const {
    for (const Entry& e : entries_) {
        if (e.key == key && e.fmt == kFmtInteger && e.data.size() == 4) {
            return static_cast<int32_t>(le32(e.data.data()));
        }
    }
    return std::nullopt;
}

} // namespace kyty
