// SPDX-FileCopyrightText: 2026 KytyPS5Plus contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "pkg.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <ostream>

#include "endian.h"
#include "psf.h"

namespace fs = std::filesystem;

namespace kyty {

namespace {

constexpr uint64_t kCntHeaderSize = 0x5A0;
constexpr size_t kFihProbeSize = 0x60;
constexpr size_t kCntFieldsSize = 0x80; // fixed fields we read from the CNT header
constexpr uint32_t kMaxEntries = 0x10000;
constexpr uint64_t kMaxMetadataEntry = 16ull * 1024 * 1024;
constexpr size_t kEntrySize = 32;

constexpr uint32_t kPatchMask = static_cast<uint32_t>(ContentFlag::FirstPatch) |
                                static_cast<uint32_t>(ContentFlag::PatchGo) |
                                static_cast<uint32_t>(ContentFlag::SubsequentPatch);

constexpr uint32_t kIdNameTable = 0x0200;
constexpr uint32_t kIdParamSfo = 0x1000;
constexpr uint32_t kIdParamJson = 0x2000;

struct KnownEntry {
    uint32_t id;
    const char* path;
};

// Content entry ids -> paths inside the game's sce_sys folder (taken from the layout PS5PKGTool
// exposes for plaintext CNT entries).
constexpr KnownEntry kKnownEntries[] = {
    {0x0402, "sce_sys/nptitle.dat"},
    {0x0403, "sce_sys/npbind.dat"},
    {0x040A, "sce_sys/imagedigs.dat"},
    {0x1000, "sce_sys/param.sfo"},
    {0x1001, "sce_sys/playgo-chunk.dat"},
    {0x1200, "sce_sys/icon0.png"},
    {0x1220, "sce_sys/pic0.png"},
    {0x1240, "sce_sys/snd0.at9"},
    {0x1280, "sce_sys/icon0.dds"},
    {0x12A0, "sce_sys/pic0.dds"},
    {0x12C0, "sce_sys/pic1.dds"},
    {0x1480, "sce_sys/trophy2/trophy00.ucp"},
    {0x14A0, "sce_sys/uds/uds00.ucp"},
    {0x2000, "sce_sys/param.json"},
    {0x2010, "sce_sys/playgo-hash-table.dat"},
    {0x2011, "sce_sys/playgo-ficm.dat"},
    {0x2020, "sce_sys/uds/npbind.dat"},
    {0x2021, "sce_sys/trophy2/npbind.dat"},
    {0x2060, "sce_sys/pic2.dds"},
};

const char* KnownPath(uint32_t id) {
    for (const KnownEntry& k : kKnownEntries)
        if (k.id == id) return k.path;
    return nullptr;
}

/// Returns a safe relative path, or an empty string if `raw` tries to escape the output folder.
std::string SanitizePath(const std::string& raw) {
    std::string norm = raw;
    std::replace(norm.begin(), norm.end(), '\\', '/');
    std::string out;
    size_t pos = 0;
    while (pos <= norm.size()) {
        size_t next = norm.find('/', pos);
        if (next == std::string::npos) next = norm.size();
        const std::string part = norm.substr(pos, next - pos);
        pos = next + 1;
        if (part.empty() || part == ".") continue;
        if (part == ".." || part.find(':') != std::string::npos) return {};
        for (unsigned char c : part)
            if (c < 0x20) return {};
        if (!out.empty()) out += '/';
        out += part;
    }
    return out;
}

/// A single folder name that is safe to join onto the output path: letters, digits, '_', '-', '.'
/// only, bounded length, and not "." / "..". Title ids and entitlement labels come from the
/// package, so they are untrusted and must never contain path separators.
bool IsSafeFolderName(const std::string& s) {
    if (s.empty() || s.size() > 64 || s == "." || s == "..") return false;
    for (unsigned char c : s) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                        c == '_' || c == '-' || c == '.';
        if (!ok) return false;
    }
    return true;
}

/// Tolerant "key": value lookup for flat or nested JSON. Good enough for param.json identity
/// fields; this is not a general JSON parser.
std::string JsonField(const std::string& text, const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    size_t pos = text.find(needle);
    while (pos != std::string::npos) {
        size_t p = pos + needle.size();
        while (p < text.size() && (text[p] == ' ' || text[p] == '\t' || text[p] == '\r' || text[p] == '\n')) p++;
        if (p < text.size() && text[p] == ':') {
            p++;
            while (p < text.size() && (text[p] == ' ' || text[p] == '\t' || text[p] == '\r' || text[p] == '\n')) p++;
            if (p >= text.size()) return {};
            std::string value;
            if (text[p] == '"') {
                for (p++; p < text.size() && text[p] != '"'; p++) {
                    if (text[p] == '\\' && p + 1 < text.size()) p++;
                    value += text[p];
                }
            } else {
                while (p < text.size() && text[p] != ',' && text[p] != '}' && text[p] != ' ' &&
                       text[p] != '\r' && text[p] != '\n')
                    value += text[p++];
            }
            return value;
        }
        pos = text.find(needle, pos + 1);
    }
    return {};
}

bool ReadAt(std::ifstream& f, uint64_t offset, void* buf, size_t size) {
    f.clear();
    f.seekg(static_cast<std::streamoff>(offset));
    f.read(static_cast<char*>(buf), static_cast<std::streamsize>(size));
    return f.gcount() == static_cast<std::streamsize>(size);
}

std::string TrimNul(const uint8_t* p, size_t n) {
    size_t len = 0;
    while (len < n && p[len] != 0) len++;
    return std::string(reinterpret_cast<const char*>(p), len);
}

} // namespace

bool Pkg::IsPkg(const fs::path& file) {
    std::ifstream f(file, std::ios::binary);
    uint8_t magic[4];
    if (!f || !ReadAt(f, 0, magic, sizeof(magic))) return false;
    const uint32_t m = be32(magic);
    return m == kMagicCnt || m == kMagicFih;
}

bool Pkg::Open(const fs::path& file, std::string& fail) {
    file_ = file;
    entries_.clear();
    std::error_code ec;
    file_size_ = fs::file_size(file, ec);
    if (ec) {
        fail = "cannot get file size: " + ec.message();
        return false;
    }
    std::ifstream f(file, std::ios::binary);
    if (!f) {
        fail = "cannot open file";
        return false;
    }

    uint8_t head[kFihProbeSize] = {};
    if (!ReadAt(f, 0, head, 4)) {
        fail = "file too small";
        return false;
    }
    const uint32_t magic = be32(head);
    cnt_base_ = 0;
    pfs_offset_ = pfs_size_ = 0;

    if (magic == kMagicFih) {
        if (file_size_ < kFihProbeSize || !ReadAt(f, 0, head, kFihProbeSize)) {
            fail = "truncated FIH header";
            return false;
        }
        const uint8_t signed_byte = head[5];
        if (signed_byte == 0x80) {
            kind_ = PkgKind::FinalizedRetail;
            fail = "this is a retail (signed) PS5 package; its contents are encrypted and this "
                   "tool only supports debug packages";
            return false;
        }
        if (signed_byte != 0x00) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "unknown FIH signed byte 0x%02X", signed_byte);
            fail = buf;
            return false;
        }
        kind_ = PkgKind::FinalizedDebug;
        signed_byte_ = signed_byte;
        format_version_ = le16(head + 6);
        pfs_offset_ = le64(head + 0x10);
        pfs_size_ = le64(head + 0x18);
        cnt_base_ = le64(head + 0x58);
        if (cnt_base_ > file_size_ || file_size_ - cnt_base_ < kCntHeaderSize) {
            fail = "package has no embedded CNT metadata";
            return false;
        }
    } else if (magic == kMagicCnt) {
        kind_ = PkgKind::MetadataContainer;
        if (file_size_ < kCntHeaderSize) {
            fail = "truncated CNT header";
            return false;
        }
    } else {
        fail = "not a PS5 package (bad magic)";
        return false;
    }

    uint8_t cnt[kCntFieldsSize];
    if (!ReadAt(f, cnt_base_, cnt, sizeof(cnt)) || be32(cnt) != kMagicCnt) {
        fail = "CNT header not found at the expected offset";
        return false;
    }

    const uint32_t entry_count = be32(cnt + 0x10);
    const uint32_t table_offset = be32(cnt + 0x18);
    content_id_ = TrimNul(cnt + 0x40, 0x24);
    drm_type_ = be32(cnt + 0x70);
    content_type_ = be32(cnt + 0x74);
    content_flags_ = be32(cnt + 0x78);

    if (entry_count == 0 || entry_count > kMaxEntries) {
        fail = "implausible CNT entry count";
        return false;
    }
    const uint64_t cnt_span = file_size_ - cnt_base_;
    if (static_cast<uint64_t>(table_offset) + static_cast<uint64_t>(entry_count) * kEntrySize > cnt_span) {
        fail = "entry table lies outside the file";
        return false;
    }

    std::vector<uint8_t> table(static_cast<size_t>(entry_count) * kEntrySize);
    if (!ReadAt(f, cnt_base_ + table_offset, table.data(), table.size())) {
        fail = "cannot read entry table";
        return false;
    }
    entries_.reserve(entry_count);
    for (uint32_t i = 0; i < entry_count; i++) {
        const uint8_t* e = table.data() + static_cast<size_t>(i) * kEntrySize;
        PkgEntry entry;
        entry.id = be32(e);
        entry.name_offset = be32(e + 4);
        entry.flags1 = be32(e + 8);
        entry.flags2 = be32(e + 12);
        entry.data_offset = be32(e + 16);
        entry.data_size = be32(e + 20);
        entry.in_bounds = static_cast<uint64_t>(entry.data_offset) + entry.data_size <= cnt_span;
        entries_.push_back(entry);
    }

    ResolvePaths();
    LoadMetadata();

    if (title_id_.empty()) {
        fail = "could not determine the title id (no param.json/param.sfo and no usable content id)";
        return false;
    }
    return true;
}

const PkgEntry* Pkg::FindEntry(uint32_t id) const {
    for (const PkgEntry& e : entries_)
        if (e.id == id) return &e;
    return nullptr;
}

bool Pkg::ReadEntry(const PkgEntry& entry, uint64_t max_size, std::vector<uint8_t>& out) const {
    if (!entry.in_bounds || entry.Encrypted() || entry.data_size > max_size) return false;
    std::ifstream f(file_, std::ios::binary);
    out.resize(entry.data_size);
    return f && ReadAt(f, cnt_base_ + entry.data_offset, out.data(), out.size());
}

void Pkg::ResolvePaths() {
    std::vector<uint8_t> names;
    if (const PkgEntry* nt = FindEntry(kIdNameTable)) ReadEntry(*nt, kMaxMetadataEntry, names);

    for (PkgEntry& e : entries_) {
        std::string path;
        if (e.id != kIdNameTable && e.name_offset < names.size()) {
            const char* s = reinterpret_cast<const char*>(names.data()) + e.name_offset;
            path = SanitizePath(std::string(s, strnlen(s, names.size() - e.name_offset)));
        }
        if (path.empty()) {
            if (const char* known = KnownPath(e.id)) {
                path = known;
            } else {
                char buf[48];
                std::snprintf(buf, sizeof(buf), "pkg_entries/entry_0x%04X.bin", e.id);
                path = buf;
            }
        }
        e.path = std::move(path);
    }
}

void Pkg::LoadMetadata() {
    title_id_.clear();
    sfo_category_.clear();

    std::vector<uint8_t> data;
    if (const PkgEntry* pj = FindEntry(kIdParamJson); pj && ReadEntry(*pj, kMaxMetadataEntry, data)) {
        const std::string text(data.begin(), data.end());
        title_id_ = JsonField(text, "titleId");
        const std::string cid = JsonField(text, "contentId");
        if (content_id_.empty()) content_id_ = cid;
    }
    if (const PkgEntry* ps = FindEntry(kIdParamSfo); ps && ReadEntry(*ps, kMaxMetadataEntry, data)) {
        Psf psf;
        if (psf.Open(data)) {
            if (title_id_.empty()) title_id_ = psf.GetString("TITLE_ID").value_or("");
            sfo_category_ = psf.GetString("CATEGORY").value_or("");
            if (content_id_.empty()) content_id_ = psf.GetString("CONTENT_ID").value_or("");
        }
    }
    // The title id becomes a folder name, so it must be a plain, safe name. Fall back to the one
    // embedded in the content id; if that is unusable too, leave it empty and Open() fails.
    if (!IsSafeFolderName(title_id_)) {
        title_id_.clear();
        if (content_id_.size() >= 16 && IsSafeFolderName(content_id_.substr(7, 9)))
            title_id_ = content_id_.substr(7, 9);
    }
}

PkgType Pkg::GetType() const {
    // The GD_AC content flag is deliberately NOT used: it classified a real PS5 base game as DLC.
    // The PS4 meaning of the content-flag bits has not been confirmed for PS5 packages, so only
    // the PARAM.SFO category decides DLC. Use --info to see the raw values, --type to override.
    if (content_flags_ & kPatchMask) return PkgType::Patch;
    if (sfo_category_ == "ac") return PkgType::Dlc;
    return PkgType::Base;
}

std::string Pkg::TypeReason() const {
    char buf[160];
    if (content_flags_ & kPatchMask) {
        std::snprintf(buf, sizeof(buf), "content_flags 0x%08X contains patch bits 0x%08X", content_flags_,
                      content_flags_ & kPatchMask);
        return buf;
    }
    if (sfo_category_ == "ac") return "PARAM.SFO CATEGORY is \"ac\"";
    return "no patch bits in content_flags and no PARAM.SFO \"ac\" category (default: base game)";
}

void Pkg::PrintInfo(std::ostream& os) const {
    auto hex = [&](const char* title, uint64_t offset, size_t size) {
        std::ifstream f(file_, std::ios::binary);
        std::vector<uint8_t> data(size);
        f.seekg(static_cast<std::streamoff>(offset));
        f.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size));
        data.resize(static_cast<size_t>(f.gcount()));
        os << "\n-- " << title << " (offset 0x" << std::hex << offset << ", " << std::dec << data.size()
           << " bytes)\n";
        for (size_t i = 0; i < data.size(); i += 16) {
            char line[96];
            int n = std::snprintf(line, sizeof(line), "%08llX  ", static_cast<unsigned long long>(offset + i));
            for (size_t j = 0; j < 16 && i + j < data.size(); j++)
                n += std::snprintf(line + n, sizeof(line) - static_cast<size_t>(n), "%02X ", data[i + j]);
            os << line << "\n";
        }
    };

    char buf[128];
    os << "== KytyPS5Plus package info ==\n";
    os << "file size        : " << file_size_ << "\n";
    os << "kind             : "
       << (kind_ == PkgKind::FinalizedDebug ? "finalized debug (FIH)" : "metadata container (bare CNT)") << "\n";
    std::snprintf(buf, sizeof(buf), "0x%02X", signed_byte_);
    os << "FIH signed byte  : " << buf << "\n";
    os << "FIH format ver   : " << format_version_ << "\n";
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(cnt_base_));
    os << "CNT base         : " << buf << "\n";
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(pfs_offset_));
    os << "PFS image offset : " << buf << "\n";
    os << "PFS image size   : " << pfs_size_ << "\n";
    os << "content id       : " << content_id_ << "\n";
    os << "title id         : " << title_id_ << "\n";
    std::snprintf(buf, sizeof(buf), "0x%08X", content_flags_);
    os << "content_flags    : " << buf;
    struct Named { uint32_t bit; const char* name; };
    constexpr Named names[] = {{0x100000, "FIRST_PATCH"}, {0x200000, "PATCHGO"}, {0x400000, "REMASTER"},
                               {0x800000, "PS_CLOUD"},    {0x2000000, "GD_AC"},  {0x4000000, "NON_GAME"},
                               {0x40000000, "SUBSEQUENT_PATCH"}};
    for (const Named& n : names)
        if (content_flags_ & n.bit) os << " " << n.name;
    os << "\n";
    std::snprintf(buf, sizeof(buf), "0x%08X", drm_type_);
    os << "drm_type         : " << buf << "\n";
    std::snprintf(buf, sizeof(buf), "0x%08X", content_type_);
    os << "content_type     : " << buf << "\n";
    os << "SFO CATEGORY     : " << (sfo_category_.empty() ? "(none)" : sfo_category_) << "\n";
    os << "detected type    : " << TypeDescription(GetType()) << "  [" << TypeReason() << "]\n";

    os << "\n-- entries (" << entries_.size() << ")\n";
    os << "id      flags1    flags2    offset    size      path\n";
    for (const PkgEntry& e : entries_) {
        std::snprintf(buf, sizeof(buf), "0x%04X  %08X  %08X  %08X  %-8u  ", e.id, e.flags1, e.flags2,
                      e.data_offset, e.data_size);
        os << buf << e.path << (e.Encrypted() ? "  [encrypted]" : "") << (e.in_bounds ? "" : "  [OUT OF BOUNDS]")
           << "\n";
    }

    if (kind_ == PkgKind::FinalizedDebug) hex("FIH header", 0, 0x60);
    hex("CNT header", cnt_base_, 0x80);
    if (kind_ == PkgKind::FinalizedDebug && pfs_size_ > 0) hex("start of inner PFS image", pfs_offset_, 0x200);
}

std::string Pkg::TypeDescription(PkgType type) const {
    switch (type) {
    case PkgType::Patch:
        return "pkg is a game update";
    case PkgType::Dlc:
        return "pkg is a dlc";
    default:
        return "pkg is a base game";
    }
}

std::string Pkg::EntitlementLabel() const {
    // CONTENT_ID looks like "UP0000-PPSA00000_00-XXXXXXXXXXXXXXXX"; the label is the last part.
    const size_t first = content_id_.find('-');
    if (first == std::string::npos) return {};
    const size_t second = content_id_.find('-', first + 1);
    if (second == std::string::npos) return {};
    const std::string label = content_id_.substr(second + 1);
    return IsSafeFolderName(label) ? label : std::string{};
}

bool Pkg::Extract(const fs::path& out_dir, ExtractReport& report, std::string& fail,
                  const std::function<void(size_t, size_t)>& progress) const {
    report = ExtractReport{};
    report.inner_image_present = kind_ == PkgKind::FinalizedDebug && pfs_size_ > 0;
    report.inner_image_size = pfs_size_;

    std::error_code ec;
    fs::create_directories(out_dir, ec);
    if (ec) {
        fail = "cannot create output folder: " + ec.message();
        return false;
    }
    std::ifstream in(file_, std::ios::binary);
    if (!in) {
        fail = "cannot reopen package";
        return false;
    }

    std::vector<uint8_t> buffer(1 << 20);
    for (size_t i = 0; i < entries_.size(); i++) {
        const PkgEntry& e = entries_[i];
        if (progress) progress(i + 1, entries_.size());

        if (e.Encrypted()) {
            report.skipped_encrypted++;
            continue;
        }
        if (!e.in_bounds) {
            report.skipped_out_of_bounds++;
            continue;
        }

        const fs::path target = out_dir / fs::path(e.path);
        fs::create_directories(target.parent_path(), ec);
        if (ec) {
            fail = "cannot create folder for " + e.path + ": " + ec.message();
            return false;
        }
        std::ofstream out(target, std::ios::binary | std::ios::trunc);
        if (!out) {
            fail = "cannot write " + target.string();
            return false;
        }
        uint64_t remaining = e.data_size;
        uint64_t offset = cnt_base_ + e.data_offset;
        while (remaining > 0) {
            const size_t chunk = static_cast<size_t>(std::min<uint64_t>(remaining, buffer.size()));
            if (!ReadAt(in, offset, buffer.data(), chunk)) {
                fail = "read error while extracting " + e.path;
                return false;
            }
            out.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(chunk));
            offset += chunk;
            remaining -= chunk;
        }
        report.written++;
    }
    return true;
}

} // namespace kyty
