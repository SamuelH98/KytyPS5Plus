// SPDX-FileCopyrightText: 2026 KytyPS5Plus contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace kyty {

constexpr uint32_t kMagicCnt = 0x7F434E54; // 0x7F 'C' 'N' 'T'
constexpr uint32_t kMagicFih = 0x7F464948; // 0x7F 'F' 'I' 'H'

/// Package categories. The numeric values double as the exit codes of `--check-type`.
enum class PkgType : int { Base = 101, Patch = 102, Dlc = 103 };

enum class PkgKind {
    MetadataContainer, ///< bare CNT, no inner image
    FinalizedDebug,    ///< FIH wrapper, signed byte 0x00
    FinalizedRetail,   ///< FIH wrapper, signed byte 0x80 (encrypted, unsupported)
};

enum class ContentFlag : uint32_t {
    FirstPatch = 0x100000,
    PatchGo = 0x200000,
    Remaster = 0x400000,
    PsCloud = 0x800000,
    GdAc = 0x2000000,
    NonGame = 0x4000000,
    SubsequentPatch = 0x40000000, // delta (0x41000000) and cumulative (0x60000000) include this bit
};

struct PkgEntry {
    uint32_t id = 0;
    uint32_t name_offset = 0;
    uint32_t flags1 = 0;
    uint32_t flags2 = 0;
    uint32_t data_offset = 0;
    uint32_t data_size = 0;
    bool in_bounds = false;
    std::string path; ///< sanitized relative output path

    bool Encrypted() const {
        return (flags1 & 0x80000000u) != 0;
    }
};

struct ExtractReport {
    size_t written = 0;
    size_t skipped_encrypted = 0;
    size_t skipped_out_of_bounds = 0;
    bool inner_image_present = false; ///< true when the package carries a PFS image
    uint64_t inner_image_size = 0;
    std::vector<std::string> warnings;

    /// True when everything in the package was written out.
    bool Complete() const {
        return !inner_image_present && skipped_encrypted == 0 && skipped_out_of_bounds == 0;
    }
};

class Pkg {
public:
    /// Cheap magic check (FIH or CNT).
    static bool IsPkg(const std::filesystem::path& file);

    bool Open(const std::filesystem::path& file, std::string& fail_reason);

    /// Writes every readable (plaintext, in-bounds) CNT entry below `out_dir`.
    /// The inner PFS image is NOT extracted; see ExtractReport::inner_image_present.
    bool Extract(const std::filesystem::path& out_dir, ExtractReport& report,
                 std::string& fail_reason,
                 const std::function<void(size_t, size_t)>& progress = {}) const;

    PkgType GetType() const;
    std::string TypeDescription(PkgType type) const;

    /// 9-character title id such as "PPSA01234".
    const std::string& TitleId() const {
        return title_id_;
    }
    const std::string& ContentId() const {
        return content_id_;
    }
    /// Third dash-separated part of the content id (the entitlement label used for DLC folders).
    std::string EntitlementLabel() const;

    PkgKind Kind() const {
        return kind_;
    }
    uint32_t ContentFlags() const {
        return content_flags_;
    }
    size_t EntryCount() const {
        return entries_.size();
    }
    const std::vector<PkgEntry>& Entries() const {
        return entries_;
    }

private:
    const PkgEntry* FindEntry(uint32_t id) const;
    bool ReadEntry(const PkgEntry& entry, uint64_t max_size, std::vector<uint8_t>& out) const;
    void LoadMetadata();
    void ResolvePaths();

    std::filesystem::path file_;
    uint64_t file_size_ = 0;
    uint64_t cnt_base_ = 0; ///< entry offsets are relative to this position
    PkgKind kind_ = PkgKind::MetadataContainer;
    uint64_t pfs_offset_ = 0;
    uint64_t pfs_size_ = 0;
    uint32_t content_flags_ = 0;
    std::string title_id_;
    std::string content_id_;
    std::string sfo_category_;
    std::vector<PkgEntry> entries_;
};

} // namespace kyty
