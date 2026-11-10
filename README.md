# Standalone PKG extractor for KytyPS5

It has two main parts:

# pkg_extractor exe / AppImage

This is the extractor proper, it is a command line tool.
The first argument is the path to the pkg file to extract.
The second argument is where to extract it.
If no second argument is provided, it will be extracted next to the pkg file.

On Windows, you can drag and drop the pkg file onto the exe and it will extract it at the same location.

```
pkg_extractor <file.pkg> [output_dir] [--check-type] [--info] [--type base|patch|dlc]
```

`--info` extracts nothing and prints the header fields, content flags, entry table and the raw
bytes of the headers and of the start of the inner image. Use it to see why a package was
classified the way it was, and attach its output to a bug report.

Output layout (same as the tool this is modelled on):

| Package type | Extracted to |
| --- | --- |
| Base game | `<output_dir>/<TITLE_ID>` |
| Game update | `<output_dir>/<TITLE_ID>-patch` |
| DLC | `<output_dir>/<TITLE_ID>/<entitlement label>` |

`--check-type` extracts nothing and exits with `101` (base game), `102` (update), `103` (DLC) or `0`
(the file could not be read). The install scripts rely on this. `--type` overrides the detected type.

Exit codes when extracting: `0` everything written, `3` written but incomplete (see below), `1` failure.

# install_pkg sh / bat

This script has to be edited before use.
Set the values for `gamesDir` and `addonsDir` to the ones used in KytyPS5.

The first argument is the path to the pkg file to extract.

On Windows, you can drag and drop the pkg file onto the bat and it will extract it where it needs to be.

`batch_install.sh` / `batch_install.bat` run `install_pkg` on every `.pkg` in a folder.

# What this build does and does not do

**Supported: debug / fake PS5 packages only.** Retail packages are encrypted and are refused with a
clear message. This tool contains no key material and no decryption.

**Currently extracted:** the package's own metadata entries (`param.json`, `param.sfo`, icons and
artwork, trophy and UDS data, PlayGo data, and any named entries), written under their `sce_sys/...`
paths. Entries flagged encrypted are skipped and counted.

**Not yet extracted:** the inner PFS image that holds the game files (`eboot.bin`, assets, ...).
The extractor detects it and says so, and exits with code `3` instead of pretending the job is done.
Reading that image needs a PFS/PFSC reader (plus the Oodle Kraken decoder for compressed images);
the reference engine used by [PS5PKGTool](https://github.com/pearlxcore/PS5PKGTool) is a prebuilt
.NET library, so it cannot be linked into this C++ project and has to be reimplemented from the
format. That is the next milestone.

**Unverified assumptions.** The header offsets, entry layout and entry-id table were derived from the
readable parts of PS5PKGTool and the PS4 package layout the format descends from. They have been
tested against synthetic packages in `tests/`, **not against real console packages**. Package-type
detection (`101`/`102`/`103`) is a heuristic: patch is decided by the content-flag patch bits, DLC
only by the PARAM.SFO category (the `GD_AC` flag misclassified a real base game, so it is ignored).
The extractor prints which rule decided; use `--type` to override it if a package is classified wrongly.

# Build

```
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Requires a C++20 compiler and CMake 3.16+. There are no third-party library dependencies.
The tests need Python 3.

# Security

Everything read from a package is treated as untrusted. Entry names, the title id and the
entitlement label are sanitized so a hostile package cannot write outside the output folder, all
offsets are bounds-checked, and the parser has been run under AddressSanitizer/UBSan against
mutated and truncated packages.

# Credits and license

GPL-2.0-or-later (see `LICENSE`). The command line contract, install-script workflow and project
layout follow [ShadPs4Plus](https://github.com/AzaharPlus/shadPS4Plus); the PS5 package layout notes
come from [PS5PKGTool](https://github.com/pearlxcore/PS5PKGTool). No source code was copied from
either project.
