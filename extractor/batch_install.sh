#!/bin/bash
# SPDX-FileCopyrightText: 2026 KytyPS5Plus contributors
# SPDX-License-Identifier: GPL-2.0-or-later

# Installs every .pkg found in the folder given as the first argument.
here="$(cd "$(dirname "$0")" && pwd)"

shopt -s nullglob
for f in "$1"/*.pkg ; do
	"$here/install_pkg.sh" "$f" --batch
done

echo "Press [enter] to close"
read
