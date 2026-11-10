#!/bin/bash
# SPDX-FileCopyrightText: 2026 KytyPS5Plus contributors
# SPDX-License-Identifier: GPL-2.0-or-later

gamesDir="PATH_TO_GAMES_DIR"
addonsDir="PATH_TO_ADDONS_DIR"

here="$(cd "$(dirname "$0")" && pwd)"

# Use the AppImage if present, otherwise the plain binary.
if [ -x "$here/pkg_extractor.AppImage" ]; then
	extractor="$here/pkg_extractor.AppImage"
else
	extractor="$here/pkg_extractor"
fi

pause() {
	echo "Press [enter] to close"
	if [ "$2" != "--batch" ]; then read ; fi
}

if [ "$gamesDir" == "PATH_TO_GAMES_DIR" ]; then
	echo "You need to update gamesDir with the games path used by KytyPS5"
	pause "$@"
	exit
fi

if [ "$addonsDir" == "PATH_TO_ADDONS_DIR" ]; then
	echo "You need to update addonsDir with the addons path used by KytyPS5"
	pause "$@"
	exit
fi

"$extractor" "$1" --check-type

ret="$?"

if [ "$ret" -eq 0 ]; then
	echo "An error has occurred."
else
	if [ "$ret" -eq 101 ]; then
		echo "The file is a base game, installing to $gamesDir"
	elif [ "$ret" -eq 102 ]; then
		echo "The file is a game update, installing to $gamesDir"
	elif [ "$ret" -eq 103 ]; then
		echo "The file is a dlc, installing to $addonsDir"
		gamesDir="$addonsDir"
	fi

	"$extractor" "$1" "$gamesDir"
fi

pause "$@"
