@echo off
rem SPDX-FileCopyrightText: 2026 KytyPS5Plus contributors
rem SPDX-License-Identifier: GPL-2.0-or-later
setlocal EnableDelayedExpansion

set "pkg=%~1"
set "par=%~2"
set "gamesDir=PATH_TO_GAMES_DIR"
set "addonsDir=PATH_TO_ADDONS_DIR"
set "extractor=%~dp0pkg_extractor.exe"

if "%gamesDir%"=="PATH_TO_GAMES_DIR" (
	echo You need to update gamesDir with the games path used by KytyPS5
	if not "%par%"=="--batch" pause
	exit /b 0
)

if "%addonsDir%"=="PATH_TO_ADDONS_DIR" (
	echo You need to update addonsDir with the addons path used by KytyPS5
	if not "%par%"=="--batch" pause
	exit /b 0
)

"%extractor%" "%pkg%" --check-type
set "ret=%errorlevel%"

if "%ret%"=="0" (
	echo An error has occurred
) else (
	if "%ret%"=="101" echo The file is a base game, installing to %gamesDir%
	if "%ret%"=="102" echo The file is a game update, installing to %gamesDir%
	if "%ret%"=="103" (
		echo The file is a dlc, installing to %addonsDir%
		set "gamesDir=%addonsDir%"
	)

	"%extractor%" "%pkg%" "!gamesDir!"
)

if not "%par%"=="--batch" pause
