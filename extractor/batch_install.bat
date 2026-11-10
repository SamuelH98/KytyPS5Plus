@echo off
rem SPDX-FileCopyrightText: 2026 KytyPS5Plus contributors
rem SPDX-License-Identifier: GPL-2.0-or-later

rem Installs every .pkg found in the folder given as the first argument.
set "dir=%~1"

for %%i in ("%dir%\*.pkg") do call "%~dp0install_pkg.bat" "%%i" --batch

echo Batch install done

pause
