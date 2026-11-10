1. pkg_extractor (or pkg_extractor.AppImage)

	Can be called in command line.
	The first argument is the path to the pkg file to extract.
	The second argument is where to extract it.
	If no second argument is provided, it will be extracted next to the pkg file.

	Only debug / fake PS5 packages are supported. Retail packages are encrypted and are refused.


2. install_pkg.sh

	Needs to be edited before use.
	Set the values for gamesDir and addonsDir to the ones used in KytyPS5.

	Can then be called in command line.
	The first argument is the path to the pkg file to extract.


3. batch_install.sh

	The first argument is a folder; every .pkg inside it is passed to install_pkg.sh.
