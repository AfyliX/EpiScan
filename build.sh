#!/bin/sh
set -e

cd "$(dirname "$0")"
mkdir -p build
cd build
cmake .. > /dev/null
cmake --build . -j"$(nproc)"

cd ..

# Live traffic capture needs CAP_NET_RAW/CAP_NET_ADMIN on the binary.
# The CMake POST_BUILD step only succeeds when the build itself runs as
# root, so grant it here once if it's still missing (asks for sudo).
if command -v setcap >/dev/null 2>&1 && command -v getcap >/dev/null 2>&1; then
	if [ -z "$(getcap ./build/episcan 2>/dev/null)" ]; then
		echo "Granting cap_net_raw,cap_net_admin to ./build/episcan for traffic capture (sudo needed)..."
		sudo setcap cap_net_raw,cap_net_admin=eip ./build/episcan || \
			echo "Could not set capabilities; live traffic capture will need 'sudo ./build/episcan' instead."
	fi
fi

export LD_LIBRARY_PATH="/opt/sfml2/lib:$LD_LIBRARY_PATH"
exec ./build/episcan "$@"
