#!/usr/bin/env bash
set -euo pipefail

version="${1:?usage: pack-hub-release-linux.sh <hub-vX.Y.Z|manual>}"
if [[ "$version" != "manual" && ! "$version" =~ ^hub-v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "Unsafe hub release version: $version" >&2
  exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="$root/target/release/hacash-l2-hub"
[[ -x "$binary" ]] || { echo "Missing release binary: $binary" >&2; exit 1; }

dist="$root/dist-hub"
package_name="hpay-fast-pay-hub-linux-x86_64"
package="$dist/$package_name"
archive="$dist/$package_name-$version.tar.gz"

case "$dist" in
  "$root"/*) ;;
  *) echo "Refusing to clean a dist path outside the repository" >&2; exit 1 ;;
esac
rm -rf -- "$dist"
mkdir -p "$package"

install -m 0755 "$binary" "$package/hacash-l2-hub"
install -m 0755 "$root/scripts/install-vps-release.sh" "$package/INSTALL-VPS.sh"
install -m 0755 "$root/scripts/one-click-vps.sh" "$package/ONE-CLICK-VPS.sh"
install -m 0755 "$root/scripts/hpay-status.sh" "$package/hpay-status.sh"
install -m 0644 "$root/README-HUB.txt" "$package/README.txt"
install -m 0644 "$root/l2-hub.example.ini" "$package/l2-hub.example.ini"
install -m 0644 "$root/SECURITY.md" "$package/SECURITY.md"
install -m 0644 "$root/NETWORK-GLOBAL.md" "$package/NETWORK-GLOBAL.md"
install -m 0644 "$root/deploy/Caddyfile.example" "$package/Caddyfile.example"
install -m 0644 "$root/deploy/nginx.example.conf" "$package/nginx.example.conf"
install -m 0644 "$root/scripts/hacash-l2-hub.service" "$package/hacash-l2-hub.service"

commit="$(git -C "$root" rev-parse HEAD 2>/dev/null || printf unknown)"
printf '%s\n' "$version" > "$package/VERSION.txt"
printf '%s\n' "$commit" > "$package/SOURCE-COMMIT.txt"

tar -C "$dist" -czf "$archive" "$package_name"
(
  cd "$dist"
  sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256"
)
printf '%s\n' "$archive"
