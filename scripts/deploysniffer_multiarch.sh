#!/bin/bash
# Reference Bamboo deployment script for /home/festr/buildsniffer/deploysniffer.sh
# Backward-compatible multi-ISA deployment for download.voipmonitor.org/senzor/
#
# Guarantees 100% compatibility with ALL existing clients & GUIs:
#   - Keeps senzor/list.txt exact 5-column format unchanged
#   - Keeps voipmonitor.gz.{32,64,armv6k,arm64} and voipmonitor-wireshark.gz.64 unchanged
#   - Adds voipmonitor.gz.64-v{2,3,4} (when present in build artifacts) + manifest.txt
#   - Uses exact ${version} tarball filenames instead of ambiguous wildcard globs

set -euo pipefail

src_tarball=$(ls -1 voipmonitor-*-src.tar.gz | head -n 1)
version=$(echo "$src_tarball" | sed 's/voipmonitor-\(.*\)-src\.tar\.gz/\1/')
MAJOR=$(echo "$version" | cut -d'.' -f1)
MINOR=$(echo "$version" | cut -d'.' -f2)

DOWNLOAD_ROOT="/var/www/download.voipmonitor.org"
SENZOR_DIR="${DOWNLOAD_ROOT}/senzor/download/${version}"
mkdir -p "${SENZOR_DIR}"
mkdir -p "${DOWNLOAD_ROOT}/sniffer/${MAJOR}.${MINOR}"

# Clean any leftover unpacked directories in working dir
rm -rf "voipmonitor-amd64-${version}-static" \
       "voipmonitor-amd64-${version}-v2-static" \
       "voipmonitor-amd64-${version}-v3-static" \
       "voipmonitor-amd64-${version}-v4-static" \
       "voipmonitor-wireshark-amd64-${version}-static" \
       "voipmonitor-i686-${version}-static" \
       "voipmonitor-armv6k-${version}-static" \
       "voipmonitor-arm64-${version}-static" \
       "voipmonitor-${version}-src"

# Update www.voipmonitor.org version marker & copy tarballs to download + SourceForge
echo "${version}" > /tmp/snifferversion
scp /tmp/snifferversion root@hosting:/var/www/voipmonitor/
scp -o IdentitiesOnly=yes -i /root/.ssh/id_rsa *.gz "festr,voipmonitor@frs.sourceforge.net:/home/frs/project/v/vo/voipmonitor/${MAJOR}.${MINOR}/"
cp *.gz "${DOWNLOAD_ROOT}/sniffer/${MAJOR}.${MINOR}/"

# Extract mandatory legacy tarballs (exact version match so v2/v3/v4 don't collide!)
tar xzf "voipmonitor-amd64-${version}-static.tar.gz"
tar xzf "voipmonitor-wireshark-amd64-${version}-static.tar.gz"
tar xzf "voipmonitor-i686-${version}-static.tar.gz"
tar xzf "voipmonitor-armv6k-${version}-static.tar.gz"
tar xzf "voipmonitor-arm64-${version}-static.tar.gz"
tar xzf "voipmonitor-${version}-src.tar.gz"

# Publish ChangeLog
cp "voipmonitor-${version}-src/ChangeLog" "${SENZOR_DIR}/changelog.txt"
scp -o IdentitiesOnly=yes -i /root/.ssh/id_rsa "voipmonitor-${version}-src/ChangeLog" "festr,voipmonitor@frs.sourceforge.net:/home/frs/project/v/vo/voipmonitor/${MAJOR}.${MINOR}/README-changelog.txt"
scp "voipmonitor-${version}-src/ChangeLog" root@hosting:/var/www/voipmonitor/ChangeLog
cp "voipmonitor-${version}-src/ChangeLog" "${DOWNLOAD_ROOT}/"

# Stage legacy binaries
mv "voipmonitor-i686-${version}-static/usr/local/sbin/voipmonitor" "${SENZOR_DIR}/voipmonitor.32"
mv "voipmonitor-amd64-${version}-static/usr/local/sbin/voipmonitor" "${SENZOR_DIR}/voipmonitor.64"
mv "voipmonitor-wireshark-amd64-${version}-static/usr/local/sbin/voipmonitor" "${SENZOR_DIR}/voipmonitor-wireshark.64"
mv "voipmonitor-armv6k-${version}-static/usr/local/sbin/voipmonitor" "${SENZOR_DIR}/voipmonitor.armv6k"
mv "voipmonitor-arm64-${version}-static/usr/local/sbin/voipmonitor" "${SENZOR_DIR}/voipmonitor.arm64"

md5_32=$(md5sum "${SENZOR_DIR}/voipmonitor.32" | cut -f1 -d' ')
md5_64=$(md5sum "${SENZOR_DIR}/voipmonitor.64" | cut -f1 -d' ')
md5_armv6k=$(md5sum "${SENZOR_DIR}/voipmonitor.armv6k" | cut -f1 -d' ')
md5_64_ws=$(md5sum "${SENZOR_DIR}/voipmonitor-wireshark.64" | cut -f1 -d' ')
md5_arm64=$(md5sum "${SENZOR_DIR}/voipmonitor.arm64" | cut -f1 -d' ')

# Compress legacy binaries (exact legacy filenames)
gzip -f "${SENZOR_DIR}/voipmonitor.32"            && mv "${SENZOR_DIR}/voipmonitor.32.gz"            "${SENZOR_DIR}/voipmonitor.gz.32"
gzip -f "${SENZOR_DIR}/voipmonitor.64"            && mv "${SENZOR_DIR}/voipmonitor.64.gz"            "${SENZOR_DIR}/voipmonitor.gz.64"
gzip -f "${SENZOR_DIR}/voipmonitor-wireshark.64"  && mv "${SENZOR_DIR}/voipmonitor-wireshark.64.gz"  "${SENZOR_DIR}/voipmonitor-wireshark.gz.64"
gzip -f "${SENZOR_DIR}/voipmonitor.armv6k"        && mv "${SENZOR_DIR}/voipmonitor.armv6k.gz"        "${SENZOR_DIR}/voipmonitor.gz.armv6k"
gzip -f "${SENZOR_DIR}/voipmonitor.arm64"         && mv "${SENZOR_DIR}/voipmonitor.arm64.gz"         "${SENZOR_DIR}/voipmonitor.gz.arm64"

# Stage optional x86-64 ISA variants (v4, v3, v2) and generate manifest.txt atomically
manifest_tmp="${SENZOR_DIR}/manifest.txt.tmp"
{
    echo "# voipmonitor release manifest: <variant> <filename> <md5_uncompressed>"
    for isa in v4 v3 v2; do
        tarball="voipmonitor-amd64-${version}-${isa}-static.tar.gz"
        if [ -f "${tarball}" ]; then
            tar xzf "${tarball}"
            raw_bin="${SENZOR_DIR}/voipmonitor.64-${isa}"
            mv "voipmonitor-amd64-${version}-${isa}-static/usr/local/sbin/voipmonitor" "${raw_bin}"
            md5_isa=$(md5sum "${raw_bin}" | cut -f1 -d' ')
            gzip -f "${raw_bin}"
            mv "${raw_bin}.gz" "${SENZOR_DIR}/voipmonitor.gz.64-${isa}"
            echo "64-${isa} voipmonitor.gz.64-${isa} ${md5_isa}"
        fi
    done
    echo "64 voipmonitor.gz.64 ${md5_64}"
} > "${manifest_tmp}"
mv "${manifest_tmp}" "${SENZOR_DIR}/manifest.txt"

# Publish to list.txt LAST so clients never see a half-deployed release
# (Exact existing 5-MD5 format preserved — zero breakage for legacy GUIs/sniffers!)
echo -e "${version} http://download.voipmonitor.org/senzor/download/${version}\t${md5_32}\t${md5_64}\t${md5_armv6k}\t${md5_64_ws}\t${md5_arm64}" \
    >> "${DOWNLOAD_ROOT}/senzor/list.txt"
