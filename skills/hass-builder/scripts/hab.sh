#!/usr/bin/env bash

set -euo pipefail

REPO="balloob/home-assistant-build-cli"
BASE_URL="https://github.com/${REPO}/releases/latest/download"
CACHE_DIR="${HOME}/.cache/hab-cli"

detect_os() {
    case "$(uname -s 2>/dev/null)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "darwin" ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT) echo "windows" ;;
        *)       echo "unsupported" ;;
    esac
}

detect_arch() {
    case "$(uname -m 2>/dev/null)" in
        x86_64|amd64|x64)     echo "amd64" ;;
        aarch64|arm64|armv8l) echo "arm64" ;;
        *)                    echo "unsupported" ;;
    esac
}

get_filename() {
    local os="$1" arch="$2" name="hab-${os}-${arch}"
    [ "${os}" = "windows" ] && name="${name}.exe"
    echo "${name}"
}

download() {
    local url="$1" dest="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fSL --progress-bar -o "${dest}" "${url}"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --show-progress -O "${dest}" "${url}"
    else
        echo "Error: curl or wget required" >&2
        exit 1
    fi
}

main() {
    local os arch filename binary_path url

    os="$(detect_os)"
    arch="$(detect_arch)"

    if [ "${os}" = "unsupported" ] || [ "${arch}" = "unsupported" ]; then
        echo "Error: unsupported platform ($(uname -s -m 2>/dev/null))" >&2
        exit 1
    fi

    filename="$(get_filename "${os}" "${arch}")"
    binary_path="${CACHE_DIR}/${filename}"

    if [ ! -s "${binary_path}" ]; then
        mkdir -p "${CACHE_DIR}"

        url="${BASE_URL}/${filename}"
        echo "Downloading hab (${os}/${arch})..."

        local tmp_file
        tmp_file="${CACHE_DIR}/.download-${filename}"

        if download "${url}" "${tmp_file}" && [ -s "${tmp_file}" ]; then
            chmod +x "${tmp_file}"
            mv -f "${tmp_file}" "${binary_path}"
        else
            rm -f "${tmp_file}"
            echo "Error: download failed from ${url}" >&2
            exit 1
        fi
    fi

    exec "${binary_path}" "$@"
}

main "$@"