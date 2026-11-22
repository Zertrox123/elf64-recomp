#!/usr/bin/env bash
set -euo pipefail

# One-command builder & macOS .app packager for Portal: Revolution (Steam AppID 601360).
# Requires the user's own legally downloaded Windows x64 Steam depots (601361 + 601363)
# or an existing Windows Portal: Revolution install directory passed via --game-dir.

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STEAM_CONTENT="$HOME/Library/Application Support/Steam/Steam.AppBundle/Steam/Contents/MacOS/steamapps/content/app_601360"
GAME_DIR=""
OUT_APP="$REPO_ROOT/build/release/Portal Revolution.app"
OPT="-O1"
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 8)"

usage() {
    cat <<EOF
Usage: $0 [--game-dir PATH] [--out-app PATH] [--opt -O1|-O2] [-j N]

Builds a standalone Apple Silicon macOS app bundle (Portal Revolution.app)
from your own Steam copy of Portal: Revolution (Windows x64).

If --game-dir is omitted, automatically merges Steam depots 601361 and 601363
from:
  $STEAM_CONTENT

To download those depots legally on macOS, open Steam's console:
  open steam://open/console
and run:
  download_depot 601360 601361
  download_depot 601360 601363
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --game-dir) GAME_DIR="$2"; shift 2 ;;
        --out-app)  OUT_APP="$2"; shift 2 ;;
        --opt)      OPT="$2"; shift 2 ;;
        -j|--jobs)  JOBS="$2"; shift 2 ;;
        -h|--help)  usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

# 1. Verify required Homebrew libraries
missing=()
for pkg in sdl2 cairo pango; do
    if ! pkg-config --exists "$pkg" 2>/dev/null; then
        missing+=("$pkg")
    fi
done
if [[ ${#missing[@]} -gt 0 ]]; then
    echo "Missing Homebrew dependencies: ${missing[*]}" >&2
    echo "Install them with:" >&2
    echo "  brew install sdl2 cairo pango molten-vk vulkan-headers lld" >&2
    exit 1
fi

# 2. Locate or merge the Windows x64 game root
REV_ROOT="$REPO_ROOT/build/rev_root"
if [[ -n "$GAME_DIR" ]]; then
    REV_ROOT="$(cd "$GAME_DIR" && pwd)"
else
    D61="$STEAM_CONTENT/depot_601361"
    D63="$STEAM_CONTENT/depot_601363"
    if [[ ! -d "$D61/revolution" || ! -d "$D63/bin/win64" ]]; then
        echo "Portal: Revolution Steam depots not found at:" >&2
        echo "  $D61" >&2
        echo "  $D63" >&2
        echo "" >&2
        echo "Download them legally in Steam Console (open steam://open/console):" >&2
        echo "  download_depot 601360 601361" >&2
        echo "  download_depot 601360 601363" >&2
        echo "Or pass an existing Windows install with: $0 --game-dir /path/to/Portal\\ Revolution" >&2
        exit 1
    fi
    mkdir -p "$REV_ROOT/revolution"
    ln -sfn "$D63/bin" "$REV_ROOT/bin"
    ln -sfn "$D61/platform" "$REV_ROOT/platform"
    ln -sfn "$D61/steam_appid.txt" "$REV_ROOT/steam_appid.txt"
    [[ -e "$D61/thirdpartylegalnotices.txt" ]] && ln -sfn "$D61/thirdpartylegalnotices.txt" "$REV_ROOT/thirdpartylegalnotices.txt"
    ln -sfn "$D63/revolution/bin" "$REV_ROOT/revolution/bin"
    for item in "$D61/revolution"/*; do
        base="$(basename "$item")"
        [[ "$base" == "bin" ]] && continue
        ln -sfn "$item" "$REV_ROOT/revolution/$base"
    done
fi

BIN64="$REV_ROOT/bin/win64"
MOD64="$REV_ROOT/revolution/bin/win64"
MODULES=(
    "$BIN64/revolution.exe"
    "$BIN64/launcher.dll"
    "$BIN64/tier0.dll"
    "$BIN64/vstdlib.dll"
    "$BIN64/filesystem_stdio.dll"
    "$BIN64/engine.dll"
    "$BIN64/inputsystem.dll"
    "$BIN64/materialsystem.dll"
    "$BIN64/shaderapidx11.dll"
    "$BIN64/stdshader_dx11.dll"
    "$BIN64/studiorender.dll"
    "$BIN64/datacache.dll"
    "$BIN64/vphysics.dll"
    "$BIN64/vgui2.dll"
    "$BIN64/vguimatsurface.dll"
    "$BIN64/localize.dll"
    "$BIN64/scenefilecache.dll"
    "$BIN64/soundsystem.dll"
    "$BIN64/video_services.dll"
    "$BIN64/imemanager.dll"
    "$BIN64/soundemittersystem.dll"
    "$BIN64/vscript.dll"
    "$BIN64/engineaudio.dll"
    "$BIN64/richpresence.dll"
    "$BIN64/devui.dll"
    "$BIN64/toolframework.dll"
    "$MOD64/client.dll"
    "$MOD64/server.dll"
    "$BIN64/panorama.dll"
    "$BIN64/panoramauiclient.dll"
    "$BIN64/panorama_text_pango.dll"
)

for m in "${MODULES[@]}"; do
    if [[ ! -f "$m" ]]; then
        echo "Missing required game binary: $m" >&2
        exit 1
    fi
done

# 3. Static recompilation (x86_64 PE32+ -> C -> native ARM64 Mach-O)
WORK_DIR="$REPO_ROOT/build/rev_game"
OUT_BIN="$WORK_DIR/revolution_arm64"
echo "[1/2] Recompiling 31 PE64 modules -> native ARM64 ($OPT, -j $JOBS)..."
python3 "$REPO_ROOT/tools/build64.py" \
    -w "$WORK_DIR" \
    -o "$OUT_BIN" \
    --opt="$OPT" \
    -j "$JOBS" \
    "${MODULES[@]}"

# 4. Package standalone macOS .app bundle
echo "[2/2] Packaging standalone macOS app -> $OUT_APP..."
ICON_ARG=()
if [[ -f "$REV_ROOT/revolution/resource/game.icns" ]]; then
    ICON_ARG=(--icon "$REV_ROOT/revolution/resource/game.icns")
fi
python3 "$REPO_ROOT/tools/package_macos_app.py" \
    --app "$OUT_APP" \
    --binary "$OUT_BIN" \
    --prep-dir "$WORK_DIR/prep" \
    --game-root "$REV_ROOT" \
    --name "Portal: Revolution" \
    --bundle-id "com.elf64recomp.portal-revolution" \
    --default-cfg-rel "revolution/cfg/video.txt" \
    --skip users \
    --skip revolution/SAVE \
    --skip revolution/console.log \
    --skip revolution/cfg/video.txt \
    --skip revolution/cfg/videodefaults.txt \
    "${ICON_ARG[@]}"

echo ""
echo "Done! Launch with:"
echo "  open \"$OUT_APP\""
