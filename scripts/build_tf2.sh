#!/usr/bin/env bash
set -euo pipefail

# One-command builder & macOS .app packager for Team Fortress 2 (Steam AppID 440).
# Requires the user's own legally downloaded Windows x64 Steam depots (441 + 232251)
# or an existing Windows Team Fortress 2 install directory passed via --game-dir.

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STEAM_CONTENT="$HOME/Library/Application Support/Steam/Steam.AppBundle/Steam/Contents/MacOS/steamapps/content/app_440"
GAME_DIR=""
OUT_APP="$REPO_ROOT/build/release/Team Fortress 2.app"
OPT="-O2"
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 8)"

usage() {
    cat <<EOF
Usage: $0 [--game-dir PATH] [--out-app PATH] [--opt -O1|-O2] [-j N]

Builds a standalone Apple Silicon macOS app bundle (Team Fortress 2.app)
from your own Steam copy of Team Fortress 2 (Windows x64, free on Steam).

If --game-dir is omitted, automatically merges Steam depots 441 and 232251
from:
  $STEAM_CONTENT

To download those depots legally on macOS, open Steam's console:
  open steam://open/console
and run:
  download_depot 440 441
  download_depot 440 232251
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
if [[ ! -f /opt/homebrew/lib/libMoltenVK.dylib && ! -f /usr/local/lib/libMoltenVK.dylib ]]; then
    missing+=("molten-vk")
fi
if [[ ${#missing[@]} -gt 0 ]]; then
    echo "Missing Homebrew dependencies: ${missing[*]}" >&2
    echo "Install them with:" >&2
    echo "  brew install sdl2 cairo pango molten-vk vulkan-headers lld" >&2
    exit 1
fi

# 2. Locate or merge the Windows x64 game root
TF2_ROOT="$REPO_ROOT/build/tf2_root"
if [[ -n "$GAME_DIR" ]]; then
    TF2_ROOT="$(cd "$GAME_DIR" && pwd)"
else
    D441="$STEAM_CONTENT/depot_441"
    D251="$STEAM_CONTENT/depot_232251"
    if [[ ! -d "$D441/tf" || ! -f "$D251/tf_win64.exe" ]]; then
        echo "Team Fortress 2 Steam depots not found at:" >&2
        echo "  $D441" >&2
        echo "  $D251" >&2
        echo "" >&2
        echo "Download them legally in Steam Console (open steam://open/console):" >&2
        echo "  download_depot 440 441" >&2
        echo "  download_depot 440 232251" >&2
        echo "Or pass an existing Windows install with: $0 --game-dir /path/to/Team\\ Fortress\\ 2" >&2
        exit 1
    fi
    mkdir -p "$TF2_ROOT/tf/bin" "$TF2_ROOT/hl2"
    ln -sfn "$D251/tf_win64.exe" "$TF2_ROOT/tf_win64.exe"
    ln -sfn "$D251/bin" "$TF2_ROOT/bin"
    ln -sfn "$D441/platform" "$TF2_ROOT/platform"
    [[ -e "$D441/thirdpartylegalnotices.txt" ]] && ln -sfn "$D441/thirdpartylegalnotices.txt" "$TF2_ROOT/thirdpartylegalnotices.txt"
    printf '440\n' > "$TF2_ROOT/steam_appid.txt"
    for item in "$D441/hl2"/*; do
        ln -sfn "$item" "$TF2_ROOT/hl2/$(basename "$item")"
    done
    ln -sfn "$D251/tf/bin/x64" "$TF2_ROOT/tf/bin/x64"
    [[ -d "$D251/tf/media" ]] && ln -sfn "$D251/tf/media" "$TF2_ROOT/tf/media"
    for item in "$D441/tf"/*; do
        base="$(basename "$item")"
        [[ "$base" == "bin" || "$base" == "media" ]] && continue
        ln -sfn "$item" "$TF2_ROOT/tf/$base"
    done
fi

BIN64="$TF2_ROOT/bin/x64"
MOD64="$TF2_ROOT/tf/bin/x64"
MODULES=(
    "$TF2_ROOT/tf_win64.exe"
    "$BIN64/launcher.dll"
    "$BIN64/tier0.dll"
    "$BIN64/vstdlib.dll"
    "$BIN64/filesystem_stdio.dll"
    "$BIN64/engine.dll"
    "$BIN64/inputsystem.dll"
    "$BIN64/materialsystem.dll"
    "$BIN64/shaderapidx9.dll"
    "$BIN64/shaderapivk.dll"
    "$BIN64/dxvk_d3d9.dll"
    "$BIN64/stdshader_dx9.dll"
    "$BIN64/studiorender.dll"
    "$BIN64/datacache.dll"
    "$BIN64/vphysics.dll"
    "$BIN64/vgui2.dll"
    "$BIN64/vguimatsurface.dll"
    "$BIN64/libfreetype-6.dll"
    "$BIN64/GameUI.dll"
    "$BIN64/ServerBrowser.dll"
    "$BIN64/scenefilecache.dll"
    "$BIN64/soundemittersystem.dll"
    "$BIN64/soundsystem.dll"
    "$BIN64/vscript.dll"
    "$BIN64/replay.dll"
    "$BIN64/unicode.dll"
    "$BIN64/video_services.dll"
    "$BIN64/vaudio_minimp3.dll"
    "$BIN64/vaudio_celt.dll"
    "$BIN64/bsppack.dll"
    "$MOD64/client.dll"
    "$MOD64/server.dll"
)

for m in "${MODULES[@]}"; do
    if [[ ! -f "$m" ]]; then
        echo "Missing required game binary: $m" >&2
        exit 1
    fi
done

# 3. Static recompilation (x86_64 PE32+ -> C -> native ARM64 Mach-O)
WORK_DIR="$REPO_ROOT/build/tf2_game/work"
OUT_BIN="$REPO_ROOT/build/tf2_game/tf2_arm64"
mkdir -p "$(dirname "$OUT_BIN")"
echo "[1/2] Recompiling 32 PE64 modules -> native ARM64 ($OPT, -j $JOBS)..."
python3 "$REPO_ROOT/tools/build64.py" \
    -w "$WORK_DIR" \
    -o "$OUT_BIN" \
    --opt="$OPT" \
    -j "$JOBS" \
    "${MODULES[@]}"

# 4. Package standalone macOS .app bundle
echo "[2/2] Packaging standalone macOS app -> $OUT_APP..."
ICON_ARG=()
if [[ -f "$TF2_ROOT/tf/resource/game.icns" ]]; then
    ICON_ARG=(--icon "$TF2_ROOT/tf/resource/game.icns")
fi
python3 "$REPO_ROOT/tools/package_macos_app.py" \
    --app "$OUT_APP" \
    --binary "$OUT_BIN" \
    --prep-dir "$WORK_DIR/prep" \
    --game-root "$TF2_ROOT" \
    --name "Team Fortress 2" \
    --bundle-id "com.elf64recomp.tf2" \
    --skip tf/console.log \
    --skip tf_win64_d3d9.log \
    --arg=-game --arg=tf --arg=-steam --arg=-sw --arg=-w --arg=1280 --arg=-h --arg=720 --arg=-dxlevel --arg=95 --arg=-novid \
    "${ICON_ARG[@]}"

echo ""
echo "Done! Launch with:"
echo "  open \"$OUT_APP\""
echo "Or install into /Applications (APFS copy-on-write clone) so Spotlight finds it:"
echo "  cp -Rc \"$OUT_APP\" \"/Applications/Team Fortress 2.app\""
