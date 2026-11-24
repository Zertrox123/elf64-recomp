#!/usr/bin/env python3
"""Package a recompiled elf64-recomp ARM64 binary into a standalone macOS .app bundle.

Bundles the native ARM64 Mach-O executable, module memory images (*.img), game data
directory (dereferencing symlinks via APFS copy-on-write cloning when available),
relocated Homebrew dylibs (SDL2/SDL3/Cairo/Pango/FreeType/Fontconfig/GLib), a
self-contained Fontconfig config, a native ARM64 Mach-O launcher, and ad-hoc code
signatures so the resulting .app runs with zero external Homebrew dependencies.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, Iterable, List, Set

LAUNCHER_C = r"""#include <mach-o/dyld.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char exe[PATH_MAX], real_exe[PATH_MAX];
    uint32_t sz = sizeof(exe);
    if (_NSGetExecutablePath(exe, &sz) != 0 || !realpath(exe, real_exe)) {
        fprintf(stderr, "launcher: cannot locate bundle executable\n");
        return 1;
    }
    char *slash = strrchr(real_exe, '/');
    if (!slash) return 1;
    *slash = '\0';
    char bin[PATH_MAX], contents[PATH_MAX];
    snprintf(bin, sizeof(bin), "%s/%s", real_exe, LAUNCH_BIN_NAME);
    snprintf(contents, sizeof(contents), "%s", real_exe);
    slash = strrchr(contents, '/');
    if (!slash) return 1;
    *slash = '\0';

    char game[PATH_MAX], img[PATH_MAX], fw[PATH_MAX], fc[PATH_MAX];
    snprintf(game, sizeof(game), "%s/Resources/game", contents);
    snprintf(img,  sizeof(img),  "%s/Resources/img", contents);
    snprintf(fw,   sizeof(fw),   "%s/Frameworks", contents);
    snprintf(fc,   sizeof(fc),   "%s/Resources/fonts.conf", contents);

    setenv("ELF64_WIN_ROOT", game, 1);
    setenv("ELF64_IMG_DIR", img, 1);
    setenv("ELF64_LIB_DIR", fw, 1);
    setenv("FONTCONFIG_FILE", fc, 1);
    setenv("DYLD_FALLBACK_LIBRARY_PATH", fw, 1);

    if (chdir(game) != 0) {
        perror("chdir");
        return 1;
    }

    static const char *kDefaultArgs[] = { DEFAULT_ARGS_INIT NULL };
    int n_def = (int)(sizeof(kDefaultArgs) / sizeof(kDefaultArgs[0])) - 1;
    char **nargv = (char **)calloc((size_t)(argc + n_def + 8), sizeof(char *));
    if (!nargv) return 1;
    int n = 0;
    nargv[n++] = bin;
    for (int i = 0; i < n_def; i++) nargv[n++] = (char *)kDefaultArgs[i];
    int has_user_args = 0;
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-psn_", 5) == 0) continue;
        nargv[n++] = argv[i];
        has_user_args = 1;
    }
    if (!has_user_args && DEFAULT_CFG_REL[0]) {
        char vcfg[PATH_MAX];
        snprintf(vcfg, sizeof(vcfg), "%s/%s", game, DEFAULT_CFG_REL);
        if (access(vcfg, F_OK) != 0) {
            nargv[n++] = "-windowed";
            nargv[n++] = "-w";
            nargv[n++] = "1280";
            nargv[n++] = "-h";
            nargv[n++] = "720";
        }
    }
    nargv[n] = NULL;
    execv(bin, nargv);
    perror("execv");
    return 1;
}
"""

FONTS_CONF = """<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">
<fontconfig>
  <dir>/System/Library/Fonts</dir>
  <dir>/System/Library/Fonts/Supplemental</dir>
  <dir>/Library/Fonts</dir>
  <dir prefix="xdg">fonts</dir>
  <dir>~/Library/Fonts</dir>
  <cachedir>/tmp/elf64_recomp_fc_cache</cachedir>
</fontconfig>
"""

DEFAULT_SEED_LIBS = [
    "/opt/homebrew/opt/sdl2-compat/lib/libSDL2-2.0.0.dylib",
    "/opt/homebrew/opt/sdl3/lib/libSDL3.0.dylib",
    "/opt/homebrew/lib/libMoltenVK.dylib",
    "/opt/homebrew/lib/libglib-2.0.dylib",
    "/opt/homebrew/lib/libgobject-2.0.dylib",
    "/opt/homebrew/lib/libfreetype.dylib",
    "/opt/homebrew/lib/libfontconfig.dylib",
    "/opt/homebrew/lib/libcairo.dylib",
    "/opt/homebrew/lib/libpango-1.0.dylib",
    "/opt/homebrew/lib/libpangoft2-1.0.dylib",
]


def apfs_clone_file(src: str, dst: str) -> None:
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    r = subprocess.run(["cp", "-c", src, dst], capture_output=True)
    if r.returncode != 0:
        shutil.copy2(src, dst)


def clone_tree_deref(src_root: str, dst_root: str, skip_rel: Set[str]) -> int:
    src_root = os.path.realpath(src_root)
    count = 0
    for dirpath, dirnames, filenames in os.walk(src_root, followlinks=True):
        rel_dir = os.path.relpath(dirpath, src_root)
        if rel_dir == ".":
            rel_dir = ""
        dirnames[:] = [
            d for d in dirnames
            if os.path.normpath(os.path.join(rel_dir, d)) not in skip_rel
        ]
        out_dir = os.path.join(dst_root, rel_dir) if rel_dir else dst_root
        os.makedirs(out_dir, exist_ok=True)
        for fn in filenames:
            rel_f = os.path.normpath(os.path.join(rel_dir, fn))
            if rel_f in skip_rel:
                continue
            sp = os.path.realpath(os.path.join(dirpath, fn))
            if not os.path.isfile(sp):
                continue
            apfs_clone_file(sp, os.path.join(out_dir, fn))
            count += 1
    return count


def otool_deps(path: str) -> List[str]:
    out = subprocess.check_output(["otool", "-L", path], text=True)
    deps: List[str] = []
    for line in out.splitlines()[1:]:
        p = line.strip().split(" (", 1)[0]
        if not p or p.startswith("/usr/lib/") or p.startswith("/System/Library/"):
            continue
        deps.append(p)
    return deps


def bundle_dylibs(bin_dst: str, frameworks_dir: str, extra_seeds: Iterable[str]) -> int:
    real_to_base: Dict[str, str] = {}
    alias_links: Dict[str, str] = {}
    queue: List[str] = []

    def enqueue(path: str) -> None:
        if not path:
            return
        req_base = os.path.basename(path)
        rp = os.path.realpath(path)
        if not os.path.isfile(rp):
            cand = os.path.join("/opt/homebrew/lib", req_base)
            if os.path.isfile(cand):
                rp = os.path.realpath(cand)
            else:
                return
        real_base = os.path.basename(rp)
        if req_base != real_base:
            alias_links[req_base] = real_base
        if rp not in real_to_base:
            real_to_base[rp] = real_base
            queue.append(rp)

    for s in extra_seeds:
        enqueue(s)
    for dep in otool_deps(bin_dst):
        enqueue(dep)

    while queue:
        cur = queue.pop(0)
        for dep in otool_deps(cur):
            if dep.startswith("@"):
                cand = os.path.join(os.path.dirname(cur), os.path.basename(dep))
                if not os.path.isfile(cand):
                    cand = os.path.join("/opt/homebrew/lib", os.path.basename(dep))
                enqueue(cand)
            else:
                enqueue(dep)

    # sdl2-compat dlopens unversioned @loader_path/libSDL3.dylib at runtime.
    if "libSDL3.0.dylib" in real_to_base.values():
        alias_links["libSDL3.dylib"] = "libSDL3.0.dylib"

    for rp, base in sorted(real_to_base.items(), key=lambda kv: kv[1]):
        dst = os.path.join(frameworks_dir, base)
        shutil.copy2(rp, dst)
        os.chmod(dst, 0o755)
        subprocess.check_call(["install_name_tool", "-id", f"@loader_path/{base}", dst])
        for dep in otool_deps(dst):
            db = os.path.basename(dep)
            if db == base:
                continue
            target = alias_links.get(db, db)
            if target in real_to_base.values():
                subprocess.check_call(["install_name_tool", "-change", dep, f"@loader_path/{target}", dst])
            elif db in real_to_base.values():
                subprocess.check_call(["install_name_tool", "-change", dep, f"@loader_path/{db}", dst])

    for alias, target in alias_links.items():
        lp = os.path.join(frameworks_dir, alias)
        if not os.path.exists(lp) and os.path.exists(os.path.join(frameworks_dir, target)):
            os.symlink(target, lp)

    for dep in otool_deps(bin_dst):
        db = os.path.basename(dep)
        target = alias_links.get(db, db)
        subprocess.check_call(
            ["install_name_tool", "-change", dep, f"@executable_path/../Frameworks/{target}", bin_dst]
        )

    return len(real_to_base)


def package_app(
    app_path: str,
    binary: str,
    prep_dir: str,
    game_root: str,
    name: str,
    bundle_id: str,
    icon: str | None = None,
    default_cfg_rel: str = "",
    skip_rel: Iterable[str] = (),
    default_args: Iterable[str] = (),
) -> str:
    app_path = os.path.abspath(app_path)
    contents = os.path.join(app_path, "Contents")
    macos = os.path.join(contents, "MacOS")
    frameworks = os.path.join(contents, "Frameworks")
    resources = os.path.join(contents, "Resources")
    img_dir = os.path.join(resources, "img")
    game_dir = os.path.join(resources, "game")

    if os.path.exists(app_path):
        shutil.rmtree(app_path)
    for d in (macos, frameworks, resources, img_dir, game_dir):
        os.makedirs(d, exist_ok=True)

    n_img = 0
    for fn in sorted(os.listdir(prep_dir)):
        if fn.endswith(".img"):
            apfs_clone_file(os.path.join(prep_dir, fn), os.path.join(img_dir, fn))
            n_img += 1

    n_game = clone_tree_deref(game_root, game_dir, {os.path.normpath(p) for p in skip_rel})

    bin_name = os.path.basename(binary)
    bin_dst = os.path.join(macos, bin_name)
    shutil.copy2(binary, bin_dst)
    os.chmod(bin_dst, 0o755)
    subprocess.check_call(["strip", "-x", bin_dst])

    n_libs = bundle_dylibs(bin_dst, frameworks, DEFAULT_SEED_LIBS)

    if icon and os.path.isfile(icon):
        apfs_clone_file(icon, os.path.join(resources, "AppIcon.icns"))

    with open(os.path.join(resources, "fonts.conf"), "w") as f:
        f.write(FONTS_CONF)

    exec_name = "".join(ch for ch in name if ch.isalnum()) or "AppLauncher"
    with open(os.path.join(contents, "Info.plist"), "w") as f:
        f.write(
            f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key><string>en</string>
    <key>CFBundleDisplayName</key><string>{name}</string>
    <key>CFBundleExecutable</key><string>{exec_name}</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundleIdentifier</key><string>{bundle_id}</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleName</key><string>{name}</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>1.0.0</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.games</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSPrincipalClass</key><string>NSApplication</string>
</dict>
</plist>
"""
        )

    def_args_c = "".join(
        '"' + a.replace("\\", "\\\\").replace('"', '\\"') + '", ' for a in default_args
    )
    launcher_bin = os.path.join(macos, exec_name)
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as tf:
        tf.write(LAUNCHER_C)
        lc_path = tf.name
    try:
        subprocess.check_call(
            [
                "clang", "-O2", "-arch", "arm64",
                f'-DLAUNCH_BIN_NAME="{bin_name}"',
                f'-DDEFAULT_CFG_REL="{default_cfg_rel}"',
                f"-DDEFAULT_ARGS_INIT={def_args_c}",
                lc_path, "-o", launcher_bin,
            ]
        )
    finally:
        os.unlink(lc_path)

    for fn in sorted(os.listdir(frameworks)):
        fp = os.path.join(frameworks, fn)
        if os.path.isfile(fp) and not os.path.islink(fp):
            subprocess.check_call(["codesign", "--force", "--sign", "-", fp], stderr=subprocess.DEVNULL)
    subprocess.check_call(["codesign", "--force", "--sign", "-", bin_dst], stderr=subprocess.DEVNULL)
    subprocess.check_call(["codesign", "--force", "--sign", "-", launcher_bin], stderr=subprocess.DEVNULL)
    subprocess.check_call(["codesign", "--force", "--sign", "-", app_path], stderr=subprocess.DEVNULL)

    print(f"package_macos_app: built {app_path} ({n_img} .img, {n_game} game files, {n_libs} dylibs)")
    return app_path


def main() -> int:
    ap = argparse.ArgumentParser(description="Package a recompiled elf64-recomp game into a standalone macOS .app.")
    ap.add_argument("--app", required=True, help="Output .app path")
    ap.add_argument("--binary", required=True, help="Recompiled ARM64 Mach-O binary")
    ap.add_argument("--prep-dir", required=True, help="Directory containing *.img memory images")
    ap.add_argument("--game-root", required=True, help="Game root directory to bundle")
    ap.add_argument("--name", required=True, help="Display name (e.g. 'Portal: Revolution')")
    ap.add_argument("--bundle-id", default="com.elf64recomp.game", help="CFBundleIdentifier")
    ap.add_argument("--icon", default=None, help="Optional .icns file path")
    ap.add_argument("--default-cfg-rel", default="", help="Relative video config path (adds -windowed 1280x720 if absent)")
    ap.add_argument("--skip", action="append", default=[], help="Relative paths inside game-root to omit")
    ap.add_argument("--arg", action="append", default=[], help="Default argument passed to the binary (repeatable)")
    args = ap.parse_args()
    package_app(
        args.app, args.binary, args.prep_dir, args.game_root,
        name=args.name, bundle_id=args.bundle_id, icon=args.icon,
        default_cfg_rel=args.default_cfg_rel, skip_rel=args.skip,
        default_args=args.arg,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
