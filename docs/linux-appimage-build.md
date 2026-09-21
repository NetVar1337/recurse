# Linux AppImage build notes (Arch / bleeding-edge distros)

`npm run tauri build` and `just build` bundle a `.deb`, `.rpm`, and `.AppImage`,
but the AppImage step runs [`linuxdeploy`](https://github.com/linuxdeploy/linuxdeploy)
plus its GTK plugin, and both assume a Linux userland older than what Arch and
other rolling distros now ship. The `.deb`/`.rpm`/standalone binary build fine
regardless — only the AppImage step fails.

You will see this at the end of an otherwise successful build:

```
failed to bundle project: `failed to run linuxdeploy`
```

The full error is `[gtk/stderr] ...` noise earlier in the output; two independent
causes are involved.

## Cause 1 — gdk-pixbuf no longer ships a loader directory

`linuxdeploy-plugin-gtk` unconditionally copies
`/usr/lib/gdk-pixbuf-2.0/2.10.0`, but gdk-pixbuf 2.44 (Arch) has no external
loader modules and therefore does not create that directory. The plugin's copy
step aborts the whole bundle.

Confirm it is missing:

```bash
ls /usr/lib/gdk-pixbuf-2.0/2.10.0/loaders
# ls: cannot access '...': No such file or directory
```

## Cause 2 — linuxdeploy bundles a 2020-era strip

Even once the directory exists, `linuxdeploy`'s bundled `strip` faults. It ships
**GNU strip 2.35**, which predates the `.relr.dyn` ELF section that modern
distro libraries use, so it fails on almost every copied `.so`:

```
strip: ... unknown type [0x13] section `.relr.dyn'
```

Your system toolchain is far newer:

```bash
strip --version | head -n 1   # GNU strip (GNU Binutils) 2.47
```

`linuxdeploy` only exposes `NO_STRIP` as an escape hatch — there is no way to
point it at the system `strip`.

## Fix — on your machine, not in the repo

The missing directory lives under root-owned `/usr/lib`, so this needs `sudo`
once (a symlink there would need it too). `NO_STRIP=1` covers the strip half.

```bash
# 1. Give the GTK plugin the directory it insists on copying.
sudo mkdir -p /usr/lib/gdk-pixbuf-2.0/2.10.0/loaders

# 2. Tell linuxdeploy's bundled (2020-era) strip to stand down.
echo 'export NO_STRIP=1' >> ~/.bashrc   # or your shell's rc file
exec $SHELL -l
```

After that, `just build` / `npm run tauri build` work with no source changes.

Trade-off: `NO_STRIP=1` leaves every bundled library unstripped, so the AppImage
is roughly **106 MB** instead of ~35 MB. Fine for local dev; for release
artifacts, prefer building the AppImage on a distro whose toolchain linuxdeploy
supports (e.g. Ubuntu CI), where stripping still works.

## Verify

```bash
just build
# ...
#     Finished 3 bundles at:
#         target/release/bundle/deb/recurse_0.1.0_amd64.deb
#         target/release/bundle/rpm/recurse-0.1.0-1.x86_64.rpm
#         target/release/bundle/appimage/recurse_0.1.0_amd64.AppImage
```

## Why this is not patched in the repository

Both causes are upstream tooling bugs that the distro raced ahead of. A shim in
`package.json` would have to (a) fake a `gdk-pixbuf-2.0.pc`, and (b) force
`NO_STRIP=1` for everyone — silently tripling the AppImage size for all
contributors and CI, while being invisible on machines that never hit the bug.
Keeping the fix on the affected machine leaves the build path vanilla for
everyone else, and this page is the discoverable note for the next person on a
rolling distro.
