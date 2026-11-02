"""Downloads a portable 64-bit Windows CPython 3.12 (from conda-forge) into installer/build/python.
Runs on Windows, Linux or macOS. Requires: pip install zstandard
Usage:  python fetch_python.py"""
import io
import json
import os
import shutil
import sys
import tarfile
import urllib.request
import zipfile

try:
    import zstandard
except ImportError:
    sys.exit("Please run:  pip install zstandard")

CHANNEL = "https://conda.anaconda.org/conda-forge/win-64/"
# Pinned, tested package set (Python 3.12.16 + native dependencies)
PACKAGES = [
    "python-3.12.16-hb12b558_0_cpython.conda", "libpython-3.12.16-hfb4101e_0_cpython.conda",
    "bzip2-1.0.8-h2466b09_7.conda", "libexpat-2.9.0-hac47afa_0.conda", "libffi-3.7.0-h3d046cb_1.conda",
    "liblzma-5.8.3-hfd05255_1.conda", "libsqlite-3.54.1-hf5d6505_101.conda", "libzlib-1.3.2-hfd05255_3.conda",
    "openssl-3.6.5-hf411b9b_0.conda", "vc14_runtime-14.51.36247-habf1de7_42.conda",
]
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "build", "python")
CACHE = os.path.join(HERE, "build", "cache")
REMOVE = ["include", "libs", "Tools", "info", "etc", "Scripts", "Library/include", "Library/lib", "Library/share",
          "Library/ssl", "Lib/test", "Lib/idlelib", "Lib/tkinter", "Lib/turtledemo", "Lib/ensurepip", "Lib/lib2to3"]
DLLS = ["ffi-8", "libbz2", "libcrypto-3-x64", "libexpat", "liblzma", "libssl-3-x64", "sqlite3"]


def main():
    os.makedirs(CACHE, exist_ok=True)
    if os.path.exists(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)
    for name in PACKAGES:
        path = os.path.join(CACHE, name)
        if not os.path.exists(path):
            print("downloading", name)
            urllib.request.urlretrieve(CHANNEL + name, path)
        z = zipfile.ZipFile(path)
        for n in z.namelist():
            if n.startswith("pkg-") and n.endswith(".tar.zst"):
                stream = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(z.read(n)))
                with tarfile.open(fileobj=stream, mode="r|") as t:
                    t.extractall(OUT, filter="data") if sys.version_info >= (3, 12) else t.extractall(OUT)
    for r in REMOVE:
        shutil.rmtree(os.path.join(OUT, r), ignore_errors=True)
    sp = os.path.join(OUT, "Lib", "site-packages")
    for n in os.listdir(sp) if os.path.isdir(sp) else []:
        p = os.path.join(sp, n)
        shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
    for root, dirs, files in os.walk(OUT):
        for d in list(dirs):
            if d == "__pycache__":
                shutil.rmtree(os.path.join(root, d))
                dirs.remove(d)
        for f in files:
            if f.endswith(".pdb"):
                os.remove(os.path.join(root, f))
    for f in ("openssl.exe", "c_rehash.pl"):
        p = os.path.join(OUT, "Library", "bin", f)
        if os.path.exists(p):
            os.remove(p)
    for d in DLLS:
        shutil.copy2(os.path.join(OUT, "Library", "bin", d + ".dll"), os.path.join(OUT, "DLLs"))
    print("Portable Python ready in", OUT)


if __name__ == "__main__":
    main()
