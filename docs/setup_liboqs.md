# Post-quantum sharing (ML-KEM-768)

The optional `mlkem` Python package is used by the ML-KEM-768 sharing helpers
(`ghostdrive/crypto/sharing_keys.py`). It is **not required** for the core drive:
uploads, downloads, backends, sharing links, and integrity verification work
without it. `GET /api/secrets/post-quantum-status` reports whether it is
installed.

## Install

Most platforms have pre-built wheels:

```powershell
py -3.12 -m pip install mlkem
```

If no wheel exists for your platform, build the `liboqs` C library first:

1. Install CMake and a C compiler (Visual Studio Build Tools on Windows).
2. Build and install liboqs:
   ```powershell
   git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
   cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=C:\liboqs
   cmake --build liboqs/build --config Release
   cmake --install liboqs/build
   ```
3. Point the build at the library and install:
   ```powershell
   $env:CMAKE_PREFIX_PATH = "C:\liboqs"
   py -3.12 -m pip install mlkem
   ```

## Verify

```powershell
py -3.12 -c "from mlkem.ml_kem import ML_KEM, ML_KEM_768; print('ML-KEM-768 ready')"
```

If this import fails, the app degrades gracefully: the PQ status endpoint
reports `ml_kem_768_supported: false` and classical sharing paths remain usable.
