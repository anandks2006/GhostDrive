# SQLCipher on Windows

GhostDrive uses `sqlcipher3` for the encrypted index database. If the module is
not importable, GhostDrive still runs but stores the database **unencrypted** and
logs a warning — do not use that mode for real data.

## Recommended: pre-built wheel

```powershell
py -3.12 -m pip install sqlcipher3-binary
```

This ships the SQLCipher SQLite extension (`_sqlite3.cp312-win_amd64.pyd`) and
requires no C compiler.

## Verify

```powershell
py -3.12 -c "import sqlcipher3; print(sqlcipher3.__file__)"
```

`ghostdrive-cli doctor` also reports whether SQLCipher is available.

## Troubleshooting

- **`ModuleNotFoundError: No module named 'sqlcipher3'`** — install the wheel
  above into the same interpreter that runs GhostDrive.
- **`ImportError: DLL load failed`** — install the Microsoft Visual C++
  Redistributable (x64).
- **Database already created without SQLCipher** — the DB is plaintext SQLite.
  Create a new vault (or rotate to a new data directory) once SQLCipher is
  installed; there is no automatic plaintext-to-encrypted migration.
