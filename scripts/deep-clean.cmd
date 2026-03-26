@echo off
setlocal
if exist ".venv\Scripts\python.exe" (
  .venv\Scripts\python.exe scripts\deep_clean_smoke.py %*
) else (
  python scripts\deep_clean_smoke.py %*
)
