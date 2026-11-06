@echo off
rem Doble clic: permite abrir Centinela desde el celular (pide permisos de administrador).
rem Para desactivarlo:  habilitar_acceso_celular.bat quitar
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0' -ArgumentList '%1'"
  exit /b
)
if /i "%1"=="quitar" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0habilitar_acceso_celular.ps1" -Quitar
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0habilitar_acceso_celular.ps1"
)
pause
