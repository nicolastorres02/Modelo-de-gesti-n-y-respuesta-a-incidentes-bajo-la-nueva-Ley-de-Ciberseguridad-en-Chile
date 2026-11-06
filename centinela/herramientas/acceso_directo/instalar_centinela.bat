@echo off
rem Doble clic: instala el certificado de Centinela y crea el acceso directo en el escritorio.
rem Para otra IP:  instalar_centinela.bat 192.168.58.132
set IP=%1
if "%IP%"=="" set IP=192.168.58.132
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0instalar_centinela.ps1" -Servidor %IP%
pause
