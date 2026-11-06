@echo off
rem Inicia el buzón de correo de laboratorio de Centinela (doble clic).
chcp 65001 >nul
set PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe
if not exist "%PY%" set PY=%LOCALAPPDATA%\Programs\Python\Python314\python.exe
if not exist "%PY%" set PY=python
"%PY%" "%~dp0buzon_laboratorio.py" %*
pause
