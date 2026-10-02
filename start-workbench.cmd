@echo off
setlocal EnableExtensions

rem Start the source checkout from any current directory without installing it.
set "FK_PROJECT_ROOT=%~dp0"
set "FK_CASE=%FK_PROJECT_ROOT%examples\sample-case"
set "FK_PORT=8765"

if not "%~1"=="" for %%I in ("%~1") do set "FK_CASE=%%~fI"
if not "%~2"=="" set "FK_PORT=%~2"

if not exist "%FK_CASE%\" goto case_missing
pushd "%FK_PROJECT_ROOT%" || goto checkout_unavailable

if defined FK_PYTHON goto use_python
where py >nul 2>nul
if errorlevel 1 goto launcher_missing
py -3 -m forensickit serve "%FK_CASE%" --port "%FK_PORT%"
goto finished

:use_python
if not exist "%FK_PYTHON%" goto python_missing
"%FK_PYTHON%" -m forensickit serve "%FK_CASE%" --port "%FK_PORT%"
goto finished

:case_missing
echo ForensicKit case directory was not found: "%FK_CASE%"
endlocal & exit /b 2

:checkout_unavailable
echo Could not enter the ForensicKit checkout: "%FK_PROJECT_ROOT%"
endlocal & exit /b 3

:launcher_missing
echo The Windows Python launcher was not found. Set FK_PYTHON to a Python 3.11+ executable and retry.
popd
endlocal & exit /b 4

:python_missing
echo The Python executable in FK_PYTHON was not found: "%FK_PYTHON%"
popd
endlocal & exit /b 5

:finished
set "FK_EXIT_CODE=%ERRORLEVEL%"
popd
endlocal & exit /b %FK_EXIT_CODE%
