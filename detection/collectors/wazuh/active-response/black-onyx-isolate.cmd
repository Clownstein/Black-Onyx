@echo off
rem Wazuh active response (Windows) wrapper. Install with black-onyx-isolate.ps1 in
rem "C:\Program Files (x86)\ossec-agent\active-response\bin\". Wazuh passes the
rem active-response JSON on stdin; PowerShell inherits it.
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0black-onyx-isolate.ps1" %*
exit /b %ERRORLEVEL%
