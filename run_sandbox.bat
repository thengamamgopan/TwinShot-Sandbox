@echo off
title Sand Box Dashboard
cd /d C:\SandboxTools
py sandbox_dashboard.py
if errorlevel 1 pause
