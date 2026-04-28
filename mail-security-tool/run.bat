@echo off
REM Mail Security Analyzer - Démarrage Windows
REM Double-cliquer sur ce fichier pour lancer l'application

title Mail Security Analyzer - Startup

echo.
echo ========================================
echo  Mail Security Analyzer - Demarrage
echo ========================================
echo.

REM Définir les chemins
set "VENV_PYTHON=venv\Scripts\python.exe"
set "VENV_PIP=venv\Scripts\pip.exe"

REM Vérifier si venv existe, sinon le créer
if not exist "venv" (
    echo Verification de Python...
    python --version >nul 2>&1
    if errorlevel 1 (
        echo ERREUR: Python n'est pas installe ou n'est pas dans PATH
        echo.
        echo Installez Python 3.8+ depuis: https://www.python.org/downloads/
        pause
        exit /b 1
    )
    
    echo Création de l'environnement virtuel...
    python -m venv venv
    if errorlevel 1 (
        echo ERREUR: Impossible de créer venv
        pause
        exit /b 1
    )
)

REM Installer les dépendances
echo Verification des dependances...
"%VENV_PIP%" install -q -r requirements.txt 2>nul
if errorlevel 1 (
    echo ATTENTION: Impossible d'installer via pip, essai normal...
    "%VENV_PIP%" install -r requirements.txt
)

echo.
echo ========================================
echo  Configuration
echo ========================================
echo.
echo IMPORTANT: Avant de continuer, assurez-vous que:
echo 1. Les cles API sont configurees dans '.env'
echo 2. Le fichier .env n'est pas vide
echo.

REM Lancer Flask
echo Demarrage du serveur Flask...
echo.
echo === SERVEUR EN COURS D'EXECUTION ===
echo.
echo URL: http://127.0.0.1:5000
echo.
echo Appuyez sur Ctrl+C pour arreter
echo.

"%VENV_PYTHON%" run.py

pause
