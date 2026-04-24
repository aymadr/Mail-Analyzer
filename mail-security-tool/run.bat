@echo off
REM Mail Security Analyzer - Démarrage Windows
REM Double-cliquer sur ce fichier pour lancer l'application

title Mail Security Analyzer - Startup

echo.
echo ========================================
echo  Mail Security Analyzer - Demarrage
echo ========================================
echo.

REM Vérifier si Python est installé
python --version >nul 2>&1
if errorlevel 1 (
    echo ERREUR: Python n'est pas installe ou n'est pas dans PATH
    echo.
    echo Installez Python 3.8+ depuis: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Créer l'environnement virtuel s'il n'existe pas
if not exist "venv" (
    echo Création de l'environnement virtuel...
    python -m venv venv
    if errorlevel 1 (
        echo ERREUR: Impossible de créer venv
        pause
        exit /b 1
    )
)

REM Activer l'environnement virtuel
call venv\Scripts\activate.bat

REM Installer les dépendances
echo Verification des dependances...
pip install -q -r requirements.txt
if errorlevel 1 (
    echo ERREUR: Impossible d'installer les dépendances
    pause
    exit /b 1
)

echo.
echo ========================================
echo  Configuration
echo ========================================
echo.
echo IMPORTANT: Avant de continuer, assurez-vous que:
echo 1. Les cles API sont configurees dans '.env'
echo 2. Les fichiers .env n'est pas vide
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

cd frontend
python app.py

pause
