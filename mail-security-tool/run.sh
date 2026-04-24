#!/bin/bash
# Mail Security Analyzer - Démarrage Linux/Mac

echo ""
echo "========================================"
echo "  Mail Security Analyzer - Démarrage"
echo "========================================"
echo ""

# Vérifier si Python est installé
if ! command -v python3 &> /dev/null; then
    echo "ERREUR: Python 3 n'est pas installé"
    exit 1
fi

# Créer l'environnement virtuel s'il n'existe pas
if [ ! -d "venv" ]; then
    echo "Création de l'environnement virtuel..."
    python3 -m venv venv
fi

# Activer l'environnement virtuel
source venv/bin/activate

# Installer les dépendances
echo "Vérification des dépendances..."
pip install -q -r requirements.txt

echo ""
echo "========================================"
echo "  Configuration"
echo "========================================"
echo ""
echo "IMPORTANT: Avant de continuer, assurez-vous que:"
echo "1. Les clés API sont configurées dans '.env'"
echo "2. Le fichier '.env' n'est pas vide"
echo ""

# Lancer Flask
echo "Démarrage du serveur Flask..."
echo ""
echo "=== SERVEUR EN COURS D'EXÉCUTION ==="
echo ""
echo "URL: http://127.0.0.1:5000"
echo ""
echo "Appuyez sur Ctrl+C pour arrêter"
echo ""

cd frontend
python app.py
