"""
Script de démarrage rapide - Lance automatiquement l'application
"""
import os
import sys
import subprocess
from pathlib import Path

def main():
    print("🔒 Mail Security Analyzer - Démarrage")
    print("=" * 50)
    
    # Déterminer le chemin du projet
    project_root = Path(__file__).parent
    frontend_dir = project_root / "frontend"
    backend_dir = project_root / "backend"
    
    # Vérifier l'environnement virtuel
    venv_path = project_root / "venv"
    if not venv_path.exists():
        print("\n⚠️  Environnement virtuel non trouvé!")
        print("\nCréation de l'environnement virtuel...")
        subprocess.run([sys.executable, "-m", "venv", str(venv_path)], check=True)
        
        # Installer les dépendances
        print("\n📦 Installation des dépendances...")
        pip_path = venv_path / "Scripts" / "pip" if sys.platform == "win32" else venv_path / "bin" / "pip"
        subprocess.run([str(pip_path), "install", "-r", str(project_root / "requirements.txt")], check=True)
    
    print("\n✅ Environnement prêt!")
    print("\n📂 Structure du projet:")
    print(f"  Backend: {backend_dir}")
    print(f"  Frontend: {frontend_dir}")
    print(f"  Données: {project_root / 'data'}")
    
    print("\n🌐 Lancement du serveur Flask...")
    print("   URL: http://127.0.0.1:5000")
    print("\n💡 Appuie sur Ctrl+C pour arrêter\n")
    
    # Ajouter backend au PYTHONPATH
    os.environ['PYTHONPATH'] = str(backend_dir)
    
    # Lancer Flask
    os.chdir(str(frontend_dir))
    subprocess.run([sys.executable, "app.py"])

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Arrêt de l'application")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
        sys.exit(1)
