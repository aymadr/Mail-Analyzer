FROM python:3.10-slim

WORKDIR /app

# Installer les dépendances système
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copier les fichiers
COPY requirements.txt .
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY .env.example .env

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Créer les dossiers
RUN mkdir -p /app/uploads /app/data

# Port
EXPOSE 5000

# Commande de démarrage
CMD ["python", "frontend/app.py"]
