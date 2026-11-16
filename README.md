# TP N°3 -- DevOps : tests automatisés et intégration continue

Projet de départ du TP. Il contient un petit module d'authentification en
Python, des tests Pytest et un pipeline GitHub Actions.

## Arborescence

```text
tp3-devops-securite/
├── app/
│   ├── __init__.py
│   └── auth.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   └── test_auth.py
├── .github/workflows/security-tests.yml
├── .gitignore
├── requirements.txt
└── README.md
```

## Installation locale (facultative)

Python 3.10 ou supérieur.

```bash
python -m venv .venv
# Windows : .venv\Scripts\activate     Linux/macOS : source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Lancer les tests

```bash
pytest -v
```

## Publier le projet sur GitHub

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin URL_DU_DEPOT
git push -u origin main
```

Le workflow se déclenche à chaque `push` vers `main` ou `master`.
Consulter l'onglet **Actions** du dépôt pour examiner les résultats.

Suivre ensuite les consignes de la fiche de TP.
