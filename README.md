# 🛡️ Web Security Scanner

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Scanner de sécurité web pour détecter des vulnérabilités courantes (OWASP Top 10) : en-têtes de sécurité, XSS, injections SQL, CSRF.

## ✨ Fonctionnalités

| Scanner | Description | Payloads |
|---------|-------------|----------|
| 🔍 En-têtes HTTP | Sécurité des en-têtes | 4 tests |
| 🛡️ XSS | Cross-Site Scripting | 18 payloads |
| 💉 SQL Injection | Injection SQL | 3 méthodes |
| 🎭 CSRF | Cross-Site Request Forgery | Formulaire + cookies |

## 🚀 Installation locale

```bash
git clone https://github.com/Delkatonne/web-security-scanner.git
cd web-security-scanner
pip install -r requirements.txt
```

## Utilisation en ligne de commande

```bash
python main.py https://example.com --all
python main.py https://example.com --xss
python main.py --history
python main.py --stats
```

## Interface web

```bash
python app.py
```

Puis ouvrir `http://localhost:5000` dans un navigateur.

## Déploiement

Le projet est prêt pour Render (`Procfile` inclus, `gunicorn app:app`).