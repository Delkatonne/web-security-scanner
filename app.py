import io
import re
import contextlib
import requests

from flask import Flask, request, jsonify

from src.scanners.xss_scanner import ScannerXSS
from src.scanners.sql_scanner import ScannerSQL
from src.scanners.csrf_scanner import ScannerCSRF

app = Flask(__name__)

# Sans User-Agent, de nombreux sites bloquent ou coupent silencieusement
# les requetes envoyees par python-requests (voir aussi les scanners).
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/124.0 Safari/537.36'
}

# En-tetes de securite HTTP verifies (nom, valeur attendue, description)
ENTETES_SECURITE = [
    ('X-Content-Type-Options', 'nosniff', 'Empeche le MIME-sniffing'),
    ('X-Frame-Options', 'DENY', 'Protege contre le clickjacking'),
    ('X-XSS-Protection', '1; mode=block', 'Protection XSS'),
    ('Strict-Transport-Security', 'max-age', 'Force HTTPS'),
]

# Retire les codes couleur ANSI (colorama) du texte capture, pour un affichage propre cote web
ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def _strip_ansi(texte):
    return ANSI_RE.sub('', texte)


HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Web Security Scanner</title>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }
        h1 {
            color: #667eea;
            text-align: center;
        }
        p {
            text-align: center;
            color: #666;
        }
        input, select {
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            margin-top: 10px;
        }
        button:hover {
            background: #5a67d8;
        }
        .result {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            overflow-x: auto;
            font-family: monospace;
            font-size: 12px;
            white-space: pre-wrap;
        }
        .loading {
            text-align: center;
            color: #667eea;
            margin: 20px;
        }
        .download {
            text-align: center;
            margin-top: 20px;
        }
        .download a {
            color: #667eea;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Web Security Scanner</h1>
        <p>Auditez la sécurité d'un site web gratuitement</p>

        <input type="text" id="url" placeholder="https://exemple.com">
        <select id="scan_type">
            <option value="all">🔍 Audit complet (Recommandé)</option>
            <option value="xss">🛡️ Scan XSS uniquement</option>
            <option value="sql">💉 Scan SQL uniquement</option>
            <option value="csrf">🎭 Scan CSRF uniquement</option>
        </select>
        <button onclick="startScan()">Lancer l'audit</button>

        <div id="result" class="result"></div>

        <div class="download">
            <p>📦 <a href="https://github.com/Delkatonne/web-security-scanner">Télécharger la version complète sur GitHub</a></p>
        </div>
    </div>

    <script>
        async function startScan() {
            const url = document.getElementById('url').value;
            const scanType = document.getElementById('scan_type').value;
            const resultDiv = document.getElementById('result');

            if (!url) {
                resultDiv.innerHTML = '❌ Veuillez entrer une URL';
                return;
            }

            resultDiv.innerHTML = '<div class="loading">⏳ Scan en cours... (20-40 secondes)</div>';

            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url, type: scanType})
                });
                const data = await response.json();
                resultDiv.innerHTML = '<pre>' + data.output + '</pre>';
            } catch(error) {
                resultDiv.innerHTML = '❌ Erreur: ' + error.message;
            }
        }
    </script>
</body>
</html>
'''


@app.route('/')
def index():
    return HTML


def _verifier_site(url):
    """Vérifie que le site répond avant de lancer les scanners.
    Retourne (accessible: bool, reponse ou None, message: str)."""
    try:
        reponse = requests.get(url, timeout=8, headers=HEADERS, allow_redirects=True)
        return True, reponse, f"✓ Site accessible (HTTP {reponse.status_code})"
    except requests.exceptions.SSLError:
        return False, None, "✗ Erreur de certificat SSL — le site utilise un certificat invalide ou expiré"
    except requests.exceptions.ConnectionError:
        return False, None, "✗ Impossible de se connecter au site (DNS introuvable, site hors ligne, ou connexion bloquée)"
    except requests.exceptions.Timeout:
        return False, None, "✗ Timeout — le site n'a pas répondu à temps"
    except requests.exceptions.RequestException as e:
        return False, None, f"✗ Erreur de requête: {e}"


def _analyser_entetes(reponse):
    """Analyse les en-têtes de sécurité HTTP. Retourne (lignes_texte, nb_problemes)."""
    lignes = []
    problemes = 0
    entetes = reponse.headers

    for entete, valeur_attendue, description in ENTETES_SECURITE:
        if entete in entetes:
            valeur_actuelle = entetes[entete]
            if valeur_attendue in valeur_actuelle:
                lignes.append(f"[✓] {entete}: {valeur_actuelle}")
            else:
                lignes.append(f"[!] {entete}: {valeur_actuelle} (attendu: {valeur_attendue})")
                problemes += 1
        else:
            lignes.append(f"[✗] {entete} manquant — {description}")
            problemes += 1

    return lignes, problemes


def _calculer_score(nb_problemes_entetes, nb_vulnerabilites):
    score = 100 - (nb_problemes_entetes * 5) - (nb_vulnerabilites * 15)
    return max(0, min(100, score))


def _niveau_securite(score):
    if score >= 90:
        return "EXCELLENT", "🛡️"
    elif score >= 70:
        return "BON", "✅"
    elif score >= 50:
        return "MOYEN", "⚠️"
    elif score >= 30:
        return "FAIBLE", "🔶"
    else:
        return "CRITIQUE", "🚨"


def _run_scan(url, scan_type):
    """Vérifie l'accessibilité du site, analyse les en-têtes, exécute les
    scanners sélectionnés en Python (pas de binaire externe), puis calcule
    un score de fiabilité global."""
    lignes = []

    # 1. Vérifier que le site est accessible avant de lancer quoi que ce soit
    accessible, reponse, message = _verifier_site(url)
    lignes.append(f"[*] Vérification de {url}")
    lignes.append(message)

    if not accessible:
        lignes.append("")
        lignes.append("[!] Analyse stoppée — le site n'est pas accessible depuis le serveur de scan.")
        return "\n".join(lignes)

    # 2. Analyser les en-têtes de sécurité (fiabilité de base)
    lignes.append("")
    lignes.append("[*] Analyse des en-têtes de sécurité...")
    entetes_lignes, nb_problemes_entetes = _analyser_entetes(reponse)
    lignes.extend(entetes_lignes)

    # 3. Lancer les scanners sélectionnés, en capturant leurs prints
    buffer = io.StringIO()
    nb_vulnerabilites = 0

    with contextlib.redirect_stdout(buffer):
        if scan_type in ('all', 'xss'):
            scanner = ScannerXSS(url)
            vulns = scanner.tester_xss_reflechi()
            nb_vulnerabilites += len(vulns)
            print(scanner.generer_rapport())

        if scan_type in ('all', 'sql'):
            scanner = ScannerSQL(url)
            vulns = scanner.executer_scan_complet()
            nb_vulnerabilites += len(vulns)
            print(scanner.generer_rapport())

        if scan_type in ('all', 'csrf'):
            scanner = ScannerCSRF(url)
            vulns = scanner.analyser_formulaires()
            nb_vulnerabilites += len(vulns)
            print(scanner.generer_rapport())

    lignes.append("")
    lignes.append(_strip_ansi(buffer.getvalue()).strip())

    # 4. Score de fiabilité global
    score = _calculer_score(nb_problemes_entetes, nb_vulnerabilites)
    niveau, emoji = _niveau_securite(score)

    lignes.append("")
    lignes.append("=" * 50)
    lignes.append("   FIABILITÉ GLOBALE DU SITE")
    lignes.append("=" * 50)
    lignes.append(f"Problèmes d'en-têtes : {nb_problemes_entetes}")
    lignes.append(f"Vulnérabilités détectées : {nb_vulnerabilites}")
    lignes.append(f"Score de sécurité : {score}/100 {emoji}")
    lignes.append(f"Niveau : {niveau}")
    lignes.append("=" * 50)

    return "\n".join(lignes)


@app.route('/scan', methods=['POST'])
def scan():
    data = request.json or {}
    url = data.get('url', '').strip()
    scan_type = data.get('type', 'all')

    if not url:
        return jsonify({'output': "❌ Veuillez fournir une URL"})

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        output = _run_scan(url, scan_type)
        if not output.strip():
            output = "✓ Scan terminé, aucun résultat à afficher."
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'output': f'❌ Erreur: {str(e)}'})


if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)