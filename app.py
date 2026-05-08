from flask import Flask, request, jsonify, send_file
import subprocess
import os
import tempfile
import os

app = Flask(__name__)

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

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get('url')
    scan_type = data.get('type', 'all')
    
    # Utiliser l'exécutable qu'on a créé
    exe_path = os.path.join(os.path.dirname(__file__), 'dist', 'websec.exe')
    
    if scan_type == 'all':
        cmd = [exe_path, url, '--all']
    else:
        cmd = [exe_path, url, f'--{scan_type}']
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return jsonify({'output': result.stdout})
    except subprocess.TimeoutExpired:
        return jsonify({'output': '⏰ Timeout - L\'analyse a pris trop de temps'})
    except Exception as e:
        return jsonify({'output': f'❌ Erreur: {str(e)}'})

    if __name__ == '__main__':
        port = int(os.environ.get('PORT', 5000))
        app.run(host='0.0.0.0', port=port)