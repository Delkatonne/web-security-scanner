"""
Scanner CSRF (Cross-Site Request Forgery)
"""

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style

class ScannerCSRF:
    def __init__(self, url_cible):
        self.url_cible = url_cible
        self.vulnerabilites = []
    
    def analyser_formulaires(self):
        """Analyse les formulaires pour détecter les protections CSRF"""
        print(f"\n{Fore.YELLOW}[*] Analyse CSRF sur: {self.url_cible}")
        print(f"{Fore.CYAN}[-] Recherche de formulaires...")
        
        try:
            # Récupérer le contenu de la page
            reponse = requests.get(self.url_cible, timeout=5)
            soup = BeautifulSoup(reponse.text, 'html.parser')
            
            # Trouver tous les formulaires
            formulaires = soup.find_all('form')
            
            if not formulaires:
                print(f"{Fore.YELLOW}[~] Aucun formulaire trouvé sur la page")
                return self.vulnerabilites
            
            print(f"{Fore.CYAN}[-] {len(formulaires)} formulaire(s) trouvé(s)")
            
            for i, formulaire in enumerate(formulaires, 1):
                print(f"\n{Fore.CYAN}[-] Analyse du formulaire {i}:")
                
                # Vérifier la méthode (GET ou POST)
                methode = formulaire.get('method', 'get').lower()
                action = formulaire.get('action', '')
                print(f"{Fore.CYAN}  Méthode: {methode.upper()}")
                print(f"{Fore.CYAN}  Action: {action}")
                
                # Chercher les tokens CSRF
                tokens_csrf = self._chercher_tokens_csrf(formulaire)
                
                if tokens_csrf:
                    print(f"{Fore.GREEN}[✓] Tokens CSRF trouvés: {', '.join(tokens_csrf)}")
                else:
                    print(f"{Fore.RED}[✗] Aucun token CSRF trouvé!")
                    
                    self.vulnerabilites.append({
                        'type': 'CSRF',
                        'formulaire': i,
                        'methode': methode,
                        'action': action,
                        'severite': 'MOYENNE',
                        'description': 'Formulaire sans protection CSRF'
                    })
            
            # Vérifier les cookies SameSite
            self._verifier_cookies_samesite(reponse)
            
            return self.vulnerabilites
            
        except Exception as e:
            print(f"{Fore.RED}[✗] Erreur lors de l'analyse CSRF: {e}")
            return self.vulnerabilites
    
    def _chercher_tokens_csrf(self, formulaire):
        """Cherche les tokens CSRF dans un formulaire"""
        tokens = []
        
        # Chercher les champs input avec des noms typiques de CSRF
        inputs = formulaire.find_all('input')
        
        for input_tag in inputs:
            nom = input_tag.get('name', '').lower()
            valeur = input_tag.get('value', '')
            
            # Noms courants pour les tokens CSRF
            noms_csrf = ['csrf', 'token', 'nonce', 'authenticity', '_token', 'csrf_token']
            
            for nom_csrf in noms_csrf:
                if nom_csrf in nom and len(valeur) > 10:  # Un vrai token fait plus de 10 caractères
                    tokens.append(nom)
                    break
        
        return tokens
    
    def _verifier_cookies_samesite(self, reponse):
        """Vérifie les attributs SameSite des cookies"""
        print(f"\n{Fore.CYAN}[-] Vérification des cookies...")
        
        cookies = reponse.cookies
        
        if not cookies:
            print(f"{Fore.YELLOW}[~] Aucun cookie trouvé")
            return
        
        print(f"{Fore.CYAN}  Nombre de cookies: {len(cookies)}")
        
        for cookie in cookies:
            nom = cookie.name
            print(f"\n{Fore.CYAN}  Cookie: {nom}")
            
            # Vérifier l'attribut SameSite
            if hasattr(cookie, 'same_site'):
                samesite = cookie.same_site
                if samesite in ['Strict', 'Lax']:
                    print(f"{Fore.GREEN}    SameSite: {samesite} (sécurisé)")
                elif samesite == 'None':
                    print(f"{Fore.YELLOW}    SameSite: {samesite} (nécessite Secure=True)")
                else:
                    print(f"{Fore.RED}    SameSite: {samesite or 'Non défini'} (non sécurisé)")
            else:
                print(f"{Fore.RED}    SameSite: Non défini (vulnérable)")
                
                self.vulnerabilites.append({
                    'type': 'Cookie SameSite manquant',
                    'cookie': nom,
                    'severite': 'MOYENNE',
                    'description': f'Cookie "{nom}" sans attribut SameSite'
                })
            
            # Vérifier l'attribut Secure
            if cookie.secure:
                print(f"{Fore.GREEN}    Secure: Oui")
            else:
                print(f"{Fore.YELLOW}    Secure: Non")
                if 'session' in nom.lower() or 'auth' in nom.lower():
                    print(f"{Fore.RED}    ⚠️  Cookie de session sans Secure!")
    
    def generer_rapport(self):
        """Génère un rapport des vulnérabilités CSRF trouvées"""
        if not self.vulnerabilites:
            return f"{Fore.GREEN}[✓] Aucune vulnérabilité CSRF majeure détectée\n"
        
        rapport = f"\n{Fore.RED}{'='*60}"
        rapport += f"\n{Fore.RED}   RAPPORT CSRF - {len(self.vulnerabilites)} VULNÉRABILITÉ(S)"
        rapport += f"\n{Fore.RED}{'='*60}\n"
        
        for i, vuln in enumerate(self.vulnerabilites, 1):
            rapport += f"\n{Fore.YELLOW}[VULN {i}] {vuln['type']}\n"
            rapport += f"{Fore.CYAN}  Sévérité: {vuln['severite']}\n"
            
            if 'formulaire' in vuln:
                rapport += f"{Fore.CYAN}  Formulaire: {vuln['formulaire']}\n"
                rapport += f"{Fore.CYAN}  Méthode: {vuln['methode'].upper()}\n"
                rapport += f"{Fore.CYAN}  Action: {vuln['action']}\n"
            
            if 'cookie' in vuln:
                rapport += f"{Fore.CYAN}  Cookie: {vuln['cookie']}\n"
            
            rapport += f"{Fore.CYAN}  Description: {vuln['description']}\n"
        
        rapport += f"\n{Fore.YELLOW}[!] Recommandations:"
        rapport += f"\n{Fore.CYAN}  1. Ajouter des tokens CSRF à tous les formulaires"
        rapport += f"\n{Fore.CYAN}  2. Utiliser l'attribut SameSite sur les cookies"
        rapport += f"\n{Fore.CYAN}  3. Vérifier l'origine des requêtes (Origin/Referer headers)"
        rapport += f"\n{Fore.CYAN}  4. Implémenter le double submit cookie pattern"
        
        return rapport

# Fonction de test
def tester_scanner_csrf():
    """Teste le scanner CSRF"""
    from colorama import init
    init(autoreset=True)
    
    print(f"\n{Fore.CYAN}[*] Test du scanner CSRF")
    
    # URL de test
    url_test = "https://httpbin.org/forms/post"
    
    scanner = ScannerCSRF(url_test)
    vulnerabilites = scanner.analyser_formulaires()
    
    print(scanner.generer_rapport())

if __name__ == "__main__":
    tester_scanner_csrf()