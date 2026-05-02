"""
Scanner SQL Injection simple
"""

import requests
import time
from colorama import Fore, Style

class ScannerSQL:
    def __init__(self, url_cible):
        self.url_cible = url_cible
        self.vulnerabilites = []
        
        # Payloads SQL Injection
        self.payloads_boolean = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "admin' --",
            "' OR 'a'='a",
        ]
        
        self.payloads_erreur = [
            "'",
            "\"",
            "';",
            "\";",
            "' OR SLEEP(5) --",
            "' AND 1=CONVERT(int, @@version) --",
        ]
        
        self.payloads_time = [
            "' OR SLEEP(5) --",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a) --",
            "'; WAITFOR DELAY '00:00:05' --",
        ]
    
    def scanner_sql_boolean(self):
        """Teste les injections SQL basées sur les booléens"""
        print(f"\n{Fore.YELLOW}[*] Test SQL Injection (Boolean-based)")
        
        # On suppose que le site a un paramètre 'id'
        # Dans une vraie application, il faudrait détecter les paramètres
        parametres_tests = ['id', 'user', 'product', 'page', 'category']
        
        for param in parametres_tests:
            url_base = f"{self.url_cible}?{param}=1"
            
            # Requête normale
            try:
                reponse_normale = requests.get(url_base, timeout=5)
                contenu_normale = reponse_normale.text
                
                for payload in self.payloads_boolean:
                    url_test = f"{self.url_cible}?{param}=1{payload}"
                    
                    try:
                        reponse_test = requests.get(url_test, timeout=5)
                        
                        # Si la réponse est différente, possible injection
                        if reponse_test.text != contenu_normale:
                            # Vérifier les indicateurs d'injection
                            if self._detecter_indices_sql(reponse_test.text):
                                print(f"{Fore.RED}[!] Possible SQL Injection sur paramètre: {param}")
                                print(f"{Fore.RED}    Payload: {payload}")
                                
                                self.vulnerabilites.append({
                                    'type': 'SQL Injection (Boolean-based)',
                                    'parametre': param,
                                    'payload': payload,
                                    'url': url_test,
                                    'severite': 'CRITIQUE',
                                    'description': 'La réponse change avec des payloads booléens'
                                })
                                
                    except:
                        continue
                        
            except:
                continue
        
        return self.vulnerabilites
    
    def scanner_sql_erreur(self):
        """Teste les injections SQL basées sur les erreurs"""
        print(f"\n{Fore.YELLOW}[*] Test SQL Injection (Error-based)")
        
        messages_erreur_sql = [
            'SQL syntax',
            'mysql',
            'postgresql',
            'oracle',
            'sql server',
            'syntax error',
            'unclosed quotation',
            'undefined column',
            'unknown column'
        ]
        
        parametres_tests = ['id', 'search', 'query', 'filter']
        
        for param in parametres_tests:
            for payload in self.payloads_erreur:
                url_test = f"{self.url_cible}?{param}=1{payload}"
                
                try:
                    reponse = requests.get(url_test, timeout=5)
                    
                    # Chercher des messages d'erreur SQL dans la réponse
                    for erreur in messages_erreur_sql:
                        if erreur in reponse.text.lower():
                            print(f"{Fore.RED}[!] SQL Injection (Error-based) détectée!")
                            print(f"{Fore.RED}    Paramètre: {param}, Payload: {payload}")
                            print(f"{Fore.RED}    Message: {erreur}")
                            
                            self.vulnerabilites.append({
                                'type': 'SQL Injection (Error-based)',
                                'parametre': param,
                                'payload': payload,
                                'url': url_test,
                                'severite': 'CRITIQUE',
                                'description': f'Message d\'erreur SQL détecté: {erreur}'
                            })
                            break
                            
                except:
                    continue
        
        return self.vulnerabilites
    
    def scanner_sql_time(self):
        """Teste les injections SQL basées sur le temps"""
        print(f"\n{Fore.YELLOW}[*] Test SQL Injection (Time-based)")
        print(f"{Fore.CYAN}[-] Ce test peut prendre 15-20 secondes...")
        
        seuil_delai = 4  # secondes
        
        for payload in self.payloads_time:
            url_test = f"{self.url_cible}?id=1{payload}"
            
            try:
                debut = time.time()
                reponse = requests.get(url_test, timeout=10)
                duree = time.time() - debut
                
                if duree > seuil_delai:
                    print(f"{Fore.RED}[!] Possible SQL Injection (Time-based)!")
                    print(f"{Fore.RED}    Délai: {duree:.2f} secondes avec payload: {payload}")
                    
                    self.vulnerabilites.append({
                        'type': 'SQL Injection (Time-based)',
                        'payload': payload,
                        'url': url_test,
                        'duree': f'{duree:.2f}s',
                        'seuil': f'{seuil_delai}s',
                        'severite': 'CRITIQUE',
                        'description': f'Réponse retardée de {duree:.2f} secondes'
                    })
                else:
                    print(f"{Fore.GREEN}[✓] Pas de délai anormal: {duree:.2f}s")
                    
            except requests.Timeout:
                print(f"{Fore.YELLOW}[~] Timeout avec payload: {payload}")
            except:
                continue
        
        return self.vulnerabilites
    
    def _detecter_indices_sql(self, texte):
        """Détecte des indices d'injection SQL dans un texte"""
        indices = [
            'sql',
            'syntax',
            'mysql',
            'database',
            'query failed',
            'unexpected',
            'warning',
            'error'
        ]
        
        texte_minuscule = texte.lower()
        
        for indice in indices:
            if indice in texte_minuscule:
                return True
        
        return False
    
    def executer_scan_complet(self):
        """Exécute tous les tests SQL Injection"""
        print(f"\n{Fore.MAGENTA}[*] Démarrage du scan SQL Injection")
        print(f"{Fore.MAGENTA}[*] Cible: {self.url_cible}")
        
        self.scanner_sql_boolean()
        self.scanner_sql_erreur()
        self.scanner_sql_time()
        
        return self.vulnerabilites
    
    def generer_rapport(self):
        """Génère un rapport des vulnérabilités SQL trouvées"""
        if not self.vulnerabilites:
            return f"{Fore.GREEN}[✓] Aucune vulnérabilité SQL Injection détectée\n"
        
        rapport = f"\n{Fore.RED}{'='*60}"
        rapport += f"\n{Fore.RED}   RAPPORT SQL INJECTION - {len(self.vulnerabilites)} VULNÉRABILITÉ(S)"
        rapport += f"\n{Fore.RED}{'='*60}\n"
        
        for i, vuln in enumerate(self.vulnerabilites, 1):
            rapport += f"\n{Fore.YELLOW}[VULN {i}] {vuln['type']}\n"
            rapport += f"{Fore.CYAN}  Sévérité: {vuln['severite']}\n"
            rapport += f"{Fore.CYAN}  URL: {vuln['url'][:80]}...\n"
            
            if 'parametre' in vuln:
                rapport += f"{Fore.CYAN}  Paramètre: {vuln['parametre']}\n"
            
            rapport += f"{Fore.CYAN}  Payload: {vuln['payload'][:50]}...\n"
            rapport += f"{Fore.CYAN}  Description: {vuln['description']}\n"
        
        rapport += f"\n{Fore.YELLOW}[!] Recommandations:"
        rapport += f"\n{Fore.CYAN}  1. Utiliser des requêtes paramétrées (Prepared Statements)"
        rapport += f"\n{Fore.CYAN}  2. Valider et filtrer toutes les entrées utilisateur"
        rapport += f"\n{Fore.CYAN}  3. Échapper les caractères spéciaux"
        rapport += f"\n{Fore.CYAN}  4. Utiliser un ORM (Object-Relational Mapping)"
        rapport += f"\n{Fore.CYAN}  5. Limiter les privilèges de la base de données"
        
        return rapport

# Fonction de test
def tester_scanner_sql():
    """Teste le scanner SQL"""
    from colorama import init
    init(autoreset=True)
    
    print(f"\n{Fore.CYAN}[*] Test du scanner SQL Injection")
    
    # URL de test (normalement non vulnérable)
    url_test = "https://httpbin.org/html"
    
    scanner = ScannerSQL(url_test)
    vulnerabilites = scanner.executer_scan_complet()
    
    print(scanner.generer_rapport())

if __name__ == "__main__":
    tester_scanner_sql()