"""
AUDIT DE SÉCURITÉ WEB - Scanner de Sécurité Complet
Auteur : Aaron Delkatonne
Version : 1.6
"""

import requests
import sys
from colorama import init, Fore, Style
from src.scanners.xss_scanner import ScannerXSS
from src.scanners.sql_scanner import ScannerSQL
from src.scanners.csrf_scanner import ScannerCSRF
from src.utils.logger import logger

# Initialiser colorama pour Windows
init(autoreset=True)

def afficher_banniere():
    """Affiche une bannière stylée"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.GREEN}   AUDIT DE SÉCURITÉ WEB - SCANNER COMPLET")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

def verifier_site(url):
    """Vérifie si un site web est accessible"""
    print(f"\n{Fore.YELLOW}[*] Test de connexion à {url}")
    
    try:
        # Essayer d'accéder au site
        reponse = requests.get(url, timeout=5)
        
        if reponse.status_code == 200:
            print(f"{Fore.GREEN}[✓] Site accessible (HTTP {reponse.status_code})")
            return True
        else:
            print(f"{Fore.YELLOW}[!] Site répond avec HTTP {reponse.status_code}")
            return True  # Le site répond quand même
            
    except requests.ConnectionError:
        print(f"{Fore.RED}[✗] Impossible de se connecter au site")
        return False
    except requests.Timeout:
        print(f"{Fore.RED}[✗] Timeout - Le site ne répond pas")
        return False
    except Exception as e:
        print(f"{Fore.RED}[✗] Erreur inattendue: {e}")
        return False

def analyser_entetes(url):
    """Analyse les en-têtes HTTP de sécurité"""
    print(f"\n{Fore.YELLOW}[*] Analyse des en-têtes de sécurité...")
    
    try:
        reponse = requests.get(url, timeout=5)
        entetes = reponse.headers
        
        print(f"{Fore.CYAN}[-] Serveur: {entetes.get('Server', 'Non spécifié')}")
        print(f"{Fore.CYAN}[-] Powered-By: {entetes.get('X-Powered-By', 'Non spécifié')}")
        
        # En-têtes de sécurité importants
        entetes_securite = [
            ('X-Content-Type-Options', 'nosniff', 'Empêche le MIME-sniffing'),
            ('X-Frame-Options', 'DENY', 'Protège contre le clickjacking'),
            ('X-XSS-Protection', '1; mode=block', 'Protection XSS'),
            ('Strict-Transport-Security', 'max-age', 'Force HTTPS'),
        ]
        
        problemes = []
        
        for entete, valeur_attendue, description in entetes_securite:
            if entete in entetes:
                valeur_actuelle = entetes[entete]
                
                if valeur_attendue in valeur_actuelle:
                    print(f"{Fore.GREEN}[✓] {entete}: {valeur_actuelle}")
                else:
                    print(f"{Fore.YELLOW}[!] {entete}: {valeur_actuelle} (attendu: {valeur_attendue})")
                    problemes.append(f"{entete} incorrect")
            else:
                print(f"{Fore.RED}[✗] {entete} manquant - {description}")
                problemes.append(f"{entete} manquant")
        
        return problemes
        
    except Exception as e:
        print(f"{Fore.RED}[✗] Erreur lors de l'analyse: {e}")
        return []

def analyser_infos_site(url):
    """Affiche des informations générales sur le site"""
    print(f"\n{Fore.YELLOW}[*] Informations générales du site...")
    
    try:
        reponse = requests.get(url, timeout=5)
        
        print(f"{Fore.CYAN}[-] Type de contenu: {reponse.headers.get('Content-Type', 'Inconnu')}")
        print(f"{Fore.CYAN}[-] Taille de la réponse: {len(reponse.text)} caractères")
        
        # Vérifier si c'est un site WordPress
        if 'wp-content' in reponse.text or 'wordpress' in reponse.text.lower():
            print(f"{Fore.YELLOW}[!] Ce site semble utiliser WordPress")
        
        # Vérifier les formulaires (simplifié)
        if '<form' in reponse.text.lower():
            nombre_formulaires = reponse.text.lower().count('<form')
            print(f"{Fore.CYAN}[-] Formulaires détectés: {nombre_formulaires}")
        
    except Exception as e:
        print(f"{Fore.RED}[✗] Erreur: {e}")

def scanner_xss(url):
    """Exécute un scan XSS sur l'URL"""
    print(f"\n{Fore.MAGENTA}{'='*60}")
    print(f"{Fore.MAGENTA}   SCAN XSS (CROSS-SITE SCRIPTING)")
    print(f"{Fore.MAGENTA}{'='*60}")
    
    scanner = ScannerXSS(url)
    vulnerabilites = scanner.tester_xss_reflechi()
    
    print(scanner.generer_rapport())
    
    return len(vulnerabilites)

def scanner_sql(url):
    """Exécute un scan SQL Injection sur l'URL"""
    print(f"\n{Fore.MAGENTA}{'='*60}")
    print(f"{Fore.MAGENTA}   SCAN SQL INJECTION")
    print(f"{Fore.MAGENTA}{'='*60}")
    
    scanner = ScannerSQL(url)
    vulnerabilites = scanner.executer_scan_complet()
    
    print(scanner.generer_rapport())
    
    return len(vulnerabilites)

def scanner_csrf(url):
    """Exécute un scan CSRF sur l'URL"""
    print(f"\n{Fore.MAGENTA}{'='*60}")
    print(f"{Fore.MAGENTA}   SCAN CSRF (CROSS-SITE REQUEST FORGERY)")
    print(f"{Fore.MAGENTA}{'='*60}")
    
    scanner = ScannerCSRF(url)
    vulnerabilites = scanner.analyser_formulaires()
    
    print(scanner.generer_rapport())
    
    return len(vulnerabilites)

def calculer_score_securite(total_problemes, total_vulnerabilites):
    """Calcule un score de sécurité simple"""
    score_base = 100
    
    # Pénalités
    penalite_entetes = total_problemes * 5  # 5 points par problème d'en-tête
    penalite_vulns = total_vulnerabilites * 15  # 15 points par vulnérabilité
    
    score_final = score_base - penalite_entetes - penalite_vulns
    
    # Assurer que le score reste entre 0 et 100
    score_final = max(0, min(100, score_final))
    
    return score_final

def obtenir_niveau_securite(score):
    """Détermine le niveau de sécurité basé sur le score"""
    if score >= 90:
        return f"{Fore.GREEN}EXCELLENT", "🛡️"
    elif score >= 70:
        return f"{Fore.GREEN}BON", "✅"
    elif score >= 50:
        return f"{Fore.YELLOW}MOYEN", "⚠️"
    elif score >= 30:
        return f"{Fore.YELLOW}FAIBLE", "🔶"
    else:
        return f"{Fore.RED}CRITIQUE", "🚨"

def main():
    """Fonction principale"""
    # Vérifier les arguments spéciaux d'abord (sans bannière)
    if '--help' in sys.argv or '-h' in sys.argv:
        print(f"\n{Fore.CYAN}UTILISATION :")
        print(f"{Fore.YELLOW}  python main.py [URL] [OPTIONS]")
        print(f"\n{Fore.CYAN}OPTIONS :")
        print(f"{Fore.GREEN}  --xss          Exécuter un scan XSS (Cross-Site Scripting)")
        print(f"{Fore.GREEN}  --sql          Exécuter un scan SQL Injection")
        print(f"{Fore.GREEN}  --csrf         Exécuter un scan CSRF")
        print(f"{Fore.GREEN}  --all          Exécuter tous les scans")
        print(f"{Fore.GREEN}  --history      Afficher l'historique des scans")
        print(f"{Fore.GREEN}  --stats        Afficher les statistiques des scans")
        print(f"{Fore.GREEN}  --help, -h     Afficher cette aide")
        print(f"\n{Fore.CYAN}EXEMPLES :")
        print(f"{Fore.YELLOW}  python main.py https://example.com")
        print(f"{Fore.YELLOW}  python main.py https://example.com --xss")
        print(f"{Fore.YELLOW}  python main.py https://example.com --sql --csrf")
        print(f"{Fore.YELLOW}  python main.py https://example.com --all")
        print(f"{Fore.YELLOW}  python main.py --history")
        print(f"{Fore.YELLOW}  python main.py --stats")
        print(f"\n{Fore.CYAN}REMARQUE :")
        print(f"{Fore.YELLOW}  Si aucune URL n'est fournie, le programme demandera une URL")
        return  # Quitter après avoir affiché l'aide
    
    # Si l'utilisateur demande l'historique
    if '--history' in sys.argv:
        # Afficher l'historique SANS bannière
        logger.print_history()
        return  # Quitter après avoir affiché l'historique
    
    # Si l'utilisateur demande les statistiques
    if '--stats' in sys.argv:
        # Afficher les statistiques SANS bannière
        logger.print_statistics()
        return  # Quitter après avoir affiché les statistiques
    
    # Si on arrive ici, c'est un scan normal → afficher la bannière
    afficher_banniere()
    
    # Vérifier les arguments de scan
    faire_scan_xss = False
    faire_scan_sql = False
    faire_scan_csrf = False
    
    # Gérer --all
    if '--all' in sys.argv:
        faire_scan_xss = True
        faire_scan_sql = True
        faire_scan_csrf = True
        sys.argv.remove('--all')
    
    if len(sys.argv) > 1:
        # Vérifier si l'utilisateur veut un scan XSS
        if '--xss' in sys.argv:
            faire_scan_xss = True
            sys.argv.remove('--xss')
        
        # Vérifier si l'utilisateur veut un scan SQL
        if '--sql' in sys.argv:
            faire_scan_sql = True
            sys.argv.remove('--sql')
        
        # Vérifier si l'utilisateur veut un scan CSRF
        if '--csrf' in sys.argv:
            faire_scan_csrf = True
            sys.argv.remove('--csrf')
        
        # L'URL est le premier argument restant
        if len(sys.argv) > 1:
            url_test = sys.argv[1]
        else:
            url_test = input(f"\n{Fore.CYAN}[?] Entrez l'URL à analyser (ex: https://example.com): ")
    else:
        url_test = input(f"\n{Fore.CYAN}[?] Entrez l'URL à analyser (ex: https://example.com): ")
    
    # Ajouter https:// si non présent
    if not url_test.startswith(('http://', 'https://')):
        url_test = 'https://' + url_test
    
    print(f"\n{Fore.MAGENTA}[+] Démarrage de l'analyse sur: {url_test}")
    print(f"{Fore.MAGENTA}[+] Date: 2025-01-25")
    print(f"{Fore.MAGENTA}[+] Scanner: Version 1.6")
    
    # Déterminer le mode
    scans = []
    if faire_scan_xss:
        scans.append("XSS")
    if faire_scan_sql:
        scans.append("SQL")
    if faire_scan_csrf:
        scans.append("CSRF")
    
    if scans:
        mode = f"Scan {', '.join(scans)} (en-têtes + {' + '.join(scans)})"
    else:
        mode = "Analyse de base (en-têtes seulement)"
    
    print(f"{Fore.MAGENTA}[+] Mode: {mode}")
    
    # Afficher astuce seulement si aucun scan n'est activé
    if not scans:
        print(f"\n{Fore.CYAN}[*] Astuce: Utilisez --xss, --sql, --csrf ou --all pour des scans complets")
        print(f"{Fore.CYAN}[*] Exemple: python main.py https://example.com --all")
    
    # Étape 1: Vérifier l'accessibilité
    if not verifier_site(url_test):
        print(f"\n{Fore.RED}[!] Analyse stoppée - site inaccessible")
        return
    
    total_vulnerabilites = 0
    
    # Étape 2: Informations générales (toujours fait)
    analyser_infos_site(url_test)
    
    # Étape 3: Analyser les en-têtes (toujours fait)
    problemes = analyser_entetes(url_test)
    total_vulnerabilites += len(problemes)
    
    # Étape 4: Scan XSS si demandé
    xss_count = 0
    if faire_scan_xss:
        xss_count = scanner_xss(url_test)
        total_vulnerabilites += xss_count
    
    # Étape 5: Scan SQL si demandé
    sql_count = 0
    if faire_scan_sql:
        sql_count = scanner_sql(url_test)
        total_vulnerabilites += sql_count
    
    # Étape 6: Scan CSRF si demandé
    csrf_count = 0
    if faire_scan_csrf:
        csrf_count = scanner_csrf(url_test)
        total_vulnerabilites += csrf_count
    
    # Calculer le score de sécurité
    vulns_sans_entetes = total_vulnerabilites - len(problemes)
    score = calculer_score_securite(len(problemes), vulns_sans_entetes)
    niveau, emoji = obtenir_niveau_securite(score)
    
    # Préparer les données pour le logging
    scan_type = "base"
    if scans:
        scan_type = "+".join(scans).lower()
    
    # Compiler les vulnérabilités pour le logging
    all_vulnerabilities = []
    
    # Ajouter les problèmes d'en-têtes comme vulnérabilités
    for probleme in problemes:
        all_vulnerabilities.append({
            'type': 'En-tête manquant',
            'severity': 'MOYENNE',
            'description': probleme,
            'recommendation': 'Configurer les en-têtes de sécurité appropriés'
        })
    
    # Ajouter les résultats pour le logging
    results_data = {
        'header_issues': len(problemes),
        'xss_vulnerabilities': xss_count,
        'sql_vulnerabilities': sql_count,
        'csrf_vulnerabilities': csrf_count,
        'total_vulnerabilities': total_vulnerabilites,
        'score': score,
        'level': niveau.replace(Fore.GREEN, '').replace(Fore.YELLOW, '').replace(Fore.RED, '').strip()
    }
    
    # Logger les résultats
    logger.log_scan(url_test, scan_type, results_data, all_vulnerabilities)

    # Résumé final amélioré
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.GREEN}   ANALYSE TERMINÉE")
    print(f"{Fore.CYAN}{'='*60}")
    
    print(f"\n{Fore.YELLOW}[*] RÉSUMÉ POUR {url_test}:")
    print(f"{Fore.CYAN}{'-'*40}")
    print(f"{Fore.CYAN}  Problèmes d'en-têtes: {len(problemes)}")
    
    if faire_scan_xss:
        print(f"{Fore.CYAN}  Vulnérabilités XSS: {xss_count}")
    
    if faire_scan_sql:
        print(f"{Fore.CYAN}  Vulnérabilités SQL: {sql_count}")
    
    if faire_scan_csrf:
        print(f"{Fore.CYAN}  Vulnérabilités CSRF: {csrf_count}")
    
    print(f"{Fore.CYAN}{'-'*40}")
    print(f"{Fore.CYAN}  Total des vulnérabilités: {total_vulnerabilites}")
    print(f"{Fore.CYAN}  Score de sécurité: {score}/100 {emoji}")
    print(f"{Fore.CYAN}  Niveau: {niveau}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*40}")
    
    if total_vulnerabilites == 0:
        print(f"\n{Fore.GREEN}[✓] Aucune vulnérabilité détectée! Site sécurisé.")
    else:
        print(f"\n{Fore.YELLOW}[!] {total_vulnerabilites} vulnérabilité(s) nécessite(nt) votre attention")
    
    # Recommandations générales
    if len(problemes) > 0:
        print(f"\n{Fore.YELLOW}[*] RECOMMANDATIONS :")
        print(f"{Fore.CYAN}  1. Configurer les en-têtes de sécurité manquants")
        print(f"{Fore.CYAN}  2. Mettre à jour la configuration du serveur")
        if faire_scan_csrf and csrf_count > 0:
            print(f"{Fore.CYAN}  3. Ajouter des tokens CSRF aux formulaires")
    
    print(f"\n{Fore.CYAN}[*] Analyse terminée avec succès!")

# Point d'entrée du programme
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Analyse interrompue par l'utilisateur")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Erreur critique: {e}")