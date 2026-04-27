"""
Module de logging pour l'audit de sécurité
Sauvegarde les résultats dans des fichiers
"""

import json
import csv
from datetime import datetime
from colorama import Fore, Style
import os

class SecurityLogger:
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        self.setup_logging()
    
    def setup_logging(self):
        """Configure le système de logging"""
        # Créer le dossier logs s'il n'existe pas
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        
        # Créer le dossier reports pour les rapports détaillés
        reports_dir = os.path.join(self.log_dir, "reports")
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
    
    def log_scan(self, url, scan_type, results, vulnerabilities=None):
        """Log les résultats d'un scan"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Données à logger
        log_data = {
            'timestamp': timestamp,
            'date': date_str,
            'url': url,
            'scan_type': scan_type,
            'results': results,
            'vulnerabilities': vulnerabilities or []
        }
        
        # Sauvegarder en JSON
        json_file = os.path.join(self.log_dir, f"scan_{timestamp}.json")
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(log_data, f, indent=2, ensure_ascii=False)
        
        # Ajouter à l'historique CSV
        self._add_to_history(log_data)
        
        # Générer un rapport détaillé si il y a des vulnérabilités
        if vulnerabilities:
            self._generate_detailed_report(log_data)
        
        print(f"{Fore.CYAN}[*] Résultats sauvegardés dans: {json_file}")
        
        return json_file
    
    def _add_to_history(self, log_data):
        """Ajoute une entrée à l'historique CSV"""
        csv_file = os.path.join(self.log_dir, "history.csv")
        
        # Définir les en-têtes CSV
        headers = ['timestamp', 'date', 'url', 'scan_type', 
                  'total_vulnerabilities', 'score', 'level']
        
        # Préparer les données
        row_data = {
            'timestamp': log_data['timestamp'],
            'date': log_data['date'],
            'url': log_data['url'],
            'scan_type': log_data['scan_type'],
            'total_vulnerabilities': len(log_data.get('vulnerabilities', [])),
            'score': log_data.get('results', {}).get('score', 0),
            'level': log_data.get('results', {}).get('level', 'INCONNU')
        }
        
        # Écrire dans le CSV
        file_exists = os.path.isfile(csv_file)
        
        with open(csv_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            
            if not file_exists:
                writer.writeheader()
            
            writer.writerow(row_data)
    
    def _generate_detailed_report(self, log_data):
        """Génère un rapport détaillé des vulnérabilités"""
        timestamp = log_data['timestamp']
        report_file = os.path.join(self.log_dir, "reports", f"report_{timestamp}.txt")
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("   RAPPORT DÉTAILLÉ DE SÉCURITÉ\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"URL: {log_data['url']}\n")
            f.write(f"Date: {log_data['date']}\n")
            f.write(f"Type de scan: {log_data['scan_type']}\n")
            f.write(f"Score: {log_data['results'].get('score', 0)}/100\n")
            f.write(f"Niveau: {log_data['results'].get('level', 'INCONNU')}\n\n")
            
            if log_data['vulnerabilities']:
                f.write("VULNÉRABILITÉS DÉTECTÉES:\n")
                f.write("-" * 40 + "\n")
                
                for i, vuln in enumerate(log_data['vulnerabilities'], 1):
                    f.write(f"\n{i}. {vuln.get('type', 'Inconnu')}\n")
                    f.write(f"   Sévérité: {vuln.get('severity', 'Inconnue')}\n")
                    f.write(f"   Description: {vuln.get('description', 'Non spécifiée')}\n")
                    if 'recommendation' in vuln:
                        f.write(f"   Recommandation: {vuln['recommendation']}\n")
            
            f.write("\n" + "=" * 60 + "\n")
            f.write("   FIN DU RAPPORT\n")
            f.write("=" * 60 + "\n")
        
        return report_file
    
    def get_recent_scans(self, limit=10):
        """Récupère les scans récents"""
        csv_file = os.path.join(self.log_dir, "history.csv")
        
        if not os.path.exists(csv_file):
            return []
        
        scans = []
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                scans.append(row)
        
        # Retourner les plus récents en premier
        return list(reversed(scans))[:limit]
    
    def print_history(self):
        """Affiche l'historique des scans"""
        scans = self.get_recent_scans(10)
        
        if not scans:
            print(f"{Fore.YELLOW}[~] Aucun historique de scan trouvé")
            return
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}   HISTORIQUE DES SCANS (10 derniers)")
        print(f"{Fore.CYAN}{'='*60}")
        
        for i, scan in enumerate(scans, 1):
            print(f"\n{Fore.YELLOW}[SCAN {i}]")
            print(f"{Fore.CYAN}  Date: {scan.get('date', 'N/A')}")
            print(f"{Fore.CYAN}  URL: {scan.get('url', 'N/A')}")
            print(f"{Fore.CYAN}  Type: {scan.get('scan_type', 'N/A')}")
            print(f"{Fore.CYAN}  Vulnérabilités: {scan.get('total_vulnerabilities', '0')}")
            print(f"{Fore.CYAN}  Score: {scan.get('score', '0')}/100")
            
            level = scan.get('level', 'N/A')
            if level in ['EXCELLENT', 'BON']:
                color = Fore.GREEN
            elif level == 'MOYEN':
                color = Fore.YELLOW
            else:
                color = Fore.RED
            
            print(f"{color}  Niveau: {level}{Style.RESET_ALL}")
    
    def print_statistics(self):
        """Affiche des statistiques sur tous les scans"""
        scans = self.get_recent_scans(1000)  # Tous les scans
        
        if not scans:
            print(f"{Fore.YELLOW}[~] Aucune donnée statistique disponible")
            return
        
        total_scans = len(scans)
        total_vulnerabilities = 0
        total_score = 0
        
        for scan in scans:
            total_vulnerabilities += int(scan.get('total_vulnerabilities', 0))
            total_score += int(scan.get('score', 0))
        
        avg_score = total_score / total_scans if total_scans > 0 else 0
        avg_vulns = total_vulnerabilities / total_scans if total_scans > 0 else 0
        
        # Compter par niveau
        levels = {}
        for scan in scans:
            level = scan.get('level', 'INCONNU')
            levels[level] = levels.get(level, 0) + 1
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}   STATISTIQUES DES SCANS")
        print(f"{Fore.CYAN}{'='*60}")
        
        print(f"\n{Fore.YELLOW}[*] Général :")
        print(f"{Fore.CYAN}  Nombre total de scans: {total_scans}")
        print(f"{Fore.CYAN}  Vulnérabilités totales: {total_vulnerabilities}")
        print(f"{Fore.CYAN}  Vulnérabilités moyennes par scan: {avg_vulns:.1f}")
        print(f"{Fore.CYAN}  Score moyen: {avg_score:.1f}/100")
        
        print(f"\n{Fore.YELLOW}[*] Répartition par niveau :")
        for level, count in sorted(levels.items()):
            percentage = (count / total_scans) * 100
            if level in ['EXCELLENT', 'BON']:
                color = Fore.GREEN
            elif level == 'MOYEN':
                color = Fore.YELLOW
            else:
                color = Fore.RED
            
            print(f"{color}  {level}: {count} scans ({percentage:.1f}%){Style.RESET_ALL}")
        
        # Sites les plus scannés
        site_counts = {}
        for scan in scans:
            site = scan.get('url', 'Inconnu')
            site_counts[site] = site_counts.get(site, 0) + 1
        
        if site_counts:
            print(f"\n{Fore.YELLOW}[*] Top 3 des sites analysés :")
            sorted_sites = sorted(site_counts.items(), key=lambda x: x[1], reverse=True)
            for i, (site, count) in enumerate(sorted_sites[:3], 1):
                print(f"{Fore.CYAN}  {i}. {site}: {count} scan(s)")
        
        print(f"\n{Fore.CYAN}{'='*60}")

# Instance globale pour une utilisation facile
logger = SecurityLogger()