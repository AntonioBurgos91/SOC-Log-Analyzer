#!/usr/bin/env python3
"""
Generador de Logs SSH Masivo para Simulación de Red Empresarial
Crea logs realistas con múltiples tipos de ataques y patrones
"""

import random
import string
from datetime import datetime, timedelta
from pathlib import Path

class MassiveLogGenerator:
    """Generador de logs SSH realistas para SOC"""
    
    def __init__(self):
        # IPs maliciosas de diferentes países
        self.malicious_ips = [
            # China
            "118.25.6.39", "123.207.167.163", "47.75.156.18", "139.196.74.124",
            "101.132.192.133", "112.74.169.178", "47.52.135.122", "121.40.153.149",
            # Russia
            "185.220.101.182", "194.87.139.103", "46.166.139.111", "178.154.171.47",
            "95.181.161.7", "212.193.30.21", "109.248.9.12", "37.230.114.119",
            # North Korea
            "175.45.178.96", "210.52.109.123", "115.85.182.44",
            # Iran
            "2.177.155.6", "5.160.33.87", "91.98.143.85", "185.51.201.133",
            # USA (compromised servers)
            "167.71.13.196", "134.209.24.42", "207.154.224.147", "159.89.154.73",
            # Brazil
            "177.54.144.205", "189.84.48.139", "201.20.109.55",
            # India
            "103.251.167.10", "117.239.107.51", "182.71.77.123",
            # Germany (compromised)
            "46.4.35.142", "85.214.67.203", "176.9.134.141",
            # Vietnam
            "113.160.155.166", "125.212.217.215", "103.97.125.252",
            # Unknown/VPN
            "tor-exit1.anonymized.com", "proxy.darkweb.onion", "185.220.102.8"
        ]
        
        # IPs legítimas de la red interna
        self.legitimate_ips = [
            "192.168.1.10", "192.168.1.25", "192.168.1.45", "192.168.1.88",
            "10.0.1.15", "10.0.1.33", "10.0.1.67", "10.0.2.12", "10.0.2.89",
            "172.16.0.100", "172.16.0.150", "172.16.1.200"
        ]
        
        # Usernames comunes en ataques reales
        self.attack_usernames = [
            # Cuentas administrativas
            "admin", "administrator", "root", "superuser", "sa", "postgres",
            "mysql", "oracle", "nginx", "apache", "www", "www-data", "ubuntu",
            "centos", "debian", "redhat", "suse", "kali", "pi", "raspberry",
            
            # Nombres comunes de usuarios
            "john", "mike", "david", "sarah", "lisa", "admin123", "test", "guest",
            "user", "demo", "temp", "backup", "service", "support", "help",
            
            # Nombres específicos de servicios
            "ftp", "mail", "email", "web", "dns", "dhcp", "nfs", "samba",
            "jenkins", "docker", "kubernetes", "git", "svn", "nagios",
            
            # Cuentas por defecto
            "admin@123", "password", "123456", "qwerty", "letmein", "welcome",
            "default", "public", "private", "secret", "hidden", "anonymous",
            
            # Nombres corporativos simulados
            "jsmith", "mdavis", "sjohnson", "kwilliams", "tbrown", "rjones",
            "lgarcia", "mmiller", "dwilson", "amoore", "jtaylor", "kanderson"
        ]
        
        # Nombres legítimos de usuarios de la empresa
        self.legitimate_users = [
            "jsmith", "mdavis", "skjohnson", "admin", "backup", "monitor",
            "service.account", "db.admin", "web.service", "api.user"
        ]
        
        # Tipos de eventos SSH
        self.event_types = [
            "failed_password", "invalid_user", "connection_closed", 
            "accepted_publickey", "accepted_password", "session_opened",
            "session_closed", "break_in_attempt", "authentication_failure",
            "maximum_authentication_attempts", "connection_reset"
        ]
        
        # Hostnames de servidores
        self.hostnames = [
            "web-srv-01", "db-srv-02", "mail-srv-03", "file-srv-04",
            "backup-srv-05", "monitor-srv-06", "jump-srv-07", "api-srv-08",
            "cache-srv-09", "log-srv-10", "dns-srv-11", "dhcp-srv-12"
        ]

    def generate_massive_logs(self, num_events: int = 5000, days_back: int = 7) -> str:
        """Genera logs masivos para simular red empresarial"""
        
        print(f"🔧 Generando {num_events} eventos de log para {days_back} días...")
        
        logs = []
        start_time = datetime.now() - timedelta(days=days_back)
        
        # Generar eventos distribuidos en el tiempo
        for i in range(num_events):
            # Timestamp aleatorio en el rango
            random_seconds = random.randint(0, days_back * 24 * 3600)
            event_time = start_time + timedelta(seconds=random_seconds)
            
            # Decidir tipo de evento (70% malicioso, 30% legítimo)
            if random.random() < 0.7:
                log_line = self._generate_malicious_event(event_time)
            else:
                log_line = self._generate_legitimate_event(event_time)
            
            logs.append(log_line)
            
            # Progress indicator
            if (i + 1) % 500 == 0:
                print(f"  📝 Generados {i + 1}/{num_events} eventos...")
        
        # Ordenar logs por timestamp
        logs.sort()
        
        print(f"✅ Generación completada: {len(logs)} eventos creados")
        return '\n'.join(logs)

    def _generate_malicious_event(self, timestamp: datetime) -> str:
        """Genera evento malicioso realista"""
        
        # Seleccionar tipo de ataque
        attack_patterns = [
            self._brute_force_attack,
            self._user_enumeration_attack,
            self._credential_stuffing_attack,
            self._automated_scanner_attack,
            self._persistent_attacker
        ]
        
        attack_generator = random.choice(attack_patterns)
        return attack_generator(timestamp)

    def _generate_legitimate_event(self, timestamp: datetime) -> str:
        """Genera evento legítimo de usuario real"""
        
        timestamp_str = timestamp.strftime("%b %d %H:%M:%S")
        hostname = random.choice(self.hostnames)
        pid = random.randint(10000, 99999)
        user = random.choice(self.legitimate_users)
        source_ip = random.choice(self.legitimate_ips)
        port = random.choice([22, 2222])
        
        # Eventos legítimos variados
        event_types = [
            f"Accepted publickey for {user} from {source_ip} port {port} ssh2: RSA SHA256:abc123def456",
            f"Accepted password for {user} from {source_ip} port {port} ssh2",
            f"pam_unix(sshd:session): session opened for user {user} by (uid=0)",
            f"pam_unix(sshd:session): session closed for user {user}",
            f"Connection from {source_ip} port {port} on {source_ip} port 22"
        ]
        
        event = random.choice(event_types)
        return f"{timestamp_str} {hostname} sshd[{pid}]: {event}"

    def _brute_force_attack(self, timestamp: datetime) -> str:
        """Genera ataque de fuerza bruta intenso"""
        
        timestamp_str = timestamp.strftime("%b %d %H:%M:%S")
        hostname = random.choice(self.hostnames)
        pid = random.randint(1000, 9999)
        username = random.choice(["admin", "root", "administrator", "postgres", "mysql"])
        source_ip = random.choice(self.malicious_ips)
        port = random.randint(50000, 65000)
        
        # Patrones típicos de brute force
        patterns = [
            f"Failed password for {username} from {source_ip} port {port} ssh2",
            f"Failed password for invalid user {username} from {source_ip} port {port}",
            f"Connection closed by {source_ip} port {port} [preauth]",
            f"maximum authentication attempts exceeded for {username} from {source_ip} port {port} ssh2 [preauth]",
            f"POSSIBLE BREAK-IN ATTEMPT!"
        ]
        
        pattern = random.choice(patterns)
        return f"{timestamp_str} {hostname} sshd[{pid}]: {pattern}"

    def _user_enumeration_attack(self, timestamp: datetime) -> str:
        """Genera ataque de enumeración de usuarios"""
        
        timestamp_str = timestamp.strftime("%b %d %H:%M:%S")
        hostname = random.choice(self.hostnames)
        pid = random.randint(1000, 9999)
        source_ip = random.choice(self.malicious_ips)
        port = random.randint(50000, 65000)
        
        # Usernames típicos de enumeración
        enum_users = [
            "test", "guest", "demo", "temp", "backup", "service", "support",
            "user1", "user2", "admin1", "admin2", "test123", "guest123"
        ]
        
        username = random.choice(enum_users)
        return f"{timestamp_str} {hostname} sshd[{pid}]: Invalid user {username} from {source_ip} port {port}"

    def _credential_stuffing_attack(self, timestamp: datetime) -> str:
        """Genera ataque de credential stuffing"""
        
        timestamp_str = timestamp.strftime("%b %d %H:%M:%S")
        hostname = random.choice(self.hostnames)
        pid = random.randint(1000, 9999)
        source_ip = random.choice(self.malicious_ips)
        port = random.randint(50000, 65000)
        
        # Usernames de diccionarios comunes
        dict_users = [
            "admin@company.com", "user@domain.com", "test@test.com",
            "info@company.com", "support@company.com", "sales@company.com"
        ]
        
        username = random.choice(dict_users)
        return f"{timestamp_str} {hostname} sshd[{pid}]: Failed password for {username} from {source_ip} port {port} ssh2"

    def _automated_scanner_attack(self, timestamp: datetime) -> str:
        """Genera actividad de scanner automatizado"""
        
        timestamp_str = timestamp.strftime("%b %d %H:%M:%S")
        hostname = random.choice(self.hostnames)
        pid = random.randint(1000, 9999)
        source_ip = random.choice(self.malicious_ips)
        port = random.randint(40000, 65000)
        
        # Patrones de scanners automáticos
        scanner_patterns = [
            f"Connection from {source_ip} port {port}",
            f"Did not receive identification string from {source_ip} port {port}",
            f"Connection closed by {source_ip} port {port} [preauth]",
            f"Invalid user scanner from {source_ip} port {port}",
            f"Invalid user bot from {source_ip} port {port}",
            f"Bad protocol version identification '\\x00\\x01\\x02' from {source_ip} port {port}"
        ]
        
        pattern = random.choice(scanner_patterns)
        return f"{timestamp_str} {hostname} sshd[{pid}]: {pattern}"

    def _persistent_attacker(self, timestamp: datetime) -> str:
        """Genera ataque persistente de APT"""
        
        timestamp_str = timestamp.strftime("%b %d %H:%M:%S")
        hostname = random.choice(self.hostnames)
        pid = random.randint(1000, 9999)
        
        # IPs de APT conocidas (simuladas)
        apt_ips = [
            "118.25.6.39",  # China APT
            "185.220.101.182",  # Russia APT
            "175.45.178.96",  # North Korea APT
            "2.177.155.6"  # Iran APT
        ]
        
        source_ip = random.choice(apt_ips)
        port = random.randint(50000, 65000)
        
        # Patrones de APT (más sofisticados)
        username = random.choice(self.legitimate_users)  # Targetan usuarios reales
        
        apt_patterns = [
            f"Failed password for {username} from {source_ip} port {port} ssh2",
            f"Accepted password for {username} from {source_ip} port {port} ssh2",  # Éxito ocasional
            f"pam_unix(sshd:session): session opened for user {username} by (uid=0)",
            f"Connection from {source_ip} port {port} on {random.choice(self.legitimate_ips)} port 22"
        ]
        
        pattern = random.choice(apt_patterns)
        return f"{timestamp_str} {hostname} sshd[{pid}]: {pattern}"

    def save_logs(self, content: str, filename: str = None) -> str:
        """Guarda logs en archivo"""
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"enterprise_auth_{timestamp}.log"
        
        filepath = Path("data") / filename
        filepath.parent.mkdir(exist_ok=True)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"💾 Logs guardados en: {filepath}")
        print(f"📊 Tamaño del archivo: {filepath.stat().st_size / 1024 / 1024:.2f} MB")
        
        return str(filepath)

    def generate_attack_campaign(self, campaign_name: str, duration_hours: int = 24) -> str:
        """Genera campaña de ataque específica"""
        
        print(f"🎯 Generando campaña de ataque: {campaign_name}")
        
        logs = []
        start_time = datetime.now() - timedelta(hours=duration_hours)
        
        if campaign_name == "APT_China":
            # Campaña sofisticada de APT chino
            source_ips = ["118.25.6.39", "123.207.167.163", "47.75.156.18"]
            targets = ["admin", "jsmith", "db.admin", "backup"]
            
            for hour in range(duration_hours):
                for _ in range(random.randint(5, 15)):
                    event_time = start_time + timedelta(hours=hour, minutes=random.randint(0, 59))
                    timestamp_str = event_time.strftime("%b %d %H:%M:%S")
                    hostname = random.choice(self.hostnames)
                    pid = random.randint(1000, 9999)
                    source_ip = random.choice(source_ips)
                    target = random.choice(targets)
                    port = random.randint(50000, 65000)
                    
                    # Patrón de ataque APT
                    if random.random() < 0.95:  # 95% fallos, 5% éxitos
                        event = f"Failed password for {target} from {source_ip} port {port} ssh2"
                    else:
                        event = f"Accepted password for {target} from {source_ip} port {port} ssh2"
                    
                    logs.append(f"{timestamp_str} {hostname} sshd[{pid}]: {event}")
        
        elif campaign_name == "Botnet_Distributed":
            # Ataque distribuido de botnet
            botnet_ips = random.sample(self.malicious_ips, 20)  # 20 IPs diferentes
            
            for _ in range(2000):  # 2000 eventos distribuidos
                event_time = start_time + timedelta(seconds=random.randint(0, duration_hours * 3600))
                timestamp_str = event_time.strftime("%b %d %H:%M:%S")
                hostname = random.choice(self.hostnames)
                pid = random.randint(1000, 9999)
                source_ip = random.choice(botnet_ips)
                username = random.choice(self.attack_usernames)
                port = random.randint(40000, 65000)
                
                event = f"Failed password for {username} from {source_ip} port {port} ssh2"
                logs.append(f"{timestamp_str} {hostname} sshd[{pid}]: {event}")
        
        logs.sort()
        return '\n'.join(logs)

def main():
    """Función principal para generar logs masivos"""
    
    print("🛡️ GENERADOR DE LOGS SSH MASIVO PARA SOC")
    print("=" * 60)
    
    generator = MassiveLogGenerator()
    
    # Menú de opciones
    print("Selecciona tipo de generación:")
    print("1. 📊 Logs masivos (5000 eventos, 7 días)")
    print("2. 🔥 Logs extremos (15000 eventos, 30 días)")
    print("3. 🎯 Campaña APT China")
    print("4. 🤖 Ataque Botnet distribuido")
    print("5. 💥 Todo incluido (20000 eventos + campañas)")
    
    try:
        choice = input("\nElige opción (1-5): ").strip()
        
        if choice == "1":
            content = generator.generate_massive_logs(5000, 7)
            filename = "enterprise_auth_massive.log"
        
        elif choice == "2":
            content = generator.generate_massive_logs(15000, 30)
            filename = "enterprise_auth_extreme.log"
        
        elif choice == "3":
            content = generator.generate_attack_campaign("APT_China", 24)
            filename = "apt_china_campaign.log"
        
        elif choice == "4":
            content = generator.generate_attack_campaign("Botnet_Distributed", 12)
            filename = "botnet_distributed.log"
        
        elif choice == "5":
            print("🚀 Generando dataset completo...")
            
            # Combinar todo
            massive_logs = generator.generate_massive_logs(10000, 14)
            apt_campaign = generator.generate_attack_campaign("APT_China", 48)
            botnet_campaign = generator.generate_attack_campaign("Botnet_Distributed", 24)
            
            # Combinar y ordenar
            all_logs = massive_logs.split('\n') + apt_campaign.split('\n') + botnet_campaign.split('\n')
            all_logs.sort()
            content = '\n'.join(all_logs)
            filename = "enterprise_auth_complete.log"
        
        else:
            print("❌ Opción inválida")
            return
        
        # Guardar archivo
        filepath = generator.save_logs(content, filename)
        
        print(f"\n✅ GENERACIÓN COMPLETADA")
        print(f"📁 Archivo: {filepath}")
        print(f"📊 Eventos generados: {len(content.split())} líneas")
        print(f"\n🚀 Para analizar con SOC:")
        print(f"python main.py --input {filepath} --analyze --report")
        
    except KeyboardInterrupt:
        print("\n⏹️ Generación cancelada por el usuario")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()