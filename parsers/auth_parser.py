import re
import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional
import sys
sys.path.append('..')
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from parsers.base_parser import BaseParser

class AuthLogParser(BaseParser):
    """Parser especializado para logs de autenticación SSH/auth.log"""
    
    def __init__(self, file_path: str):
        super().__init__(file_path)
        
        # Patrones regex para diferentes tipos de eventos SSH
        self.patterns = {
            'failed_password': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[(\d+)\]:\s+'
                r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
            ),
            'invalid_user': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[(\d+)\]:\s+'
                r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
            ),
            'connection_closed': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[(\d+)\]:\s+'
                r'Connection closed by (\d+\.\d+\.\d+\.\d+) port (\d+)'
            )
        }
    
    def parse(self) -> pd.DataFrame:
        """Parsea el archivo auth.log y extrae eventos de seguridad"""
        
        self.logger.info(f"🔍 Iniciando parsing de {self.file_path}")
        
        events = []
        total_lines = 0
        parsed_lines = 0
        
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line_num, line in enumerate(file, 1):
                    total_lines += 1
                    line = line.strip()
                    
                    if not line:
                        continue
                    
                    # Intentar parsear con cada patrón
                    for event_type, pattern in self.patterns.items():
                        match = pattern.search(line)
                        if match:
                            event = self._extract_event(event_type, match, line, line_num)
                            if event:
                                events.append(event)
                                parsed_lines += 1
                            break
        
        except FileNotFoundError:
            self.logger.error(f"❌ Archivo no encontrado: {self.file_path}")
            return pd.DataFrame()
        except Exception as e:
            self.logger.error(f"❌ Error leyendo archivo: {e}")
            return pd.DataFrame()
        
        # Convertir a DataFrame
        if events:
            self.parsed_data = pd.DataFrame(events)
            self.parsed_data['timestamp'] = pd.to_datetime(self.parsed_data['timestamp'])
            self.parsed_data = self.parsed_data.sort_values('timestamp')
        else:
            self.parsed_data = pd.DataFrame()
        
        self.logger.info(f"✅ Parsing completado: {parsed_lines}/{total_lines} líneas procesadas")
        self.logger.info(f"📊 Eventos extraídos: {len(events)}")
        
        return self.parsed_data
    
    def _extract_event(self, event_type: str, match: re.Match, raw_line: str, line_num: int) -> Optional[Dict]:
        """Extrae información estructurada de un evento"""
        
        try:
            groups = match.groups()
            
            # Timestamp base (año 2024 por defecto)
            timestamp_str = groups[0]
            timestamp = self._parse_timestamp(timestamp_str)
            
            base_event = {
                'line_number': line_num,
                'timestamp': timestamp,
                'hostname': groups[1] if len(groups) > 1 else 'unknown',
                'event_type': event_type,
                'severity': self._get_severity(event_type),
                'raw_line': raw_line
            }
            
            # Extraer campos específicos por tipo de evento
            if event_type == 'failed_password':
                base_event.update({
                    'pid': groups[2],
                    'username': groups[3],
                    'source_ip': groups[4],
                    'source_port': int(groups[5]),
                    'attack_type': 'brute_force'
                })
            
            elif event_type == 'invalid_user':
                base_event.update({
                    'pid': groups[2],
                    'username': groups[3],
                    'source_ip': groups[4],
                    'source_port': int(groups[5]),
                    'attack_type': 'user_enumeration'
                })
            
            elif event_type == 'connection_closed':
                base_event.update({
                    'pid': groups[2],
                    'source_ip': groups[3],
                    'source_port': int(groups[4]) if groups[4].isdigit() else 0
                })
            
            return base_event
            
        except Exception as e:
            self.logger.warning(f"⚠️ Error extrayendo evento línea {line_num}: {e}")
            return None
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Convierte timestamp de log a datetime object"""
        try:
            current_year = datetime.now().year
            full_timestamp = f"{current_year} {timestamp_str}"
            return datetime.strptime(full_timestamp, "%Y %b %d %H:%M:%S")
        except:
            return datetime.now()
    
    def _get_severity(self, event_type: str) -> str:
        """Asigna severidad basada en el tipo de evento"""
        severity_map = {
            'failed_password': 'MEDIUM',
            'invalid_user': 'MEDIUM', 
            'connection_closed': 'LOW'
        }
        return severity_map.get(event_type, 'LOW')

# Test del parser
if __name__ == "__main__":
    print("🧪 Testing AuthLogParser...")
    
    parser = AuthLogParser("data/sample_auth.log")
    df = parser.parse()
    
    if not df.empty:
        print("✅ Parser funcionando correctamente!")
        print(f"📊 Eventos procesados: {len(df)}")
        print(f"🔍 Columnas: {list(df.columns)}")
        print("\n📋 Primeros eventos:")
        print(df[['timestamp', 'event_type', 'source_ip', 'username']].head())
        
        # Estadísticas
        stats = parser.get_stats()
        print(f"\n📈 Estadísticas:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
    else:
        print("❌ No se pudieron extraer eventos")