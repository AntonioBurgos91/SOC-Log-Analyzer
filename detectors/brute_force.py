import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
from collections import defaultdict
import uuid

import sys
sys.path.append('..')
from detectors.base_detector import BaseDetector, Alert

class BruteForceDetector(BaseDetector):
    """
    Detector avanzado de ataques de fuerza bruta SSH
    Implementa múltiples técnicas de detección usadas en SOCs reales
    """
    
    def __init__(self, 
                 failed_threshold: int = 5,
                 time_window_minutes: int = 5,
                 distributed_threshold: int = 3):
        
        super().__init__("BruteForce")
        
        # Configuración de umbrales
        self.failed_threshold = failed_threshold
        self.time_window = timedelta(minutes=time_window_minutes)
        self.distributed_threshold = distributed_threshold
        
        self.logger.info(f"🚨 BruteForceDetector inicializado - Umbral: {failed_threshold} intentos en {time_window_minutes}min")

    def detect(self, data: pd.DataFrame) -> List[Alert]:
        """Ejecuta detección de ataques de fuerza bruta"""
        
        self.logger.info("🔍 Iniciando detección de ataques de fuerza bruta...")
        
        if data.empty:
            self.logger.warning("⚠️ DataFrame vacío - no hay datos para analizar")
            return []
        
        # Filtrar eventos relevantes para brute force
        attack_events = data[
            data['event_type'].isin(['failed_password', 'invalid_user']) &
            data['source_ip'].notna()
        ].copy()
        
        if attack_events.empty:
            self.logger.info("ℹ️ No se encontraron eventos de autenticación fallida")
            return []
        
        self.logger.info(f"🔍 Analizando {len(attack_events)} eventos de autenticación fallida")
        
        # Ejecutar diferentes detectores
        alerts = []
        alerts.extend(self._detect_rapid_brute_force(attack_events))
        alerts.extend(self._detect_user_enumeration(attack_events))
        
        self.alerts.extend(alerts)
        self.logger.info(f"✅ Detección completada: {len(alerts)} alertas generadas")
        
        return alerts

    def _detect_rapid_brute_force(self, data: pd.DataFrame) -> List[Alert]:
        """Detecta ataques de fuerza bruta rápidos desde una IP"""
        
        alerts = []
        
        # Agrupar por IP y analizar patrones
        for source_ip in data['source_ip'].unique():
            ip_events = data[data['source_ip'] == source_ip].sort_values('timestamp')
            
            if len(ip_events) >= self.failed_threshold:
                # Calcular duración del ataque
                time_span = ip_events['timestamp'].max() - ip_events['timestamp'].min()
                
                if time_span <= self.time_window:
                    # ¡Ataque detectado!
                    severity = self._calculate_severity(len(ip_events), time_span)
                    
                    alert = Alert(
                        alert_id=str(uuid.uuid4())[:8],
                        timestamp=ip_events['timestamp'].max(),
                        severity=severity,
                        alert_type="SSH_BRUTE_FORCE",
                        source_ip=source_ip,
                        description=f"Rapid brute force attack: {len(ip_events)} failed attempts in {time_span}",
                        evidence={
                            "failed_attempts": len(ip_events),
                            "time_window": str(time_span),
                            "targeted_users": ip_events['username'].dropna().unique().tolist(),
                            "attack_duration": str(time_span),
                            "attempts_per_minute": round(len(ip_events) / (time_span.total_seconds() / 60), 2) if time_span.total_seconds() > 0 else len(ip_events)
                        },
                        recommendation="Block source IP immediately. Check for successful logins from this IP.",
                        mitre_technique="T1110.001"
                    )
                    alerts.append(alert)
        
        return alerts

    def _detect_user_enumeration(self, data: pd.DataFrame) -> List[Alert]:
        """Detecta intentos de enumeración de usuarios"""
        
        alerts = []
        
        # Buscar IPs que prueban muchos usuarios diferentes
        for source_ip in data['source_ip'].unique():
            ip_events = data[data['source_ip'] == source_ip]
            unique_users = ip_events['username'].dropna().nunique()
            
            if unique_users >= 3:  # Umbral para enumeración
                invalid_user_attempts = len(ip_events[ip_events['event_type'] == 'invalid_user'])
                
                alert = Alert(
                    alert_id=str(uuid.uuid4())[:8],
                    timestamp=ip_events['timestamp'].max(),
                    severity="MEDIUM",
                    alert_type="USER_ENUMERATION",
                    source_ip=source_ip,
                    description=f"User enumeration attack: {unique_users} different usernames tested",
                    evidence={
                        "unique_usernames": unique_users,
                        "invalid_user_attempts": invalid_user_attempts,
                        "total_attempts": len(ip_events),
                        "usernames_sample": ip_events['username'].dropna().unique()[:10].tolist(),
                        "attack_span": str(ip_events['timestamp'].max() - ip_events['timestamp'].min())
                    },
                    recommendation="Block IP. Review user account policies and monitoring.",
                    mitre_technique="T1087.001"
                )
                alerts.append(alert)
        
        return alerts

    def _calculate_severity(self, attempts: int, time_span: timedelta) -> str:
        """Calcula severidad basada en intensidad del ataque"""
        
        attempts_per_minute = attempts / (time_span.total_seconds() / 60) if time_span.total_seconds() > 0 else attempts
        
        if attempts_per_minute >= 10 or attempts >= 20:
            return "CRITICAL"
        elif attempts_per_minute >= 5 or attempts >= 10:
            return "HIGH"
        elif attempts_per_minute >= 2 or attempts >= 5:
            return "MEDIUM"
        else:
            return "LOW"

# Test del detector
if __name__ == "__main__":
    from parsers.auth_parser import AuthLogParser
    
    print("🧪 Testing BruteForceDetector...")
    
    # Parsear datos
    parser = AuthLogParser("data/sample_auth.log")
    df = parser.parse()
    
    if df.empty:
        print("❌ No hay datos para analizar")
        exit()
    
    # Ejecutar detector
    detector = BruteForceDetector(
        failed_threshold=3,  # Umbral bajo para detectar en datos de muestra
        time_window_minutes=5
    )
    
    alerts = detector.detect(df)
    
    # Mostrar resultados
    print(f"\n🚨 ALERTAS DE SEGURIDAD GENERADAS: {len(alerts)}")
    print("=" * 60)
    
    for alert in alerts:
        print(f"\n[{alert.severity}] {alert.alert_type}")
        print(f"🎯 IP: {alert.source_ip}")
        print(f"📝 {alert.description}")
        print(f"🔍 Evidencia: {alert.evidence}")
        print(f"💡 Recomendación: {alert.recommendation}")
        print(f"🏷️ MITRE: {alert.mitre_technique}")
        print("-" * 40)
    
    if alerts:
        print(f"\n✅ Detector funcionando correctamente!")
    else:
        print(f"\n⚠️ No se detectaron amenazas con los umbrales actuales")