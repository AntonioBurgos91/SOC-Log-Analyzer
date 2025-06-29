from abc import ABC, abstractmethod
import pandas as pd
from typing import Dict, List, Any
from dataclasses import dataclass
from datetime import datetime
import sys
sys.path.append('..')
from utils.logger import setup_logger

@dataclass
class Alert:
    """Estructura de una alerta de seguridad"""
    alert_id: str
    timestamp: datetime
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    alert_type: str
    source_ip: str
    description: str
    evidence: Dict[str, Any]
    recommendation: str
    mitre_technique: str = ""

class BaseDetector(ABC):
    """Clase base para todos los detectores de amenazas"""
    
    def __init__(self, name: str):
        self.name = name
        self.logger = setup_logger(f"Detector-{name}")
        self.alerts = []
        
    @abstractmethod
    def detect(self, data: pd.DataFrame) -> List[Alert]:
        """Método abstracto para detectar amenazas"""
        pass
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Resumen de alertas generadas"""
        if not self.alerts:
            return {"total_alerts": 0}
        
        severity_counts = {}
        for alert in self.alerts:
            severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
        
        return {
            "total_alerts": len(self.alerts),
            "severity_breakdown": severity_counts,
            "most_recent": self.alerts[-1].timestamp if self.alerts else None
        }

# Test básico
if __name__ == "__main__":
    print("✅ BaseDetector creado correctamente")
    print("📋 Clases Alert y BaseDetector listas para uso")