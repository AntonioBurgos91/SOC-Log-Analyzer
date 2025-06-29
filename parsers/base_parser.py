from abc import ABC, abstractmethod
import pandas as pd
from typing import Dict, List, Any
import sys
sys.path.append('..')
from utils.logger import setup_logger

class BaseParser(ABC):
    """Clase base para todos los parsers de logs"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.logger = setup_logger(f"Parser-{self.__class__.__name__}")
        self.parsed_data = None
        self.logger.info(f"🔍 Inicializando parser para: {file_path}")
        
    @abstractmethod
    def parse(self) -> pd.DataFrame:
        """Método abstracto para parsear logs"""
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Estadísticas básicas del parsing"""
        if self.parsed_data is None:
            return {"error": "No data parsed yet"}
        
        return {
            "total_entries": len(self.parsed_data),
            "columns": list(self.parsed_data.columns),
            "date_range": {
                "start": self.parsed_data['timestamp'].min() if 'timestamp' in self.parsed_data.columns else None,
                "end": self.parsed_data['timestamp'].max() if 'timestamp' in self.parsed_data.columns else None
            },
            "unique_ips": self.parsed_data['source_ip'].nunique() if 'source_ip' in self.parsed_data.columns else 0
        }

# Test básico
if __name__ == "__main__":
    print("✅ BaseParser creado correctamente")
    print("📋 Clase abstracta lista para herencia")