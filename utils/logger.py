import logging
import sys
from pathlib import Path
from datetime import datetime

def setup_logger(name="SOC-Analyzer", level=logging.INFO):
    """Setup del sistema de logging profesional para SOC"""
    
    # Crear directorio de logs si no existe
    log_dir = Path("output/logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Configurar logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Evitar duplicar handlers
    if logger.handlers:
        return logger
    
    # Formato de log estilo SOC
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)-8s [%(name)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Handler para consola
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Handler para archivo
    today = datetime.now().strftime("%Y%m%d")
    file_handler = logging.FileHandler(log_dir / f"soc_analyzer_{today}.log")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger

# Test básico
if __name__ == "__main__":
    logger = setup_logger()
    logger.info("🛡️ SOC Logger inicializado correctamente")
    logger.warning("⚠️ Test de warning")
    logger.error("❌ Test de error")
    print("✅ Logger funcionando - revisar output/logs/")