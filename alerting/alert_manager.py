import json
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path
import sqlite3
from enum import Enum
import sys
sys.path.append('..')

from detectors.base_detector import Alert
from utils.logger import setup_logger

class AlertStatus(Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ESCALATED = "ESCALATED"

class AlertManager:
    """
    Gestor profesional de alertas para SOC
    Maneja ciclo de vida completo: creación, investigación, resolución
    """
    
    def __init__(self, db_path: str = "output/soc_alerts.db"):
        self.logger = setup_logger("AlertManager")
        self.db_path = db_path
        self._init_database()
        
        # Configuración de auto-filtering
        self.auto_filter_rules = {
            "duplicate_window": timedelta(minutes=30),  # Evitar alertas duplicadas
            "rate_limit": {"CRITICAL": 10, "HIGH": 20, "MEDIUM": 50, "LOW": 100},
            "whitelist_ips": set(),  # IPs excluidas de alertas
        }
        
        self.logger.info("🚨 AlertManager inicializado correctamente")

    def _init_database(self):
        """Inicializa base de datos SQLite para persistencia"""
        
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT UNIQUE,
                    timestamp TEXT,
                    severity TEXT,
                    alert_type TEXT,
                    source_ip TEXT,
                    description TEXT,
                    evidence TEXT,
                    recommendation TEXT,
                    mitre_technique TEXT,
                    status TEXT DEFAULT 'NEW',
                    assigned_to TEXT,
                    notes TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Crear índices para mejor performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
            
            self.logger.info("💾 Base de datos SQLite inicializada correctamente")

    def ingest_alerts(self, alerts: List[Alert]) -> Dict[str, Any]:
        """Ingesta y procesa nuevas alertas con filtrado inteligente"""
        
        if not alerts:
            self.logger.warning("⚠️ No hay alertas para procesar")
            return {"processed": 0, "filtered": 0, "errors": 0}
        
        processed = 0
        filtered = 0
        errors = 0
        
        self.logger.info(f"📥 Procesando {len(alerts)} alertas...")
        
        for alert in alerts:
            try:
                # Aplicar filtros automáticos
                if self._should_filter_alert(alert):
                    filtered += 1
                    self.logger.debug(f"🚫 Alerta {alert.alert_id} filtrada")
                    continue
                
                # Enriquecimiento automático
                enriched_alert = self._enrich_alert(alert)
                
                # Guardar en base de datos
                self._save_alert(enriched_alert)
                processed += 1
                self.logger.info(f"✅ Alerta {alert.alert_id} procesada correctamente")
                
                # Auto-escalation para alertas críticas
                if alert.severity == "CRITICAL":
                    self._auto_escalate(alert)
                
            except Exception as e:
                self.logger.error(f"❌ Error procesando alerta {alert.alert_id}: {e}")
                errors += 1
        
        self.logger.info(f"📊 Resumen: {processed} procesadas, {filtered} filtradas, {errors} errores")
        
        return {
            "processed": processed,
            "filtered": filtered,
            "errors": errors,
            "total_active_alerts": self.get_active_alert_count()
        }

    def _should_filter_alert(self, alert: Alert) -> bool:
        """Determina si una alerta debe ser filtrada"""
        
        # Filtrar IPs whitelistadas
        if alert.source_ip in self.auto_filter_rules["whitelist_ips"]:
            return True
        
        # Filtrar duplicados recientes
        if self._is_duplicate_alert(alert):
            return True
        
        return False

    def _is_duplicate_alert(self, alert: Alert) -> bool:
        """Verifica si es una alerta duplicada reciente"""
        
        try:
            window_start = alert.timestamp - self.auto_filter_rules["duplicate_window"]
            timestamp_str = self._convert_timestamp(alert.timestamp)
            window_start_str = self._convert_timestamp(window_start)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT COUNT(*) FROM alerts 
                    WHERE source_ip = ? AND alert_type = ? 
                    AND timestamp > ? AND timestamp <= ?
                """, (alert.source_ip, alert.alert_type, window_start_str, timestamp_str))
                
                count = cursor.fetchone()[0]
                return count > 0
        except Exception as e:
            self.logger.warning(f"⚠️ Error verificando duplicados: {e}")
            return False

    def _convert_timestamp(self, timestamp) -> str:
        """Convierte timestamp a string para SQLite"""
        if hasattr(timestamp, 'strftime'):
            return timestamp.strftime("%Y-%m-%d %H:%M:%S")
        elif isinstance(timestamp, str):
            return timestamp
        else:
            return str(timestamp)

    def _enrich_alert(self, alert: Alert) -> Alert:
        """Enriquece alerta con información adicional"""
        
        # Asegurar que evidence es un dict
        if not isinstance(alert.evidence, dict):
            alert.evidence = {}
        
        # Agregar threat intelligence score
        alert.evidence["threat_score"] = self._calculate_threat_score(alert)
        
        # Agregar contexto temporal
        try:
            alert.evidence["hour_of_day"] = alert.timestamp.hour
            alert.evidence["day_of_week"] = alert.timestamp.strftime("%A")
        except:
            alert.evidence["hour_of_day"] = 0
            alert.evidence["day_of_week"] = "Unknown"
        
        return alert

    def _calculate_threat_score(self, alert: Alert) -> int:
        """Calcula score de amenaza (0-100)"""
        
        score = 0
        
        # Base score por severidad
        severity_scores = {"LOW": 10, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 90}
        score += severity_scores.get(alert.severity, 10)
        
        # Bonus por evidencia
        if isinstance(alert.evidence, dict):
            if alert.evidence.get("failed_attempts", 0) > 50:
                score += 10
            if alert.evidence.get("attempts_per_minute", 0) > 10:
                score += 15
        
        return min(score, 100)

    def _save_alert(self, alert: Alert):
        """Guarda alerta en base de datos con manejo correcto de tipos"""
        
        try:
            # Convertir todos los valores a tipos compatibles con SQLite
            alert_id = str(alert.alert_id)
            timestamp = self._convert_timestamp(alert.timestamp)
            severity = str(alert.severity)
            alert_type = str(alert.alert_type)
            source_ip = str(alert.source_ip)
            description = str(alert.description)
            evidence = json.dumps(alert.evidence) if alert.evidence else "{}"
            recommendation = str(alert.recommendation)
            mitre_technique = str(alert.mitre_technique)
            status = AlertStatus.NEW.value
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO alerts 
                    (alert_id, timestamp, severity, alert_type, source_ip, description, 
                     evidence, recommendation, mitre_technique, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert_id,
                    timestamp,
                    severity,
                    alert_type,
                    source_ip,
                    description,
                    evidence,
                    recommendation,
                    mitre_technique,
                    status
                ))
            
            self.logger.debug(f"💾 Alerta {alert_id} guardada en base de datos")
            
        except Exception as e:
            self.logger.error(f"❌ Error guardando alerta: {e}")
            raise

    def _auto_escalate(self, alert: Alert):
        """Auto-escalación para alertas críticas"""
        
        self.logger.warning(f"🚨 ALERTA CRÍTICA AUTO-ESCALADA: {alert.alert_id}")
        
        # En producción: enviar email/webhook/SMS
        escalation_data = {
            "alert_id": alert.alert_id,
            "severity": alert.severity,
            "source_ip": alert.source_ip,
            "description": alert.description,
            "timestamp": self._convert_timestamp(alert.timestamp)
        }
        
        # Simular notificación
        self.logger.critical(f"🔥 ESCALATION: {json.dumps(escalation_data)}")

    def get_alerts(self, 
                   severity: Optional[str] = None,
                   status: Optional[str] = None,
                   limit: int = 100) -> pd.DataFrame:
        """Obtiene alertas filtradas"""
        
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        if status:
            query += " AND status = ?"
            params.append(status)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                df = pd.read_sql_query(query, conn, params=params)
                
                if not df.empty:
                    df['evidence'] = df['evidence'].apply(
                        lambda x: json.loads(x) if x and x != '{}' else {}
                    )
            
            return df
        except Exception as e:
            self.logger.error(f"❌ Error obteniendo alertas: {e}")
            return pd.DataFrame()

    def get_active_alert_count(self) -> int:
        """Cuenta alertas activas (no resueltas)"""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT COUNT(*) FROM alerts 
                    WHERE status NOT IN ('RESOLVED', 'FALSE_POSITIVE')
                """)
                return cursor.fetchone()[0]
        except Exception as e:
            self.logger.error(f"❌ Error contando alertas activas: {e}")
            return 0

    def update_alert_status(self, alert_id: str, status: AlertStatus, notes: str = ""):
        """Actualiza estado de una alerta"""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE alerts 
                    SET status = ?, notes = ?, updated_at = ?
                    WHERE alert_id = ?
                """, (status.value, notes, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), alert_id))
            
            self.logger.info(f"✅ Alerta {alert_id} actualizada a {status.value}")
        except Exception as e:
            self.logger.error(f"❌ Error actualizando alerta: {e}")

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Métricas para dashboard SOC"""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Alertas por severidad (últimas 24h)
                severity_query = """
                    SELECT severity, COUNT(*) as count 
                    FROM alerts 
                    WHERE timestamp > datetime('now', '-1 day')
                    GROUP BY severity
                """
                severity_df = pd.read_sql_query(severity_query, conn)
                
                # Top atacantes
                attackers_query = """
                    SELECT source_ip, COUNT(*) as alert_count, 
                           MAX(severity) as max_severity
                    FROM alerts 
                    WHERE timestamp > datetime('now', '-7 days') 
                    AND source_ip != 'MULTIPLE'
                    GROUP BY source_ip 
                    ORDER BY alert_count DESC 
                    LIMIT 10
                """
                attackers_df = pd.read_sql_query(attackers_query, conn)
                
                # Estadísticas generales
                stats_query = """
                    SELECT 
                        COUNT(*) as total_alerts,
                        COUNT(CASE WHEN status = 'NEW' THEN 1 END) as new_alerts,
                        COUNT(CASE WHEN timestamp > datetime('now', '-1 day') THEN 1 END) as alerts_24h,
                        COUNT(DISTINCT source_ip) as unique_attackers
                    FROM alerts
                """
                stats = pd.read_sql_query(stats_query, conn).iloc[0].to_dict()
            
            return {
                "severity_distribution": severity_df.to_dict('records'),
                "top_attackers": attackers_df.to_dict('records'),
                "general_stats": stats,
                "last_updated": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"❌ Error obteniendo métricas: {e}")
            return {
                "severity_distribution": [],
                "top_attackers": [],
                "general_stats": {"total_alerts": 0, "new_alerts": 0, "alerts_24h": 0, "unique_attackers": 0},
                "last_updated": datetime.now().isoformat()
            }

    def generate_report(self) -> Dict[str, Any]:
        """Genera reporte ejecutivo"""
        
        metrics = self.get_dashboard_metrics()
        
        return {
            "report_generated": datetime.now().isoformat(),
            "summary": {
                "total_alerts": metrics["general_stats"]["total_alerts"],
                "new_alerts": metrics["general_stats"]["new_alerts"],
                "unique_attackers": metrics["general_stats"]["unique_attackers"]
            },
            "top_threats": metrics["top_attackers"][:5],
            "severity_breakdown": metrics["severity_distribution"],
            "recommendations": [
                "Implement automated IP blocking for repeat attackers",
                "Review authentication policies for targeted accounts",
                "Consider implementing fail2ban or similar tools",
                "Monitor for successful logins from flagged IPs"
            ]
        }

# Test del Alert Manager
if __name__ == "__main__":
    from parsers.auth_parser import AuthLogParser
    from detectors.brute_force import BruteForceDetector
    
    print("🧪 Testing AlertManager...")
    
    # 1. Parsear datos
    parser = AuthLogParser("data/sample_auth.log")
    df = parser.parse()
    
    if df.empty:
        print("❌ No hay datos para analizar")
        exit()
    
    # 2. Detectar amenazas
    detector = BruteForceDetector(failed_threshold=3)
    alerts = detector.detect(df)
    
    if not alerts:
        print("⚠️ No se detectaron amenazas")
        exit()
    
    # 3. Gestionar alertas
    alert_manager = AlertManager()
    result = alert_manager.ingest_alerts(alerts)
    
    print(f"\n📊 RESULTADO:")
    print(f"✅ Procesadas: {result['processed']}")
    print(f"🚫 Filtradas: {result['filtered']}")
    print(f"❌ Errores: {result['errors']}")
    print(f"📈 Total activas: {result['total_active_alerts']}")
    
    # 4. Obtener métricas
    metrics = alert_manager.get_dashboard_metrics()
    print(f"\n📊 MÉTRICAS SOC:")
    print(f"📋 Distribución severidad: {metrics['severity_distribution']}")
    print(f"🎯 Top atacantes: {metrics['top_attackers']}")
    
    # 5. Mostrar alertas guardadas
    saved_alerts = alert_manager.get_alerts()
    print(f"\n💾 ALERTAS GUARDADAS EN BD:")
    if not saved_alerts.empty:
        for _, alert in saved_alerts.iterrows():
            print(f"🚨 {alert['alert_id'][:8]} | {alert['severity']} | {alert['source_ip']} | {alert['alert_type']}")
    
    # 6. Generar reporte
    report = alert_manager.generate_report()
    print(f"\n📄 REPORTE EJECUTIVO:")
    print(f"🚨 Total alertas: {report['summary']['total_alerts']}")
    print(f"🆕 Nuevas: {report['summary']['new_alerts']}")
    print(f"🎯 Atacantes únicos: {report['summary']['unique_attackers']}")
    
    print(f"\n✅ AlertManager funcionando correctamente!")
    print(f"💾 Base de datos creada en: {alert_manager.db_path}")