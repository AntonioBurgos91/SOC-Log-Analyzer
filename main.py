#!/usr/bin/env python3
"""
SOC-Log-Analyzer - Sistema Completo de Análisis de Seguridad
Análisis profesional de logs con detección automática de amenazas
"""

import argparse
import sys
import json
from pathlib import Path
from datetime import datetime

# Importar módulos del proyecto
from parsers.auth_parser import AuthLogParser
from detectors.brute_force import BruteForceDetector
from alerting.alert_manager import AlertManager
from utils.logger import setup_logger

def main():
    """Punto de entrada principal del sistema SOC"""
    
    parser = argparse.ArgumentParser(
        description="🛡️ SOC-Log-Analyzer - Professional Security Analysis System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python main.py --input data/sample_auth.log --analyze
  python main.py --input data/sample_auth.log --analyze --report
  python main.py --dashboard
  python main.py --input data/sample_auth.log --analyze --dashboard
        """
    )
    
    parser.add_argument("--input", "-i", 
                       help="Path to auth.log file")
    parser.add_argument("--analyze", "-a", action="store_true",
                       help="Run complete security analysis")
    parser.add_argument("--dashboard", "-d", action="store_true",
                       help="Launch interactive dashboard")
    parser.add_argument("--report", "-r", action="store_true",
                       help="Generate detailed security report")
    parser.add_argument("--output", "-o", default="output/",
                       help="Output directory for reports")
    parser.add_argument("--threshold", "-t", type=int, default=3,
                       help="Failed attempts threshold for brute force detection")
    parser.add_argument("--time-window", "-w", type=int, default=5,
                       help="Time window in minutes for attack detection")
    
    args = parser.parse_args()
    
    if not args.analyze and not args.dashboard:
        parser.print_help()
        return
    
    # Setup logging
    logger = setup_logger()
    logger.info("🛡️ Iniciando SOC-Log-Analyzer")
    
    try:
        if args.analyze:
            if not args.input:
                print("❌ Error: --input es requerido para análisis")
                return
            
            run_complete_analysis(args.input, args.output, args.threshold, args.time_window, args.report)
        
        if args.dashboard:
            launch_dashboard()
            
    except KeyboardInterrupt:
        logger.info("⏹️ Análisis interrumpido por el usuario")
    except Exception as e:
        logger.error(f"❌ Error durante ejecución: {e}")
        sys.exit(1)

def run_complete_analysis(input_file: str, output_dir: str, threshold: int, time_window: int, generate_report: bool = False):
    """Ejecuta análisis completo de seguridad SOC"""
    
    logger = setup_logger()
    
    print("🔍 INICIANDO ANÁLISIS COMPLETO DE SEGURIDAD SOC")
    print("=" * 60)
    
    # Verificar archivo de entrada
    if not Path(input_file).exists():
        print(f"❌ Error: Archivo {input_file} no encontrado")
        return
    
    # PASO 1: PARSING DE LOGS
    print("📖 Paso 1: Análisis y parsing de logs...")
    parser = AuthLogParser(input_file)
    df = parser.parse()
    
    if df.empty:
        print("❌ No se pudieron extraer eventos del archivo")
        return
    
    stats = parser.get_stats()
    print(f"✅ Eventos procesados: {stats['total_entries']}")
    print(f"📅 Rango temporal: {stats['date_range']['start']} - {stats['date_range']['end']}")
    print(f"🌐 IPs únicas detectadas: {stats['unique_ips']}")
    
    # PASO 2: DETECCIÓN DE AMENAZAS
    print(f"\n🚨 Paso 2: Detección de amenazas (umbral: {threshold} intentos en {time_window}min)...")
    detector = BruteForceDetector(
        failed_threshold=threshold,
        time_window_minutes=time_window,
        distributed_threshold=3
    )
    
    alerts = detector.detect(df)
    print(f"✅ Amenazas detectadas: {len(alerts)} alertas de seguridad generadas")
    
    if not alerts:
        print("ℹ️ No se detectaron amenazas con los umbrales configurados")
        print("💡 Intenta reducir el umbral con --threshold 2")
        return
    
    # PASO 3: GESTIÓN DE ALERTAS
    print(f"\n📋 Paso 3: Gestión profesional de alertas...")
    alert_manager = AlertManager()
    result = alert_manager.ingest_alerts(alerts)
    
    print(f"✅ Alertas procesadas: {result['processed']}")
    print(f"🚫 Alertas filtradas: {result['filtered']}")
    print(f"❌ Errores: {result['errors']}")
    print(f"📊 Alertas activas en sistema: {result['total_active_alerts']}")
    
    # PASO 4: ANÁLISIS Y MÉTRICAS
    print(f"\n📊 Paso 4: Análisis de amenazas y métricas SOC...")
    metrics = alert_manager.get_dashboard_metrics()
    
    print(f"\n🎯 RESUMEN EJECUTIVO DE AMENAZAS")
    print("=" * 60)
    
    # Mostrar distribución por severidad
    if metrics["severity_distribution"]:
        print("📈 Distribución por severidad:")
        for sev in metrics["severity_distribution"]:
            print(f"   {sev['severity']}: {sev['count']} alertas")
    
    # Mostrar top atacantes
    if metrics["top_attackers"]:
        print(f"\n🏆 TOP ATACANTES MÁS PELIGROSOS:")
        for i, attacker in enumerate(metrics["top_attackers"][:5], 1):
            print(f"   {i}. {attacker['source_ip']} - {attacker['alert_count']} alertas (max: {attacker['max_severity']})")
    
    # Mostrar alertas críticas
    critical_alerts = [alert for alert in alerts if alert.severity == "CRITICAL"]
    if critical_alerts:
        print(f"\n🚨 ALERTAS CRÍTICAS DETECTADAS ({len(critical_alerts)}):")
        print("-" * 60)
        for alert in critical_alerts[:3]:  # Mostrar top 3
            print(f"🔴 {alert.alert_type} | IP: {alert.source_ip}")
            print(f"   📝 {alert.description}")
            print(f"   💡 {alert.recommendation}")
            print(f"   🏷️ MITRE: {alert.mitre_technique}")
            print()
    
    # PASO 5: RECOMENDACIONES
    print(f"💡 RECOMENDACIONES DE SEGURIDAD:")
    recommendations = [
        "Implementar bloqueo automático de IPs con múltiples intentos fallidos",
        "Revisar políticas de autenticación para cuentas objetivo",
        "Considerar implementar fail2ban o herramientas similares",
        "Monitorear logins exitosos desde IPs marcadas como maliciosas",
        "Configurar alertas en tiempo real para ataques críticos"
    ]
    
    for i, rec in enumerate(recommendations, 1):
        print(f"   {i}. {rec}")
    
    # PASO 6: GENERAR REPORTE (OPCIONAL)
    if generate_report:
        print(f"\n📄 Paso 5: Generando reporte detallado...")
        report_data = generate_detailed_report(alert_manager, alerts, stats, metrics)
        save_report(report_data, output_dir)
        print(f"✅ Reporte guardado en: {output_dir}/security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    
    print(f"\n✅ ANÁLISIS COMPLETADO EXITOSAMENTE")
    print(f"💾 Base de datos de alertas: output/soc_alerts.db")
    print(f"📊 Dashboard disponible con: python main.py --dashboard")
    print("=" * 60)

def generate_detailed_report(alert_manager, alerts, stats, metrics):
    """Genera reporte detallado del análisis"""
    
    return {
        "report_metadata": {
            "generated_at": datetime.now().isoformat(),
            "analysis_version": "SOC-Log-Analyzer v1.0",
            "analyst": "Automated SOC System"
        },
        "executive_summary": {
            "total_events_analyzed": stats["total_entries"],
            "unique_ips_detected": stats["unique_ips"],
            "total_alerts_generated": len(alerts),
            "critical_alerts": len([a for a in alerts if a.severity == "CRITICAL"]),
            "high_alerts": len([a for a in alerts if a.severity == "HIGH"]),
            "medium_alerts": len([a for a in alerts if a.severity == "MEDIUM"]),
            "unique_attackers": metrics["general_stats"]["unique_attackers"]
        },
        "threat_analysis": {
            "severity_distribution": metrics["severity_distribution"],
            "top_attackers": metrics["top_attackers"],
            "attack_timeline": stats["date_range"]
        },
        "detailed_alerts": [
            {
                "alert_id": alert.alert_id,
                "timestamp": alert.timestamp.isoformat(),
                "severity": alert.severity,
                "type": alert.alert_type,
                "source_ip": alert.source_ip,
                "description": alert.description,
                "evidence": alert.evidence,
                "recommendation": alert.recommendation,
                "mitre_technique": alert.mitre_technique
            }
            for alert in alerts
        ],
        "recommendations": alert_manager.generate_report()["recommendations"]
    }

def save_report(report_data, output_dir):
    """Guarda reporte en formato JSON"""
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"security_report_{timestamp}.json"
    file_path = output_path / filename
    
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)

def launch_dashboard():
    """Lanza dashboard interactivo de Streamlit"""
    
    import subprocess
    import os
    
    print("🚀 Lanzando dashboard interactivo SOC...")
    print("🌐 Dashboard estará disponible en: http://localhost:8501")
    print("⏹️ Presiona Ctrl+C para detener el dashboard")
    
    try:
        # Verificar si streamlit está instalado
        subprocess.run([sys.executable, "-c", "import streamlit"], check=True, capture_output=True)
        
        # Cambiar al directorio del proyecto
        os.chdir(Path(__file__).parent)
        
        # Crear dashboard básico si no existe
        if not Path("dashboard/app.py").exists():
            create_basic_dashboard()
        
        # Lanzar Streamlit
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", 
            "dashboard/app.py",
            "--server.headless", "true",
            "--browser.gatherUsageStats", "false",
            "--server.port", "8501"
        ])
    
    except subprocess.CalledProcessError:
        print("❌ Error: Streamlit no está instalado")
        print("💡 Instala con: pip install streamlit")
        print("🔄 Luego ejecuta: python main.py --dashboard")
    except FileNotFoundError:
        print("❌ Error: No se pudo encontrar Python")
    except Exception as e:
        print(f"❌ Error lanzando dashboard: {e}")

def create_basic_dashboard():
    """Crea dashboard básico si no existe"""
    
    dashboard_code = '''
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import sys
sys.path.append('..')

from alerting.alert_manager import AlertManager

st.set_page_config(
    page_title="SOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SOC Dashboard - Security Operations Center")
st.markdown("**Real-time Security Threat Analysis**")

# Cargar datos
alert_manager = AlertManager()
metrics = alert_manager.get_dashboard_metrics()
alerts_df = alert_manager.get_alerts()

# Métricas principales
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("🚨 Total Alertas", metrics["general_stats"]["total_alerts"])

with col2:
    st.metric("🆕 Nuevas", metrics["general_stats"]["new_alerts"])

with col3:
    st.metric("🎯 Atacantes", metrics["general_stats"]["unique_attackers"])

with col4:
    st.metric("📅 Últimas 24h", metrics["general_stats"]["alerts_24h"])

# Gráfico de severidad
if metrics["severity_distribution"]:
    st.subheader("📊 Distribución por Severidad")
    severity_df = pd.DataFrame(metrics["severity_distribution"])
    
    fig = px.bar(severity_df, x="severity", y="count", 
                title="Alertas por Severidad",
                color="severity",
                color_discrete_map={
                    "CRITICAL": "#FF4B4B",
                    "HIGH": "#FF8C00", 
                    "MEDIUM": "#FFD700",
                    "LOW": "#90EE90"
                })
    st.plotly_chart(fig, use_container_width=True)

# Top atacantes
if metrics["top_attackers"]:
    st.subheader("🏆 Top Atacantes")
    attackers_df = pd.DataFrame(metrics["top_attackers"])
    st.dataframe(attackers_df, use_container_width=True)

# Alertas recientes
if not alerts_df.empty:
    st.subheader("🚨 Alertas Recientes")
    display_cols = ['timestamp', 'severity', 'alert_type', 'source_ip', 'description']
    st.dataframe(alerts_df[display_cols].head(10), use_container_width=True)

st.markdown("---")
st.markdown("🔄 **Última actualización:** " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
'''
    
    dashboard_path = Path("dashboard/app.py")
    dashboard_path.parent.mkdir(exist_ok=True)
    
    with open(dashboard_path, 'w', encoding='utf-8') as f:
        f.write(dashboard_code)

if __name__ == "__main__":
    main()