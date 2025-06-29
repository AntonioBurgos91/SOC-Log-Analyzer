import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np
from datetime import datetime, timedelta
import sys
import time
import random
sys.path.append('..')

from alerting.alert_manager import AlertManager

# Configuración de página
st.set_page_config(
    page_title="SOC Cyber Defense Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS personalizado para hacer más profesional
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .metric-container {
        background: #0E1117;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #FF6B6B;
        margin: 0.5rem 0;
    }
    .critical-alert {
        background-color: #FF4B4B;
        color: white;
        padding: 0.5rem;
        border-radius: 0.25rem;
        margin: 0.25rem 0;
    }
    .high-alert {
        background-color: #FF8C00;
        color: white;
        padding: 0.5rem;
        border-radius: 0.25rem;
        margin: 0.25rem 0;
    }
    .medium-alert {
        background-color: #FFD700;
        color: black;
        padding: 0.5rem;
        border-radius: 0.25rem;
        margin: 0.25rem 0;
    }
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #1e3c72 0%, #2a5298 100%);
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #0E1117;
        border: 1px solid #262730;
        border-radius: 4px 4px 0px 0px;
    }
</style>
""", unsafe_allow_html=True)

# Funciones para generar datos simulados adicionales
@st.cache_data(ttl=60)  # Cache por 1 minuto
def generate_geographical_data():
    """Genera datos geográficos simulados para el mapa"""
    countries = [
        {"country": "United States", "lat": 39.8283, "lon": -98.5795, "attacks": 45, "severity": "HIGH"},
        {"country": "China", "lat": 35.8617, "lon": 104.1954, "attacks": 156, "severity": "CRITICAL"},
        {"country": "Russia", "lat": 61.5240, "lon": 105.3188, "attacks": 89, "severity": "HIGH"},
        {"country": "Brazil", "lat": -14.2350, "lon": -51.9253, "attacks": 34, "severity": "MEDIUM"},
        {"country": "India", "lat": 20.5937, "lon": 78.9629, "attacks": 67, "severity": "HIGH"},
        {"country": "Germany", "lat": 51.1657, "lon": 10.4515, "attacks": 23, "severity": "LOW"},
        {"country": "United Kingdom", "lat": 55.3781, "lon": -3.4360, "attacks": 18, "severity": "LOW"},
        {"country": "France", "lat": 46.6034, "lon": 1.8883, "attacks": 12, "severity": "LOW"},
        {"country": "South Korea", "lat": 35.9078, "lon": 127.7669, "attacks": 29, "severity": "MEDIUM"},
        {"country": "Iran", "lat": 32.4279, "lon": 53.6880, "attacks": 78, "severity": "HIGH"},
        {"country": "Vietnam", "lat": 14.0583, "lon": 108.2772, "attacks": 45, "severity": "MEDIUM"},
        {"country": "North Korea", "lat": 40.3399, "lon": 127.5101, "attacks": 23, "severity": "HIGH"}
    ]
    return pd.DataFrame(countries)

@st.cache_data(ttl=30)
def generate_timeline_data():
    """Genera datos de timeline para las últimas 24 horas"""
    base_time = datetime.now() - timedelta(hours=24)
    timeline_data = []
    
    for i in range(48):  # Cada 30 minutos
        timestamp = base_time + timedelta(minutes=30*i)
        attacks = random.randint(2, 25)  # Más ataques para datos masivos
        blocked = random.randint(int(attacks*0.6), attacks)
        
        timeline_data.append({
            'timestamp': timestamp,
            'attacks_detected': attacks,
            'attacks_blocked': blocked,
            'successful_blocks': blocked / max(attacks, 1) * 100
        })
    
    return pd.DataFrame(timeline_data)

@st.cache_data(ttl=60)
def generate_threat_intelligence_data():
    """Genera datos de threat intelligence"""
    threat_types = [
        {"type": "SSH Brute Force", "count": 245, "trend": "↗️", "risk": "CRITICAL"},
        {"type": "Web Application Attack", "count": 132, "trend": "↘️", "risk": "HIGH"},
        {"type": "DDoS Attempt", "count": 89, "trend": "→", "risk": "HIGH"},
        {"type": "Malware Download", "count": 67, "trend": "↗️", "risk": "CRITICAL"},
        {"type": "Port Scanning", "count": 456, "trend": "↗️", "risk": "MEDIUM"},
        {"type": "SQL Injection", "count": 34, "trend": "↘️", "risk": "HIGH"},
        {"type": "User Enumeration", "count": 178, "trend": "↗️", "risk": "MEDIUM"},
        {"type": "Credential Stuffing", "count": 89, "trend": "→", "risk": "HIGH"}
    ]
    return pd.DataFrame(threat_types)

def get_country_from_ip(ip):
    """Determina país basado en IP"""
    if pd.isna(ip):
        return "Unknown"
    
    ip_str = str(ip)
    
    # IPs chinas
    if any(ip_str.startswith(prefix) for prefix in ["118.25", "123.207", "101.132", "47.75", "139.196"]):
        return "China"
    
    # IPs rusas
    elif any(ip_str.startswith(prefix) for prefix in ["185.220", "194.87", "109.248", "46.166", "95.181"]):
        return "Russia"
    
    # IPs indias
    elif any(ip_str.startswith(prefix) for prefix in ["103.251", "117.239", "182.71"]):
        return "India"
    
    # IPs vietnamitas
    elif any(ip_str.startswith(prefix) for prefix in ["103.97", "113.160", "125.212"]):
        return "Vietnam"
    
    # IPs iraníes
    elif any(ip_str.startswith(prefix) for prefix in ["2.177", "5.160", "91.98", "185.51"]):
        return "Iran"
    
    # IPs norcoreanas
    elif any(ip_str.startswith(prefix) for prefix in ["175.45", "210.52", "115.85"]):
        return "North Korea"
    
    # IPs brasileñas
    elif any(ip_str.startswith(prefix) for prefix in ["177.54", "189.84", "201.20"]):
        return "Brazil"
    
    # IPs estadounidenses
    elif any(ip_str.startswith(prefix) for prefix in ["167.71", "134.209", "207.154", "159.89"]):
        return "United States"
    
    # IPs alemanas
    elif any(ip_str.startswith(prefix) for prefix in ["46.4", "85.214", "176.9"]):
        return "Germany"
    
    # IPs internas
    elif any(ip_str.startswith(prefix) for prefix in ["192.168", "10.0", "172.16"]):
        return "Internal Network"
    
    else:
        return "Unknown"

def main():
    # Header principal
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ SOC Cyber Defense Center</h1>
        <p><strong>Real-time Security Operations & Threat Intelligence Platform</strong></p>
        <p>🔴 LIVE • Monitoring 24/7 • Last Updated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
    </div>
    """, unsafe_allow_html=True)

    # Sidebar para controles
    st.sidebar.header("🔧 SOC Controls")
    
    # Auto-refresh
    auto_refresh = st.sidebar.checkbox("🔄 Auto-refresh (30s)", value=False)
    if auto_refresh:
        time.sleep(30)
        st.rerun()
    
    # Filtros de tiempo
    time_range = st.sidebar.selectbox(
        "📅 Time Range",
        ["Last Hour", "Last 6 Hours", "Last 24 Hours", "Last Week", "Last Month"],
        index=2
    )
    
    # Filtros de severidad
    severity_filter = st.sidebar.multiselect(
        "⚠️ Severity Filter",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM"]
    )
    
    # Filtros de tipo de ataque
    attack_type_filter = st.sidebar.multiselect(
        "🎯 Attack Type Filter",
        ["SSH_BRUTE_FORCE", "USER_ENUMERATION", "WEB_ATTACK", "MALWARE", "DDOS"],
        default=["SSH_BRUTE_FORCE", "USER_ENUMERATION"]
    )
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📊 System Status")
    st.sidebar.success("🟢 All Systems Operational")
    st.sidebar.info("🔵 Database: Connected")
    st.sidebar.info("🔵 Threat Intel: Active")
    st.sidebar.warning("🟡 High Alert Volume")

    # Cargar datos reales
    try:
        alert_manager = AlertManager()
        metrics = alert_manager.get_dashboard_metrics()
        alerts_df = alert_manager.get_alerts()
    except Exception as e:
        st.error(f"Error loading data: {e}")
        st.stop()
    
    # Generar datos adicionales
    geo_data = generate_geographical_data()
    timeline_data = generate_timeline_data()
    threat_intel = generate_threat_intelligence_data()

    # Tabs principales
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🏠 Overview", "🗺️ Threat Map", "📈 Analytics", "🚨 Alerts", "🧠 Threat Intel"
    ])

    with tab1:
        # === OVERVIEW TAB ===
        st.subheader("📊 Security Operations Overview")
        
        # Métricas principales en tiempo real
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            total_alerts = metrics["general_stats"]["total_alerts"]
            st.metric(
                label="🚨 Total Alerts",
                value=total_alerts,
                delta=f"+{random.randint(5, 15)} today"
            )
        
        with col2:
            new_alerts = metrics["general_stats"]["new_alerts"]
            st.metric(
                label="🆕 New Alerts",
                value=new_alerts,
                delta=f"+{random.randint(2, 8)} last hour"
            )
        
        with col3:
            unique_attackers = metrics["general_stats"]["unique_attackers"]
            st.metric(
                label="🎯 Active Threats",
                value=unique_attackers,
                delta=f"+{random.randint(1, 5)} today"
            )
        
        with col4:
            # Calcular MTTR simulado
            mttr_minutes = random.randint(8, 15)
            st.metric(
                label="⏱️ MTTR (minutes)",
                value=f"{mttr_minutes}",
                delta=f"-{random.randint(1, 3)}min"
            )
        
        with col5:
            # Efectividad de bloqueo
            block_rate = random.randint(87, 95)
            st.metric(
                label="🛡️ Block Rate",
                value=f"{block_rate}%",
                delta=f"+{random.randint(1, 3)}%"
            )

        # Gráficos principales
        col1, col2 = st.columns(2)
        
        with col1:
            # Gráfico de severidad mejorado
            if metrics["severity_distribution"]:
                st.subheader("📊 Alert Severity Distribution")
                severity_df = pd.DataFrame(metrics["severity_distribution"])
                
                fig = px.pie(
                    severity_df, 
                    values="count", 
                    names="severity",
                    title="Current Alert Distribution",
                    color="severity",
                    color_discrete_map={
                        "CRITICAL": "#FF4B4B",
                        "HIGH": "#FF8C00", 
                        "MEDIUM": "#FFD700",
                        "LOW": "#90EE90"
                    },
                    hole=0.4
                )
                fig.update_layout(
                    showlegend=True,
                    height=400,
                    annotations=[dict(text='Alerts', x=0.5, y=0.5, font_size=20, showarrow=False)]
                )
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Timeline de actividad reciente
            st.subheader("📈 Attack Activity Timeline (24h)")
            
            fig = px.line(
                timeline_data.tail(24), 
                x="timestamp", 
                y="attacks_detected",
                title="Attacks Detected Over Time",
                line_shape="spline"
            )
            fig.add_scatter(
                x=timeline_data.tail(24)["timestamp"],
                y=timeline_data.tail(24)["attacks_blocked"],
                mode="lines+markers",
                name="Blocked",
                line=dict(color="green")
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

        # Top atacantes expandido
        st.subheader("🏆 Top Threat Actors")
        if metrics["top_attackers"]:
            attackers_df = pd.DataFrame(metrics["top_attackers"])
            
            # CORRECCIÓN: Generar países dinámicamente basado en IPs
            countries_list = []
            last_seen_list = []
            threat_scores_list = []
            
            for ip in attackers_df["source_ip"]:
                # Asignar país basado en IP
                countries_list.append(get_country_from_ip(ip))
                
                # Generar timestamp aleatorio
                last_seen_list.append(
                    datetime.now() - timedelta(minutes=random.randint(5, 120))
                )
                
                # Generar threat score
                threat_scores_list.append(random.randint(70, 95))
            
            attackers_df["country"] = countries_list
            attackers_df["last_seen"] = last_seen_list
            attackers_df["threat_score"] = threat_scores_list
            
            # Mostrar tabla mejorada
            st.dataframe(
                attackers_df,
                column_config={
                    "source_ip": "🎯 Source IP",
                    "alert_count": st.column_config.NumberColumn("📊 Alerts", format="%d"),
                    "max_severity": "⚠️ Max Severity",
                    "country": "🌍 Country",
                    "last_seen": st.column_config.DatetimeColumn("🕐 Last Seen"),
                    "threat_score": st.column_config.ProgressColumn("🔥 Threat Score", min_value=0, max_value=100)
                },
                use_container_width=True,
                hide_index=True
            )

    with tab2:
        # === THREAT MAP TAB ===
        st.subheader("🗺️ Global Threat Intelligence Map")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            # Mapa mundial de ataques
            fig = px.scatter_geo(
                geo_data,
                lat="lat",
                lon="lon",
                size="attacks",
                color="severity",
                hover_name="country",
                hover_data={"attacks": True, "severity": True},
                title="Global Attack Sources (Last 24h)",
                color_discrete_map={
                    "CRITICAL": "#FF4B4B",
                    "HIGH": "#FF8C00", 
                    "MEDIUM": "#FFD700",
                    "LOW": "#90EE90"
                },
                size_max=50
            )
            fig.update_layout(height=500)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("### 🌍 Geographic Statistics")
            
            # Estadísticas por región
            regions = {
                "🇺🇸 Americas": geo_data[geo_data["country"].isin(["United States", "Brazil"])]["attacks"].sum(),
                "🇪🇺 Europe": geo_data[geo_data["country"].isin(["Germany", "United Kingdom", "France"])]["attacks"].sum(),
                "🇨🇳 Asia-Pacific": geo_data[geo_data["country"].isin(["China", "India", "South Korea", "Vietnam"])]["attacks"].sum(),
                "🇷🇺 Russia/CIS": geo_data[geo_data["country"] == "Russia"]["attacks"].sum(),
                "🇮🇷 Middle East": geo_data[geo_data["country"] == "Iran"]["attacks"].sum()
            }
            
            for region, count in regions.items():
                st.metric(region, count)
            
            st.markdown("### 🔥 High-Risk Countries")
            high_risk = geo_data[geo_data["severity"].isin(["CRITICAL", "HIGH"])].sort_values("attacks", ascending=False)
            
            for _, country in high_risk.head(5).iterrows():
                severity_color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
                st.markdown(f"{severity_color[country['severity']]} **{country['country']}**: {country['attacks']} attacks")

    with tab3:
        # === ANALYTICS TAB ===
        st.subheader("📈 Advanced Security Analytics")
        
        # Métricas de rendimiento SOC
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("### ⚡ SOC Performance")
            
            # Crear gauge chart para MTTR
            fig = go.Figure(go.Indicator(
                mode = "gauge+number+delta",
                value = mttr_minutes,
                domain = {'x': [0, 1], 'y': [0, 1]},
                title = {'text': "MTTR (minutes)"},
                delta = {'reference': 20},
                gauge = {
                    'axis': {'range': [None, 30]},
                    'bar': {'color': "darkblue"},
                    'steps': [
                        {'range': [0, 10], 'color': "lightgray"},
                        {'range': [10, 20], 'color': "gray"}],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 25}}))
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("### 🎯 Detection Accuracy")
            
            # Accuracy metrics
            accuracy_data = {
                "Metric": ["True Positives", "False Positives", "True Negatives", "False Negatives"],
                "Value": [85, 8, 92, 3],
                "Percentage": ["85%", "8%", "92%", "3%"]
            }
            accuracy_df = pd.DataFrame(accuracy_data)
            
            fig = px.bar(
                accuracy_df, 
                x="Metric", 
                y="Value",
                title="Detection Performance",
                color="Value",
                color_continuous_scale="RdYlGn"
            )
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
        
        with col3:
            st.markdown("### 📊 Attack Patterns")
            
            # Patrón de ataques por hora
            hourly_attacks = [random.randint(10, 45) for _ in range(24)]
            hours = list(range(24))
            
            fig = px.line(
                x=hours,
                y=hourly_attacks,
                title="Attacks by Hour of Day",
                labels={"x": "Hour", "y": "Attacks"}
            )
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)

        # Análisis de tendencias avanzado
        st.subheader("📊 Trend Analysis & Forecasting")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Trend de los últimos 7 días
            days = pd.date_range(start=datetime.now() - timedelta(days=7), end=datetime.now(), freq='D')
            daily_attacks = [random.randint(150, 350) for _ in range(len(days))]
            
            trend_df = pd.DataFrame({"date": days, "attacks": daily_attacks})
            
            fig = px.line(
                trend_df,
                x="date",
                y="attacks",
                title="7-Day Attack Trend",
                line_shape="spline"
            )
            
            # Añadir línea de tendencia
            z = np.polyfit(range(len(daily_attacks)), daily_attacks, 1)
            p = np.poly1d(z)
            fig.add_scatter(
                x=trend_df["date"],
                y=p(range(len(daily_attacks))),
                mode="lines",
                name="Trend Line",
                line=dict(dash="dash", color="red")
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Predicción simple
            st.markdown("### 🔮 Attack Prediction")
            
            # Simulación de predicción
            future_days = 3
            future_dates = pd.date_range(start=datetime.now() + timedelta(days=1), periods=future_days, freq='D')
            predicted_attacks = [int(p(len(daily_attacks) + i)) for i in range(1, future_days + 1)]
            
            prediction_df = pd.DataFrame({
                "Date": future_dates.strftime("%Y-%m-%d"),
                "Predicted Attacks": predicted_attacks,
                "Confidence": ["High", "Medium", "Low"]
            })
            
            st.dataframe(prediction_df, use_container_width=True, hide_index=True)
            
            # Alertas predictivas
            if max(predicted_attacks) > 300:
                st.error("⚠️ High attack volume predicted for tomorrow!")
            else:
                st.success("✅ Normal attack levels expected")

    with tab4:
        # === ALERTS TAB ===
        st.subheader("🚨 Active Security Alerts")
        
        # Filtros de alertas
        col1, col2, col3 = st.columns(3)
        
        with col1:
            status_filter = st.selectbox("📋 Status", ["All", "NEW", "INVESTIGATING", "RESOLVED"])
        
        with col2:
            severity_display = st.selectbox("⚠️ Severity", ["All"] + severity_filter)
        
        with col3:
            source_ip_filter = st.text_input("🎯 Source IP Filter", placeholder="192.168.1.100")

        # Mostrar alertas críticas destacadas
        if not alerts_df.empty:
            critical_alerts = alerts_df[alerts_df['severity'] == 'CRITICAL']
            
            if not critical_alerts.empty:
                st.markdown("### 🔴 CRITICAL ALERTS - IMMEDIATE ACTION REQUIRED")
                
                for _, alert in critical_alerts.iterrows():
                    with st.expander(f"🚨 {alert['alert_type']} - {alert['source_ip']}", expanded=True):
                        col1, col2 = st.columns([3, 1])
                        
                        with col1:
                            st.markdown(f"**Description:** {alert['description']}")
                            st.markdown(f"**Recommendation:** {alert['recommendation']}")
                            st.markdown(f"**MITRE ATT&CK:** {alert['mitre_technique']}")
                            
                            # Mostrar evidencia
                            if isinstance(alert['evidence'], dict):
                                st.markdown("**Evidence:**")
                                for key, value in alert['evidence'].items():
                                    st.markdown(f"- {key}: {value}")
                        
                        with col2:
                            st.markdown(f"**Severity:** `{alert['severity']}`")
                            st.markdown(f"**Timestamp:** {alert['timestamp']}")
                            st.markdown(f"**Status:** `{alert['status']}`")
                            
                            # Botones de acción
                            col_a, col_b = st.columns(2)
                            with col_a:
                                if st.button(f"🔍 Investigate", key=f"investigate_{alert['id']}"):
                                    st.success("Status updated to 'INVESTIGATING'")
                            
                            with col_b:
                                if st.button(f"✅ Resolve", key=f"resolve_{alert['id']}"):
                                    st.success("Status updated to 'RESOLVED'")
            
            # Tabla de todas las alertas con filtros aplicados
            st.markdown("### 📋 All Security Alerts")
            
            filtered_df = alerts_df.copy()
            
            # Aplicar filtros
            if status_filter != "All":
                filtered_df = filtered_df[filtered_df['status'] == status_filter]
            
            if severity_display != "All":
                filtered_df = filtered_df[filtered_df['severity'] == severity_display]
            
            if source_ip_filter:
                filtered_df = filtered_df[filtered_df['source_ip'].str.contains(source_ip_filter, na=False)]
            
            if not filtered_df.empty:
                # Configurar columnas para mostrar
                display_columns = ['timestamp', 'severity', 'alert_type', 'source_ip', 'description', 'status']
                display_df = filtered_df[display_columns].copy()
                display_df['timestamp'] = pd.to_datetime(display_df['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
                
                st.dataframe(
                    display_df,
                    column_config={
                        "timestamp": "🕐 Timestamp",
                        "severity": st.column_config.TextColumn("⚠️ Severity"),
                        "alert_type": "🔍 Type",
                        "source_ip": "🎯 Source IP",
                        "description": "📝 Description",
                        "status": st.column_config.TextColumn("📋 Status")
                    },
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.info("No alerts match the current filters")

    with tab5:
        # === THREAT INTEL TAB ===
        st.subheader("🧠 Threat Intelligence & Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🎯 Attack Types Analysis")
            
            fig = px.bar(
                threat_intel,
                x="type",
                y="count",
                color="risk",
                title="Attack Types in Last 24h",
                color_discrete_map={
                    "CRITICAL": "#FF4B4B",
                    "HIGH": "#FF8C00", 
                    "MEDIUM": "#FFD700",
                    "LOW": "#90EE90"
                }
            )
            fig.update_xaxes(tickangle=45)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("### 📈 Threat Trends")
            
            for _, threat in threat_intel.iterrows():
                trend_color = {"↗️": "red", "↘️": "green", "→": "orange"}
                risk_color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
                
                st.markdown(f"""
                **{threat['type']}** {risk_color[threat['risk']]}  
                Count: {threat['count']} | Trend: {threat['trend']} | Risk: {threat['risk']}
                """)
        
        # IOCs (Indicators of Compromise)
        st.markdown("### 🔍 Latest IOCs (Indicators of Compromise)")
        
        iocs_data = {
            "Type": ["IP Address", "Domain", "File Hash", "URL", "Email", "IP Address", "Domain", "File Hash"],
            "IOC": ["118.25.6.39", "malicious-site.com", "d41d8cd98f00b204e9800998ecf8427e", "http://bad-site.com/malware", "phishing@evil.com", "185.220.101.182", "apt-command.org", "a1b2c3d4e5f6789012345"],
            "Threat Level": ["CRITICAL", "HIGH", "CRITICAL", "HIGH", "MEDIUM", "CRITICAL", "HIGH", "CRITICAL"],
            "Last Seen": ["30 min ago", "2 hours ago", "15 min ago", "1 hour ago", "4 hours ago", "45 min ago", "3 hours ago", "20 min ago"],
            "Source": ["Internal Detection", "VirusTotal", "Internal Detection", "URLVoid", "PhishTank", "Internal Detection", "ThreatFox", "Internal Detection"]
        }
        
        iocs_df = pd.DataFrame(iocs_data)
        st.dataframe(
            iocs_df,
            column_config={
                "Type": "🔍 IOC Type",
                "IOC": "📋 Indicator",
                "Threat Level": st.column_config.TextColumn("⚠️ Threat Level"),
                "Last Seen": "🕐 Last Seen",
                "Source": "📡 Source"
            },
            use_container_width=True,
            hide_index=True
        )
        
        # Threat Intelligence Feeds
        st.markdown("### 📡 Threat Intelligence Feeds Status")
        
        feeds_status = {
            "Feed": ["VirusTotal", "AbuseIPDB", "Malware Bazaar", "PhishTank", "URLVoid", "Shodan", "ThreatFox", "AlienVault OTX"],
            "Status": ["🟢 Active", "🟢 Active", "🟡 Delayed", "🟢 Active", "🔴 Down", "🟢 Active", "🟢 Active", "🟢 Active"],
            "Last Update": ["2 min ago", "1 min ago", "15 min ago", "30 sec ago", "2 hours ago", "1 min ago", "45 sec ago", "3 min ago"],
            "IOCs Today": [2341, 1876, 234, 156, 0, 3456, 1123, 987]
        }
        
        feeds_df = pd.DataFrame(feeds_status)
        st.dataframe(feeds_df, use_container_width=True, hide_index=True)

    # Footer con información del sistema
    st.markdown("---")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("**🔄 Last Update:**")
        st.markdown(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    with col2:
        st.markdown("**📊 System Status:**")
        st.markdown("🟢 All Systems Operational")
    
    with col3:
        st.markdown("**⚡ Performance:**")
        st.markdown(f"Response Time: {random.randint(1, 5)}ms")
    
    with col4:
        st.markdown("**🛡️ SOC-Log-Analyzer:**")
        st.markdown("v2.0 Enterprise Edition")

if __name__ == "__main__":
    main()