from graphviz import Digraph

dot = Digraph("ArquitecturaSistemaMonitoreo", format="png")

# Nodo de usuario
dot.node("Usuario", "Admin / Usuario")

# Interfaz
dot.node("UI", "UI - Dashboard")
dot.node("Mobile", "Cliente Móvil")

# Backend y almacenamiento
dot.node("Backend", "Backend Express.js Core")
dot.node("DB", "Base de Datos")
dot.node("Logs", "Módulo de Alertas y Logs")
dot.node("ML", "Análisis con ML")

# Relaciones
dot.edge("Usuario", "UI", label="Interacción")
dot.edge("Mobile", "UI", label="Acceso móvil")
dot.edge("UI", "Backend", label="Consulta API")
dot.edge("Backend", "DB", label="Almacenamiento")
dot.edge("Backend", "ML", label="Análisis")
dot.edge("ML", "Logs", label="Notificaciones")

# Guardar como PNG
dot.render(r"C:\Users\Omarb\OneDrive\Documentos\Escritorio\diagrama_monitoreo")

