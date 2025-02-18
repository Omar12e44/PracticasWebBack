import psycopg2

# Configuración de la conexión a PostgreSQL
dbname = 'web'      # Nombre de la base de datos
user = 'postgres'                # Usuario de PostgreSQL
password = 'root'       # Contraseña de PostgreSQL
host = 'localhost'               # Dirección del servidor (localhost si es local)
port = '5432'                   # Puerto de PostgreSQL

# Establecer la conexión
conn = psycopg2.connect(
    dbname=dbname,
    user=user,
    password=password,
    host=host,
    port=port
)


def get_db_connection():
    conn = psycopg2.connect(
        dbname=dbname,
        user=user,
        password=password,
        host=host,
        port=port
    )
    return conn
# Crear un cursor para ejecutar consultas
cursor = conn.cursor()

# Puedes hacer alguna operación, por ejemplo:
cursor.execute("SELECT version();")

# Obtener el resultado de la consulta
result = cursor.fetchone()

# Mostrar el resultado
print("Conexión exitosa. Versión de PostgreSQL:", result)

# Cerrar el cursor y la conexión
cursor.close()
conn.close()
