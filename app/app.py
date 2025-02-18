from flask import Flask , jsonify, request
import jwt
import datetime
from flask_cors import CORS
from database.conexion import get_db_connection
from werkzeug.security import generate_password_hash, check_password_hash
import firebase_admin
from firebase_admin import credentials, firestore


app = Flask(__name__)
CORS(app)

cred = credentials.Certificate("./taskapp-64fc4-firebase-adminsdk-fbsvc-090df849e3.json")
firebase_admin.initialize_app(cred)

db = firestore.client()

users = []

valid_username = 'admin'
valid_password = 'password'
secret_key = 'my_secret_key'

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    # Buscar usuario por email
    users_ref = db.collection("Users").where("email", "==", email).stream()
    user_doc = None
    for doc in users_ref:
        user_doc = doc.to_dict()
        user_doc["id"] = doc.id
        break  # tomamos el primero que coincida

    if not user_doc:
        return jsonify(statusCode=401, intMessage='Usuario no encontrado', data={})

    # Verificar la contraseña
    if not check_password_hash(user_doc['password'], password):
        return jsonify(statusCode=401, intMessage='Contraseña incorrecta', data={})

    # Generar token JWT
    token = jwt.encode(
        {
            'user_id': user_doc['id'],
            'email': user_doc['email'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
        },
        secret_key,
        algorithm='HS256'
    )

    # Actualizar campo last_login
    db.collection("Users").document(user_doc['id']).update({
        "last_login": datetime.datetime.utcnow()
    })

    return jsonify(
        statusCode=200,
        intMessage='Login exitoso',
        data={'token': token}
    )

# @app.route('/login', methods=['POST'])
# def login():
#     data = request.json
#     username = data.get('username')
#     password = data.get('password')

#     # Establecer la conexión a la base de datos
#     conn = get_db_connection()
#     cursor = conn.cursor()

#     # Buscar el usuario en la base de datos
#     cursor.execute("SELECT id, username, password FROM usuarios WHERE username = %s", (username,))
#     user = cursor.fetchone()

#     if user:
#         user_id, db_username, db_password = user  # Extraer los datos

#         # Verificar la contraseña hasheada
#         if check_password_hash(db_password, password):
#             token = jwt.encode(
#                 {
#                     'user_id': user_id,
#                     'username': db_username,
#                     'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
#                 },
#                 secret_key,
#                 algorithm='HS256'
#             )
#             return jsonify(
#                 statusCode=200,
#                 intMessage='Login successful',
#                 data={'token': token}
#             )

#     return jsonify(
#         statusCode=401,
#         intMessage='Invalid username or password',
#         data={}
#     )


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    rol = data.get('rol')

    # Verificar campos obligatorios
    if not username or not email or not password or not rol:
        return jsonify(statusCode=400, intMessage="Todos los campos son obligatorios", data={})

    # Hashear la contraseña
    hashed_password = generate_password_hash(password)

    # Verificar si el usuario ya existe (buscando por email)
    users_ref = db.collection("Users").where("email", "==", email).stream()
    if any(users_ref):
        return jsonify(statusCode=409, intMessage="El usuario ya existe", data={})

    # Crear documento en la colección "Users"
    new_user = {
        "userName": username,
        "email": email,
        "password": hashed_password,
        "last_login": None,
        "rol": rol,
        "created_at": datetime.datetime.utcnow()
    }

    db.collection("Users").add(new_user)

    return jsonify(statusCode=201, intMessage="Usuario registrado exitosamente", data={})



# @app.route('/register', methods=['POST'])
# def register():
#     data = request.json
#     username = data.get('username')
#     password = data.get('password')
#     email = data.get('email')
#     birth_date = data.get('birth_date')
#     full_name = data.get('full_name')
    
#     hashed_password = generate_password_hash(password)


#     # Establecer la conexión a la base de datos
#     conn = get_db_connection()
#     cursor = conn.cursor()

#     cursor.execute("SELECT * FROM usuarios WHERE username = %s OR email = %s", (username, email))
#     existing_user = cursor.fetchone()

#     if existing_user:
#         cursor.close()
#         conn.close()
#         return jsonify(
#             statusCode=400,
#             intMessage='Username or email already exists',
#             data={}
#         )

#     # Crear el hash de la contraseña
#     hashed_password = generate_password_hash(password)

#     # Insertar el nuevo usuario en la base de datos
#     cursor.execute("""
#         INSERT INTO usuarios (username, password, email, birth_date, full_name)
#         VALUES (%s, %s, %s, %s, %s)
#         RETURNING id, username, email, birth_date, full_name
#     """, (username, hashed_password, email, birth_date, full_name))
    
#     # Obtener los datos del nuevo usuario insertado
#     new_user = cursor.fetchone()

#     # Confirmar la transacción
#     conn.commit()

#     # Cerrar el cursor y la conexión
#     cursor.close()
#     conn.close()

#     new_user_data = {
#         'id_usuario': new_user[0],
#         'username': new_user[1],
#         'email': new_user[2],
#         'birth_date': new_user[3],
#         'full_name': new_user[4]
#     }

#     return jsonify(
#         statusCode=201,
#         intMessage='User registered successfully',
#         data=new_user_data
#     )


@app.route('/task', methods=['POST'])
def create_task():
    data = request.json
    nameTask = data.get('nameTask')
    descripcion = data.get('descripcion')
    categoria = data.get('categoria')
    estatus = data.get('estatus')
    deadLine = data.get('deadLine')

    # Validar que todos los campos obligatorios estén presentes
    if not nameTask or not descripcion or not categoria or not estatus or not deadLine:
        return jsonify(statusCode=400, intMessage="Todos los campos son obligatorios", data={})

    try:
        # Convertir deadLine a Timestamp de Firestore
        deadline_timestamp = datetime.datetime.strptime(deadLine, "%Y-%m-%d %H:%M:%S")

        # Crear la nueva tarea
        new_task = {
            "nameTask": nameTask,
            "descripcion": descripcion,
            "categoria": categoria,
            "estatus": estatus,
            "deadLine": deadline_timestamp,
            "created_at": datetime.datetime.now(datetime.timezone.utc)  # Fecha de creación
        }

        # Agregar la tarea a la colección "task"
        db.collection("task").add(new_task)

        return jsonify(statusCode=201, intMessage="Tarea creada exitosamente", data={})
    
    except ValueError:
        return jsonify(statusCode=400, intMessage="Formato de fecha incorrecto. Usa 'YYYY-MM-DD HH:MM:SS'", data={})



if __name__ == '__main__':
    app.run(debug=True)