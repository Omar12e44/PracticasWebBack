from asyncio import Task
from flask import Flask , jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
import jwt
import datetime
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import firebase_admin
from firebase_admin import credentials, firestore, initialize_app
from urllib.parse import quote
from dotenv import load_dotenv
import os
import json


# Cargar variables de entorno
load_dotenv()

# Obtener las variables de entorno de Firebase
firebase_credentials = {
    "type": os.getenv('FIREBASE_TYPE'),
    "project_id": os.getenv('FIREBASE_PROJECT_ID'),
    "private_key_id": os.getenv('FIREBASE_PRIVATE_KEY_ID'),
    "private_key": os.getenv('FIREBASE_PRIVATE_KEY').replace('\\n', '\n'),  # Asegúrate de reemplazar \n en la clave privada
    "client_email": os.getenv('FIREBASE_CLIENT_EMAIL'),
    "client_id": os.getenv('FIREBASE_CLIENT_ID'),
    "auth_uri": os.getenv('FIREBASE_AUTH_URI'),
    "token_uri": os.getenv('FIREBASE_TOKEN_URI'),
    "auth_provider_x509_cert_url": os.getenv('FIREBASE_AUTH_PROVIDER_X509_CERT_URL'),
    "client_x509_cert_url": os.getenv('FIREBASE_CLIENT_X509_CERT_URL'),
    "universe_domain": os.getenv('FIREBASE_UNIVERSE_DOMAIN')
}


try:
    cred = credentials.Certificate(firebase_credentials)
    firebase_admin.initialize_app(cred)
    print("Firebase inicializado correctamente")
except Exception as e:
    raise ValueError(f"Error al inicializar Firebase: {e}")

db = firestore.client()

app = Flask(__name__)
CORS(app)
app.config["JWT_TOKEN_LOCATION"] = ["headers"]

db = firestore.client()

secret_key = 'my_secret_key'
users = []

valid_username = 'admin'
valid_password = 'password'

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

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
            'rol': user_doc['rol'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=40)
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
        data={'token': token, 'rol': user_doc['rol'], 'id_usuario': user_doc['id']}
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


# @app.route('/task', methods=['POST'])
# def create_task():
#     data = request.json
#     nameTask = data.get('nameTask')
#     descripcion = data.get('descripcion')
#     categoria = data.get('categoria')
#     estatus = data.get('estatus')
#     deadLine = data.get('deadLine')

#     # Validar que todos los campos obligatorios estén presentes
#     if not nameTask or not descripcion or not categoria or not estatus or not deadLine:
#         return jsonify(statusCode=400, intMessage="Todos los campos son obligatorios", data={})

#     try:
#         # Convertir deadLine a Timestamp de Firestore
#         deadline_timestamp = datetime.datetime.strptime(deadLine, "%Y-%m-%d %H:%M:%S")

#         # Crear la nueva tarea
#         new_task = {
#             "nameTask": nameTask,
#             "descripcion": descripcion,
#             "categoria": categoria,
#             "estatus": estatus,
#             "deadLine": deadline_timestamp,
#             "created_at": datetime.datetime.now(datetime.timezone.utc)  # Fecha de creación
#         }

#         # Agregar la tarea a la colección "task"
#         db.collection("task").add(new_task)

#         return jsonify(statusCode=201, intMessage="Tarea creada exitosamente", data={})

#     except ValueError:
#         return jsonify(statusCode=400, intMessage="Formato de fecha incorrecto. Usa 'YYYY-MM-DD HH:MM:SS'", data={})

@app.route('/create_task', methods=['POST'])
def create_task():
    data = request.json
    nameTask = data.get('nameTask')
    descripcion = data.get('descripcion')
    categoria = data.get('categoria')
    estatus = data.get('estatus')
    deadLine = data.get('deadLine')

    token = request.headers.get("Authorization")
    if not token:
        return jsonify(statusCode=401, intMessage="Token de autenticación requerido", data={})

    try:
        payload = jwt.decode(token.replace("Bearer ", ""), secret_key, algorithms=["HS256"])
        uid = payload.get("user_id")

        if not nameTask or not descripcion or not categoria or not estatus or not deadLine:
            return jsonify(statusCode=400, intMessage="Todos los campos son obligatorios", data={})

        deadline_timestamp = datetime.datetime.strptime(deadLine, "%Y-%m-%d %H:%M:%S")

        new_task = {
            "uid": uid,
            "nameTask": nameTask,
            "descripcion": descripcion,
            "categoria": categoria,
            "estatus": estatus,
            "deadLine": deadline_timestamp,
            "created_at": datetime.datetime.utcnow()
        }

        db.collection("task").add(new_task)

        return jsonify(statusCode=201, intMessage="Tarea creada exitosamente", data={})

    except jwt.ExpiredSignatureError:
        return jsonify(statusCode=401, intMessage="El token ha expirado", data={})
    except jwt.InvalidTokenError:
        return jsonify(statusCode=401, intMessage="Token inválido", data={})
    except ValueError:
        return jsonify(statusCode=400, intMessage="Formato de fecha incorrecto. Usa 'YYYY-MM-DD HH:MM:SS'", data={})


@app.route('/get_tasks', methods=['GET'])
def get_tasks():
    # Obtener el token de la cabecera de la solicitud
    token = request.headers.get("Authorization")
    if not token:
        return jsonify(statusCode=401, intMessage="Token de autenticación requerido", data={})

    try:
        # Decodificar el token
        payload = jwt.decode(token.replace("Bearer ", ""), secret_key, algorithms=["HS256"])
        uid = payload.get("user_id")

        if not uid:
            return jsonify(statusCode=401, intMessage="El UID no se pudo obtener del token", data={})

        # Obtener las tareas asociadas al UID
        tasks = db.collection("task").where("uid", "==", uid).stream()

        tasks_list = []
        for task in tasks:
            task_data = task.to_dict()
            task_data["id"] = task.id  # Agregar el ID del documento de Firestore
            tasks_list.append(task_data)

        return jsonify(statusCode=200, intMessage="Tareas obtenidas exitosamente", data=tasks_list)

    except jwt.ExpiredSignatureError:
        return jsonify(statusCode=401, intMessage="El token ha expirado", data={})
    except jwt.InvalidTokenError:
        return jsonify(statusCode=401, intMessage="Token inválido", data={})

@app.route("/delete_task/<string:task_id>", methods=["DELETE"])
def delete_task(task_id):
    token = request.headers.get("Authorization")
    if not token:
        return jsonify(statusCode=401, intMessage="Token de autenticación requerido", data={}), 401

    try:
        # Decodificar el token
        payload = jwt.decode(token.replace("Bearer ", ""), secret_key, algorithms=["HS256"])
        user_id = payload.get("user_id")

        if not user_id:
            return jsonify(statusCode=401, intMessage="El UID no se pudo obtener del token", data={}), 401

        # Obtener referencia al documento en Firestore (usando el task_id como ID del documento)
        task_ref = db.collection("task").document(task_id)
        task = task_ref.get()

        if not task.exists:
            return jsonify(statusCode=404, intMessage="Tarea no encontrada", data={}), 404

        # Eliminar la tarea
        task_ref.delete()

        return jsonify(statusCode=200, intMessage="Tarea eliminada con éxito", data={}), 200

    except jwt.ExpiredSignatureError:
        return jsonify(statusCode=401, intMessage="El token ha expirado", data={}), 401
    except jwt.InvalidTokenError:
        return jsonify(statusCode=401, intMessage="Token inválido", data={}), 401
    except Exception as e:
        return jsonify(statusCode=500, intMessage=str(e), data={}), 500




@app.route("/create_group", methods=["POST"])
def create_group():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify(statusCode=401, intMessage="Token de autenticación requerido", data={})

    try:
        # Decodificar el token
        payload = jwt.decode(token.replace("Bearer ", ""), secret_key, algorithms=["HS256"])
        print(f"Payload decodificado: {payload}")  # 🔥 Verificar qué contiene el token

        user_id = payload.get("user_id")
        user_role = payload.get("rol")  # Cambiado de 'role' a 'rol' según tu JSON

        if not user_id:
            return jsonify(statusCode=401, intMessage="El UID no se pudo obtener del token", data={})

        # 🔥 Imprimir el rol para depuración
        print(f"Usuario ID: {user_id}, Rol: {user_role}")

        # Validar que el usuario tenga permisos
        if user_role not in ["admin", "master"]:
            return jsonify(statusCode=403, intMessage="No tienes permisos para crear un grupo", data={})

        # Obtener datos del grupo
        data = request.get_json()
        group_name = data.get("name")

        if not group_name:
            return jsonify(statusCode=400, intMessage="El nombre del grupo es obligatorio", data={})

        # Crear el grupo en Firestore
        new_group_ref = db.collection("groups").document()
        new_group_ref.set({
            "id": new_group_ref.id,
            "name": group_name,
            "created_by": user_id,
            "created_at": firestore.SERVER_TIMESTAMP
        })

        return jsonify(statusCode=201, intMessage="Grupo creado exitosamente", data={"group_id": new_group_ref.id}), 201

    except jwt.ExpiredSignatureError:
        return jsonify(statusCode=401, intMessage="El token ha expirado", data={})
    except jwt.InvalidTokenError:
        return jsonify(statusCode=401, intMessage="Token inválido", data={})
    except Exception as e:
        return jsonify(statusCode=500, intMessage=f"Error interno: {str(e)}", data={})

@app.route('/delete_grupo/<string:id_grupo>', methods=['DELETE'])
def delete_grupo(id_grupo):
    token = request.headers.get("Authorization")
    if not token:
        return jsonify(statusCode=401, intMessage="Token de autenticación requerido", data={})

    try:
        # Decodificar el token
        payload = jwt.decode(token.replace("Bearer ", ""), secret_key, algorithms=["HS256"])
        user_id = payload.get("user_id")
        user_role = payload.get("rol")

        if not user_id:
            return jsonify(statusCode=401, intMessage="El UID no se pudo obtener del token", data={})

        # Validar que el usuario tenga permisos
        if user_role not in ["admin", "master"]:
            return jsonify(statusCode=403, intMessage="No tienes permisos para eliminar el grupo", data={})

        # Obtener el grupo por ID
        grupo_ref = db.collection("groups").document(id_grupo)
        grupo = grupo_ref.get()

        if not grupo.exists:
            return jsonify(statusCode=404, intMessage="Grupo no encontrado", data={})

        # Eliminar el grupo
        grupo_ref.delete()

        return jsonify(statusCode=200, intMessage="Grupo eliminado exitosamente", data={})
    except jwt.ExpiredSignatureError:
        return jsonify(statusCode=401, intMessage="El token ha expirado", data={})
    except jwt.InvalidTokenError:
        return jsonify(statusCode=401, intMessage="Token inválido", data={})
    except Exception as e:
        return jsonify(statusCode=500, intMessage=str(e), data={})

@app.route('/add_task_to_grupo', methods=['POST'])
def add_task_to_grupo():
    data = request.json
    id_grupo = data.get('idGrupo')
    ids_usuarios = data.get('idsUsuarios')  # Lista de IDs de usuarios
    usernames = data.get('usernames')  # Lista de usernames
    name_task = data.get('nameTask')
    descripcion = data.get('descripcion')
    categoria = data.get('categoria')
    estatus = data.get('estatus')
    dead_line = data.get('deadLine')

    if not id_grupo or not ids_usuarios or not usernames or not name_task or not descripcion or not categoria or not estatus or not dead_line:
        return jsonify(statusCode=400, intMessage="Todos los campos son obligatorios", data={})

    try:
        # Obtener el grupo por ID
        grupo_ref = db.collection("groups").document(id_grupo)
        grupo = grupo_ref.get()

        if not grupo.exists:
            return jsonify(statusCode=404, intMessage="Grupo no encontrado", data={})

        # Convertir deadLine a Timestamp de Firestore
        deadline_timestamp = datetime.datetime.strptime(dead_line, "%Y-%m-%d %H:%M:%S")

        # Crear la nueva tarea
        new_task = {
            "ids_usuarios": ids_usuarios,
            "usernames": usernames,
            "nameTask": name_task,
            "descripcion": descripcion,
            "categoria": categoria,
            "estatus": estatus,
            "deadLine": deadline_timestamp,
            "created_at": datetime.datetime.utcnow()
        }

        # Agregar la tarea a la colección "tasks" dentro del grupo
        grupo_ref.collection("tasks").add(new_task)

        return jsonify(statusCode=201, intMessage="Tarea agregada al grupo exitosamente", data={})

    except ValueError:
        return jsonify(statusCode=400, intMessage="Formato de fecha incorrecto. Usa 'YYYY-MM-DD HH:MM:SS'", data={})
    except Exception as e:
        return jsonify(statusCode=500, intMessage=str(e), data={})
    


@app.route('/get_grupos', methods=['GET'])
def get_grupos():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify(statusCode=401, intMessage="Token de autenticación requerido", data={})

    try:
        # Decodificar el token
        payload = jwt.decode(token.replace("Bearer ", ""), secret_key, algorithms=["HS256"])
        user_id = payload.get("user_id")
        user_role = payload.get("rol")

        if not user_id:
            return jsonify(statusCode=401, intMessage="El UID no se pudo obtener del token", data={})

        # Validar que el usuario tenga permisos
        if user_role not in ["admin", "master"]:
            return jsonify(statusCode=403, intMessage="No tienes permisos para obtener los grupos", data={})

        # Obtener los grupos
        grupos = db.collection("groups").stream()

        grupos_list = []
        for grupo in grupos:
            grupo_data = grupo.to_dict()
            grupo_data["id"] = grupo.id  # Agregar el ID del documento de Firestore
            grupos_list.append(grupo_data)

        return jsonify(statusCode=200, intMessage="Grupos obtenidos exitosamente", data=grupos_list)

    except jwt.ExpiredSignatureError:
        return jsonify(statusCode=401, intMessage="El token ha expirado", data={})
    except jwt.InvalidTokenError:
        return jsonify(statusCode=401, intMessage="Token inválido", data={})
    except Exception as e:
        return jsonify(statusCode=500, intMessage=f"Error interno: {str(e)}", data={})


@app.route('/get_usuarios', methods=['GET'])
def get_usuarios():
    try:
        users_ref = db.collection("Users").stream()
        users = []
        for doc in users_ref:
            user = doc.to_dict()
            user["id"] = doc.id
            users.append(user)
        return jsonify(statusCode=200, intMessage='Usuarios obtenidos exitosamente', data=users)
    except Exception as e:
        return jsonify(statusCode=500, intMessage=str(e), data=[])


@app.route('/add_user_to_grupo', methods=['POST'])
def add_user_to_grupo():
    data = request.json
    id_grupo = data.get('idGrupo')
    id_usuario = data.get('idUsuario')
    user_name = data.get('userName')

    if not id_grupo or not id_usuario or not user_name:
        return jsonify(statusCode=400, intMessage="Todos los campos son obligatorios", data={})

    try:
        # Obtener el grupo por ID
        grupo_ref = db.collection("groups").document(id_grupo)
        grupo = grupo_ref.get()

        if not grupo.exists:
            return jsonify(statusCode=404, intMessage="Grupo no encontrado", data={})

        # Actualizar el grupo para agregar el usuario
        grupo_ref.update({
            "usuarios": firestore.ArrayUnion([{"id": id_usuario, "name": user_name}])
        })

        return jsonify(statusCode=200, intMessage="Usuario agregado al grupo exitosamente", data={})
    except Exception as e:
        return jsonify(statusCode=500, intMessage=str(e), data={})



@app.route('/tareas_usuario_grupo', methods=['GET'])
def obtener_tareas_usuario():
    """ Endpoint para obtener tareas de un usuario autenticado """

    # Obtener y validar el token
    auth_header = request.headers.get("Authorization")
    if not auth_header or "Bearer " not in auth_header:
        return jsonify({"error": "Token no proporcionado"}), 401

    token = auth_header.split("Bearer ")[1]

    try:
        # 🔑 Decodificar el token para obtener el user_id
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        user_id = payload.get("user_id")

        if not user_id:
            return jsonify({"error": "Token inválido"}), 401

        # 🔥 Consultar Firestore: buscar grupos donde el usuario tenga tareas
        grupos_ref = db.collection("groups").stream()
        tareas_usuario = []

        for grupo in grupos_ref:
            grupo_data = grupo.to_dict()
            grupo_id = grupo.id
            grupo_name = grupo_data.get("name")  # Obtener el nombre del grupo

            tasks_ref = db.collection(f"groups/{grupo_id}/tasks").stream()

            for tarea in tasks_ref:
                tarea_data = tarea.to_dict()
                if user_id in tarea_data.get("ids_usuarios", []):
                    tarea_data["id_tarea"] = tarea.id  # Agregar ID de la tarea
                    tarea_data["grupo"] = grupo_id  # Agregar ID del grupo
                    tarea_data["grupo_name"] = grupo_name  # Agregar el nombre del grupo
                    tareas_usuario.append(tarea_data)

        return jsonify(statusCode=200, intMessage="Tareas obtenidas exitosamente", data=tareas_usuario)

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
#crud

@app.route('/update_users/<id>', methods=['PUT'])
def update_user(id):
    data = request.json
    user_ref = db.collection("Users").document(id)

    if not user_ref.get().exists:
        return jsonify(statusCode=404, intMessage="Usuario no encontrado", data={})

    updates = {}
    if "username" in data:
        updates["userName"] = data["username"]
    if "email" in data:
        updates["email"] = data["email"]
    if "rol" in data:
        updates["rol"] = data["rol"]
    user_ref.update(updates)
    return jsonify(statusCode=200, intMessage="Usuario actualizado correctamente", data={})



@app.route('/delate_users/<id>', methods=['DELETE'])
def delete_user(id):
    user_ref = db.collection("Users").document(id)

    if not user_ref.get().exists:
        return jsonify(statusCode=404, intMessage="Usuario no encontrado", data={})

    user_ref.delete()
    return jsonify(statusCode=200, intMessage="Usuario eliminado correctamente", data={})

@app.route('/add_users', methods=['POST'])
def add_users_fu():
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



@app.route('/update_task/<group_id>/<task_id>', methods=['PUT'])
def update_task(group_id, task_id):
    data = request.json

    # Verificar que se haya enviado al menos un campo para actualizar
    if not data:
        return jsonify(statusCode=400, intMessage="No se enviaron datos para actualizar", data={})

    try:
        # Referencia a la tarea dentro del grupo
        task_ref = db.collection('groups').document(group_id).collection('tasks').document(task_id)

        # Verificar si la tarea existe
        if not task_ref.get().exists:
            return jsonify(statusCode=404, intMessage="La tarea no existe", data={})

        # Actualizar los campos enviados en el cuerpo de la solicitud
        update_data = {key: value for key, value in data.items() if value is not None}
        update_data['updated_at'] = datetime.datetime.utcnow()  # Agregar campo de actualización

        task_ref.update(update_data)

        return jsonify(statusCode=200, intMessage="Tarea actualizada exitosamente", data={})
    except Exception as e:
        return jsonify(statusCode=500, intMessage=f"Error al actualizar la tarea: {e}", data={})


@app.route('/update_general_task/<task_id>', methods=['PUT'])
def update_general_task(task_id):
    data = request.json

    # Verificar que se haya enviado al menos un campo para actualizar
    if not data:
        return jsonify(statusCode=400, intMessage="No se enviaron datos para actualizar", data={})

    try:
        # Referencia a la tarea en la colección "task"
        task_ref = db.collection('task').document(task_id)

        # Verificar si la tarea existe
        if not task_ref.get().exists:
            return jsonify(statusCode=404, intMessage="La tarea no existe", data={})

        # Actualizar los campos enviados en el cuerpo de la solicitud
        update_data = {key: value for key, value in data.items() if value is not None}
        update_data['updated_at'] = datetime.datetime.utcnow()  # Agregar campo de actualización

        task_ref.update(update_data)

        return jsonify(statusCode=200, intMessage="Tarea general actualizada exitosamente", data={})
    except Exception as e:
        return jsonify(statusCode=500, intMessage=f"Error al actualizar la tarea general: {e}", data={})


@app.route('/add_users', methods=['POST'])
def add_users():
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



@app.route('/get_usuarios', methods=['GET'])
def get_usuarios_u():
    try:
        users_ref = db.collection("Users").stream()
        users = []
        for doc in users_ref:
            user = doc.to_dict()
            user["id"] = doc.id
            users.append(user)
        return jsonify(statusCode=200, intMessage='Usuarios obtenidos exitosamente', data=users)
    except Exception as e:
        return jsonify(statusCode=500, intMessage=str(e), data=[])
    
    
    
@app.route('/update_users/<id>', methods=['PUT'])
def update_ussr(id):
    data = request.json  # Obtener los datos enviados en la solicitud
    user_ref = db.collection("Users").document(id)

    # Verificar si el usuario existe
    if not user_ref.get().exists:
        return jsonify(statusCode=404, intMessage="Usuario no encontrado", data={})

    # Validar los campos enviados
    updates = {}
    if "username" in data and data["username"]:
        updates["userName"] = data["username"]
    if "email" in data and data["email"]:
        updates["email"] = data["email"]
    if "rol" in data and data["rol"]:
        updates["rol"] = data["rol"]

    # Si no hay campos válidos para actualizar, devolver un error
    if not updates:
        return jsonify(statusCode=400, intMessage="No se enviaron campos válidos para actualizar", data={})

    # Actualizar los datos del usuario
    try:
        updates["updated_at"] = datetime.datetime.utcnow()  # Agregar campo de fecha de actualización
        user_ref.update(updates)
        return jsonify(statusCode=200, intMessage="Usuario actualizado correctamente", data={})
    except Exception as e:
        return jsonify(statusCode=500, intMessage=f"Error al actualizar el usuario: {e}", data={})



@app.route('/delete_users/<id>', methods=['DELETE'])
def delete_users(id):
    user_ref = db.collection("Users").document(id)

    if not user_ref.get().exists:
        return jsonify(statusCode=404, intMessage="Usuario no encontrado", data={})

    user_ref.delete()
    return jsonify(statusCode=200, intMessage="Usuario eliminado correctamente", data={})



if __name__ == '__main__':
    app.run(debug=True)