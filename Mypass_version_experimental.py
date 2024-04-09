import hashlib
import base64
from cryptography.fernet import Fernet
#Sqlite
import sqlite3
from sqlite3 import Error
import hashlib
#busqueda de la bd
import os
import glob


def generar_clave_SHA_256(contra):
    sha256 = hashlib.sha256()
    sha256.update(contra.encode())
    return sha256.hexdigest()

def generar_clave_base64(contra):
    clave_bytes = hashlib.sha256(contra.encode()).digest()
    clave_base64 = base64.urlsafe_b64encode(clave_bytes)
    return clave_base64

def encriptar_texto(texto, clave):
    cifrador = Fernet(clave)
    texto_encriptado = cifrador.encrypt(texto.encode())
    return texto_encriptado

def desencriptar_texto(texto_encriptado, clave):
    cifrador = Fernet(clave)
    texto_desencriptado = cifrador.decrypt(texto_encriptado).decode()
    return texto_desencriptado








#############------------------------CRUD USER------------------------#############

def insert_user(conn, id_user, nombre):
    """Insertar un nuevo usuario en la tabla usuario"""
    try:
        c = conn.cursor()
        c.execute("INSERT INTO usuario (id_user, nombre) VALUES (?, ?)", (id_user, nombre))
        conn.commit()  # Guardar los cambios en la base de datos
        print("Usuario agregado correctamente.")
    except Error as e:
        print("Error al insertar usuario:", e)

def get_user(conn, id_user):
    """Obtener el nombre  de usuario basado en su ID"""
    try:
        c = conn.cursor()
        c.execute("SELECT nombre FROM usuario WHERE id_user = ?", (id_user,))
        row = c.fetchone()
        if row:
            return row
        else:
            print("No se encontró ningún usuario con el ID proporcionado.")
            return None
    except Error as e:
        print("Error al obtener el nombre de usuario:", e)
        return None
    
def count_users(conn):
    """Contar la cantidad de usuarios en la tabla usuario"""
    try:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM usuario")
        count = c.fetchone()[0]
        return count
    except Error as e:
        print(e)
        return None
    
#############----------------------------------------------------------#############

#############-----------------------CRUD Password----------------------#############

# Función para insertar una contraseña
def insert_password(descripcion, password):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO passwords (descripcion, password) VALUES (?, ?)', (descripcion, password))
    conn.commit()
    conn.close()

# Función para mostrar una contraseña
def view_password(descripcion):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM passwords WHERE descripcion = ?', (descripcion,))
    row = cursor.fetchone()
    conn.close()
    return row

# Función para actualizar una contraseña existente
def update_password(descripcion, new_password):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE passwords SET password = ? WHERE descripcion = ?', (new_password, descripcion))
    conn.commit()
    conn.close()

# Función para eliminar una contraseña existente
def delete_password(descripcion):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM passwords WHERE descripcion = ?', (descripcion,))
    conn.commit()
    conn.close()

#############----------------------------------------------------------#############


def create_connection(database, password):
    try:
        conn = sqlite3.connect(database)
        conn.execute("PRAGMA key='" + password + "'")
        conn.execute("PRAGMA cipher=SQLCipher")
        return conn
    except sqlite3.Error as e:
        print(e)
        return None

def create_table(conn, create_table_sql):
    """Crear una tabla desde la sentencia create_table_sql"""
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)


def main():
    database = "./mypass.db"
    password = "tu_contraseña_aqui"  # Cambia esto por tu contraseña

    sql_create_passwords_table = """CREATE TABLE IF NOT EXISTS passwords (
                                    descripcion TEXT PRIMARY KEY,
                                    password TEXT NOT NULL
                                );"""
    
    sql_create_usuario = """CREATE TABLE IF NOT EXISTS usuario (
                                id_user int PRIMARY KEY,
                                nombre TEXT NOT NULL
                            );"""

    # Crear una conexión a la base de datos
    conn = create_connection(database, password)

    # Crear la tabla
    if conn is not None:
        create_table(conn, sql_create_passwords_table)
        create_table(conn, sql_create_usuario)
        return conn 
    else:
        print("Error! no se pudo crear la conexión a la base de datos.")
        return None


# Obtener la ruta del directorio donde se encuentra el archivo .py
directorio_ejecutable = os.path.dirname(os.path.abspath(__file__))

# Definir el nombre del archivo que deseas buscar
nombre_archivo = "Mypass.db"

# Crear un patrón de búsqueda que coincida con el nombre del archivo
patron_busqueda = os.path.join(directorio_ejecutable, nombre_archivo)

# Buscar archivos que coincidan con el patrón
archivos_encontrados = glob.glob(patron_busqueda)

# Verificar si se encontraron archivos
if archivos_encontrados:
    print("Se encontró el archivo en la siguiente ubicación:")
    for archivo in archivos_encontrados:
        print(archivo)
else:
    print("El archivo no se encontró en la carpeta del ejecutable.")








'''
if __name__ == '__main__':
    conn = main()
    #Programa como tal 

    if conn is not None:
        print("Conexión establecida.")

        if count_users(conn) == 0:
            print("Bienvenido a Mypass")
            user = input("No hay un usuario registrado, porfavor ingrese el nombre de usuario que le gustario ocupar: ")
            corte = False
            while corte == False:
                confirmacion = input("¿Seguro que quiere ocupar \"" + str(user) + "\" como su nombre de usuario? (SI/NO): ")
                confirmacion = confirmacion.upper()
                if confirmacion == "NO":
                    user = input("Ingrese su nombre de usuario: ")
                elif confirmacion == "SI":
                    corte = True
                else:
                    print("Entrada no valida.")

            corte = False
            while corte == False:
                main_contra = input("Ingrese la contraseña a usar: ")
                confirmacion = input("Ingrese la contraseña nuevamente: ")

                if confirmacion != main_contra:
                    print("Contraseñas no coinciden, porfavor volver a registrar.")

                elif confirmacion == main_contra:
                    corte = True
                    Hash_bd = generar_clave_SHA_256(main_contra)
                    print("Contraseña registrada satisfactoriamente.")

            
            insert_user(conn, 1, user, main_contra)
        
        elif count_users(conn) == 1:
            user = get_user(conn, 1)
            nombre = user[0]
            hash_bd = user[1]
            print("Bienvenido a Mypass " + str(nombre) + ".")
            corte = False
            while corte == False:
                contra_bruto = input("Ingrese su contraseña porfavor: ")
                Hash = generar_clave_SHA_256(contra_bruto)
                if Hash == hash_bd:
                    print("Contraseña correcta.")
                    corte = True
                else:
                    print("Contraseña incorrecta, porfavor volver a intentar")


        else:
            print("Este programa tiene bloqueada la posibilidad de tener mas de un usuario y actualmente se encuentra en esa situación,") 
            print("se tiene que borrar la base de datos debido a que no se puede asegurar la integridad de estos mismos")
    else:
        print("Error al establecer la conexión.")

'''