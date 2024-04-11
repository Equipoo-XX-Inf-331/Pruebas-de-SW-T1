#encriptacion
import hashlib
import base64
from cryptography.fernet import Fernet
#Sqlite
import sqlite3
from sqlite3 import Error
import hashlib
#generador contraseñas
import random
import string



######################------Creador contraseñas------######################

def generador_pass(longitud,tipo ): #Se dara a eleccion si se puede incluir los caracteres de puntucion nomas
    if tipo == "SI":
        caracteres = string.ascii_letters + string.digits + string.punctuation
    elif tipo == "NO":
        caracteres = string.ascii_letters + string.digits

    contra_random = ''.join(random.choice(caracteres) for _ in range(longitud))
    return contra_random





######################------Encriptacion------######################
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



######################------Base de datos------######################

def create_connection(db_file):
    """Crear una conexión a la base de datos SQLite especificada por db_file"""
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)
    return conn

def create_table(conn, create_table_sql):
    """Crear una tabla desde la sentencia create_table_sql"""
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)


#############------------------------CRUD USER------------------------#############

def insert_user(conn, id_user, nombre, main_password):
    """Insertar un nuevo usuario en la tabla usuario"""
    try:
        c = conn.cursor()
        c.execute("INSERT INTO usuario (id_user, nombre, main_password) VALUES (?, ?, ?)", (id_user, nombre, main_password))
        conn.commit()  # Guardar los cambios en la base de datos
        print("Usuario agregado correctamente.")
    except Error as e:
        print("Error al insertar usuario:", e)

def get_user(conn, id_user):
    """Obtener el nombre y contraseña de usuario basado en su ID"""
    try:
        c = conn.cursor()
        c.execute("SELECT nombre, main_password FROM usuario WHERE id_user = ?", (id_user,))
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
    conn = sqlite3.connect('mypass.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO passwords (descripcion, password) VALUES (?, ?)', (descripcion, password))
    conn.commit()
    conn.close()

# Función para mostrar una contraseña
def view_password(descripcion):
    conn = sqlite3.connect('mypass.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM passwords WHERE descripcion = ?', (descripcion,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row
    else:
        return False
# Función para actualizar una contraseña existente
def update_password(descripcion, new_password):
    conn = sqlite3.connect('mypass.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE passwords SET password = ? WHERE descripcion = ?', (new_password, descripcion))
    conn.commit()
    conn.close()

# Función para eliminar una contraseña existente
def delete_password(descripcion):
    conn = sqlite3.connect('mypass.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM passwords WHERE descripcion = ?', (descripcion,))
    conn.commit()
    conn.close()

#############----------------------------------------------------------#############



def main():
    database = "./mypass.db"
    sql_create_passwords_table = """CREATE TABLE IF NOT EXISTS passwords (
                                    descripcion TEXT PRIMARY KEY,
                                    password TEXT NOT NULL
                                );"""
    
    sql_create_usuario = """CREATE TABLE IF NOT EXISTS usuario (
                                id_user int PRIMARY KEY,
                                nombre TEXT NOT NULL,
                                main_password TEXT NOT NULL
                            );"""

    # Crear una conexión a la base de datos
    conn = create_connection(database)

    # Crear la tabla
    if conn is not None:
        create_table(conn, sql_create_passwords_table)
        create_table(conn, sql_create_usuario)
        return conn 
    else:
        print("Error! no se pudo crear la conexión a la base de datos.")
        return None 






if __name__ == '__main__':
    conn = main()
    #Programa como tal 

    if conn is not None:
        print("Conexión establecida.")


        #Saber si hay un usuario registrado 

        #No hay un usuario
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
                    print("Contraseña registrada satisfactoriamente.\n")

            
            insert_user(conn, 1, user, Hash_bd)


        #Si hay un usuario
        if count_users(conn) == 1:
            user = get_user(conn, 1)
            nombre = user[0]
            hash_bd = user[1]
            print("Bienvenido a Mypass " + str(nombre) + ".")
            corte = False
            while corte == False:
                contra_bruto = input("Ingrese su contraseña porfavor: ")
                Hash = generar_clave_SHA_256(contra_bruto)
                if Hash == hash_bd:
                    print("Contraseña correcta.\n")
                    corte = True
                else:
                    print("Contraseña incorrecta, porfavor volver a intentar.\n")
            
            num_aux = (len(contra_bruto))//2
            key_master_pre = contra_bruto[:num_aux] + Hash + contra_bruto[num_aux:]
            key_master_256 = generar_clave_SHA_256(key_master_pre)
            key_master = generar_clave_base64(key_master_256)

            ciclo = True
            while ciclo:
                print("¿Que desea realizar?")
                print("1. Ingresar una nueva contraseña")
                print("2. Ver una contraseña")
                print("3. Actualizar una contraseña")
                print("4. Eliminar una contraseña")
                print("5. Crear una contraseña")
                print("6. Salir")

                opcion = input("Inserte el numero de la opción: ")
                print("")

                if opcion == "1":
                    sitio = input("Ingrese el sitio o aplicacion correspondiente a la contraseña: ")
                    sitio_lower = sitio.lower()
                    if view_password(sitio_lower) == False:
                        i = True
                        while i == True:
                            print("")
                            contra_app = input("Ingrese la contraseña: ")
                            aux_app = input("Ingrese la contraseña nuevamente: ")
                            print("")

                            if contra_app == aux_app:
                                print("Contraseña registrada satisfactoriamente\n")
                                i = False
                                contra_app_encrip = encriptar_texto(contra_app, key_master)
                                insert_password(sitio_lower, contra_app_encrip)

                            else:
                                print("Las contraseñas son diferentes,porfavor volver a intentar.\n")
                    else:
                        print("")
                        print("Ya hay una contraseña registrada para "+ sitio + ".\n")



                elif opcion == "2":
                    sitio = input("Ingrese el sitio o aplicación a la que pertenece la contraseña: ")
                    sitio_lower = sitio.lower()
                    print("")
                    if view_password(sitio_lower):
                        contra_encriptada = view_password(sitio_lower)[1]
                        contra_de_vuelta = desencriptar_texto(contra_encriptada, key_master)
                        print("La contraseña para " + sitio +" es: " + contra_de_vuelta +"\n")
                    else:
                        print(sitio + " no se ha encontrado en la base de datos.\n")



                elif opcion == "3":
                    sitio = input("Ingrese el sitio o aplicación a la que pertenece la contraseña: ")
                    sitio_lower = sitio.lower()
                    print("")

                    if view_password(sitio_lower):
                        contra_encriptada = view_password(sitio_lower)[1]
                        contra_de_vuelta = desencriptar_texto(contra_encriptada, key_master)
                        print("La contraseña para " + sitio +" es: " + contra_de_vuelta +"\n")

                        i = True
                        while i == True:
                            contra_app = input("Ingrese la nueva contraseña: ")
                            aux_app = input("Ingrese la contraseña nuevamente: ")
                            print("")
                            if contra_app == aux_app:
                                print("Contraseña registrada satisfactoriamente\n")
                                i = False
                                contra_app_encrip = encriptar_texto(contra_app, key_master)
                                update_password(sitio_lower, contra_app_encrip)
                            else:
                                print("Las contraseñas son diferentes,porfavor volver a intentar.\n")
                    else:
                        print(sitio + " no se ha encontrado en la base de datos.\n")   



                elif opcion == "4":
                    sitio = input("Ingrese el sitio o aplicación a la que pertenece la contraseña: ")
                    sitio_lower = sitio.lower()
                    print("")
                    if view_password(sitio_lower):
                        i = True
                        while i:
                            confirmar = (input("¿Seguro que desea eliminar la contraseña de este sitio? (SI/NO): ")).upper()
                            if confirmar == "SI":
                                delete_password(sitio_lower)
                                print("Contraseña eliminada correctamente.\n")
                                i = False
                            elif confirmar == "NO":
                                print("No se borrara la contraseña.\n")
                                i = False
                            else:
                                print("Entrada no valida, porfavor volver a confirmar o desconfirmar.\n")
                    else:
                        print(sitio + " no se ha encontrado en la base de datos.\n")



                elif opcion == "5":
                    i = True
                    while i:
                        largo = input("Defina el largo de la contraseña, el minimo es 8: ")
                        print("")
                        if largo.isdigit():
                            largo = int(largo)
                            if largo >= 8:
                                print("¿Desea que su conotraseña posea signos de puntuación?, ejemplo: @;'...")
                                tipo = (input("(SI/NO): ")).upper()
                                contra_nueva = generador_pass(largo, tipo)
                                print("La contraseña generada es: "+ str(contra_nueva))
                                print("")
                                i = False
                            else:
                                print("Largo muy corto.\n")
                        else: 
                            print("No se ingreso un numero.\n")



                elif opcion == "6":
                    ciclo = False

                else:
                    print("Opción no valida, inserte de nuevo la opción a escojer de nuevo porfavor.\n")

        if count_users(conn) > 1:
            print("Este programa tiene bloqueada la posibilidad de tener mas de un usuario y actualmente se encuentra en esa situación,") 
            print("se tiene que borrar la base de datos debido a que no se puede asegurar la integridad de estos mismos")
    else:
        print("Error al establecer la conexión.")