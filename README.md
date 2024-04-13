# MyPass

MyPass es una aplicación simple de gestión de contraseñas escrita en Python. Permite a los usuarios almacenar y gestionar sus contraseñas de forma segura en una base de datos SQLite. Utiliza técnicas de encriptación para proteger las contraseñas almacenadas.

## Funcionalidades

- **Registro de Usuarios:** Los usuarios pueden registrarse con un nombre de usuario y una contraseña maestra.
- **Gestión de Contraseñas:** Los usuarios pueden almacenar, ver, actualizar y eliminar contraseñas para diferentes sitios o aplicaciones.
- **Generador de Contraseñas:** La aplicación incluye un generador de contraseñas que permite a los usuarios crear contraseñas seguras con diferentes longitudes y opciones de caracteres.

## Requisitos

- Python 3.x
- Biblioteca cryptography (instalable a través de pip: `pip install cryptography`)

## Instalación

1. Clona o descarga este repositorio en tu máquina local.
2. Asegúrate de tener Python 3.x instalado en tu sistema.
3. Instala la biblioteca cryptography utilizando pip: `pip install cryptography`.

## Uso

1. Ejecuta el archivo `mypass.py` para iniciar la aplicación.
2. Sigue las instrucciones en pantalla para registrarte como usuario o acceder si ya tienes una cuenta.
3. Una vez dentro, sigue las opciones del menú para gestionar tus contraseñas.

## Estructura del Proyecto

- **mypass.py:** El archivo principal que contiene el código fuente de la aplicación.
- **mypass.db:** La base de datos SQLite donde se almacenan los usuarios y las contraseñas.
- **README.md:** Este archivo que proporciona información sobre el proyecto.

## Contribuir

Si deseas contribuir a este proyecto, siéntete libre de abrir un issue o enviar un pull request.

## Licencia

Este proyecto está bajo la licencia [MIT License](LICENSE).
