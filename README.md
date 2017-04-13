# Lyris
Lyris es un script de código abierto desarrollado en el lenguaje de programación Python y bajo la librería nmap de los repositorios pip, Este script es diseñado y programado por Menkar Cantor Molina y Martin Nieto Guerrero, los cuales son ambos tecnólogos en sistemas de información.
Fue creado originalmente para GNU/Linux, aunque actualmente se piensa realizar para sistemas multiplataforma. Este es un proyecto de seguridad informática, dado que usa como motor de funcionamiento a la librería Python-Nmap, integrando asi las funciones de la herramienta Nmap a Python.
Este script posee las funciones para sondear redes de computadoras, incluyendo detección de equipos y sistemas operativos.  Además, durante el escaneo, es capaz de adaptarse a las condiciones de la red incluyendo latencia y congestión de la misma.

# Características

Identificación de host en una red, dirección ip, dirección Mac, nombre del host, adaptador de red. 
Detección de sistema operativo y versión utiliza dicha computadora, (esta técnica es también conocida como fingerprinting).
Obtención algunas características del hardware de red de la máquina

# Características En Proceso

Identificación puertos abiertos en una computadora objetivo. (aún están trabajando en esa característica)
Detección de servicios está ejecutando la misma.

# Comandos

- load_file: Permite Cargar un archivo en formato txt con todas las MAC legitimas de la red.
- scan permite escanear la red mediante la dirección IP del router y comparar las MAC almacenadas con las MAC obtenidas en la red
- pertains: permite mostrar solamente las MAC legitimas obtenidas mediante el escáner
- intruder: Permite mostrar solamente las MAC Intrusas obtenida mediante el escáner
- save_file: Permite Guardar en un archivo txt las MAC intrusas mas su dirección IP.

# Requisitos para su correcto funcionamiento

1. Sistemas GNU/Linux
2. Python 3.x
3. La librería Python-Nmap
4. La herramienta Figlet
