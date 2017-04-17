#Diseñado y Desarrollado por: Menkar Cantor Molina - menkar91@gmail.com // Marto Nieto Guerrero -  marto.nieto.g16@gmail.com 
import lyris
import os, sys
import subprocess

from cmd import Cmd

def clear():
    clear_lyris = 'clear'
    resultado_clear_lyris = subprocess.Popen(clear_lyris, shell=True, stdout=subprocess.PIPE)
    while resultado_clear_lyris.poll() is None:
        salida_clear_lyris = resultado_clear_lyris.stdout.readline()
        print(salida_clear_lyris.decode(sys.getdefaultencoding()).rstrip()) 

def banner():
    banner_lyris = "sudo ./banner.sh"
    resultado_banner_lyris = subprocess.Popen(banner_lyris, shell=True, stdout=subprocess.PIPE)
    while resultado_banner_lyris.poll() is None:
        salida_banner_lyris = resultado_banner_lyris.stdout.readline()
        print('\033[92m           '+str(salida_banner_lyris.decode(sys.getdefaultencoding()).rstrip()))
        
    print('\033[92m')
    print('#####################################################')
    print('                                                     ')
    print('       Sistema Para Dectectar Intrusos en la Red     ')
    print('                     Version: alfa                   ')
    print('                 Comunidad Byte Codes                ')
    print('             Diseñado y Desarrollado Por:            ')
    print('        Menkar Cantor Molina - menkar91@gmail.com    ')
    print('   Marto Nieto Guerrero -  marto.nieto.g16@gmail.com ')
    print('                                                     ')
    print('#####################################################')

class Console(Cmd):

    def do_scan(self, args):
        """permite escanear la red mediante la dirección IP del router y comparar las MAC almacenadas con las MAC obtenidas en la red."""
        if len(args) == 0:
            name = '\033[91m Ingrese una Direccion IP para Empezar el Escanner de la Red'
        else:
            lyris.Scan_Net(args)
            lyris.run_MAC_All()            

    def do_quit(self, args):
        """Quits the program."""
        print ("Quitting.")
        raise SystemExit

    def do_banner(self, args):
        if len(args) == 0:
            banner()

    def do_clear(self, args):
        """Limpia la Consola Terminal de Comandos"""
        if len(args) == 0:
            clear()

    def do_pertains(self, args):
        """permite mostrar solamente las MAC legitimas obtenidas mediante el escáner"""
        """ej: pertains 192.168.1.1 o pertains."""
        if len(args) == 0:
            lyris.run_MAC_Pertain()
        else:
            lyris.Scan_Net(args)
            lyris.run_MAC_Pertain()

    def do_intruder(self, args):
        """Permite mostrar solamente las MAC Intrusas obtenida mediante el escáner."""
        """ej: pertains 192.168.1.1 o pertains."""
        if len(args) == 0:
            lyris.run_MAC_Not_Pertain()
        else:
            lyris.Scan_Net(args)
            lyris.run_MAC_Not_Pertain()

    def do_load_file(self, args):
        """Permite Cargar un archivo en formato txt con todas las MAC legitimas de la red."""
        if len(args) == 0:
            name = '\033[91m No se ha Cargado las MAC Legitimas'
        else:
            name = args
            lyris.Load_File_MAC_Pertain("%s" % name)
            print('\033[0m(load_file_intruder)\033[92m > \033[0m', end='')
            archivo_mac_intusas = input()
            lyris.set_Archivo_MAC_Intruso(archivo_mac_intusas)

    def do_save_file(self, args):
        """Permite Guardar en un archivo txt las MAC intrusas mas su dirección IP."""
        if len(args) == 0:
            lyris.Save_MAC_Not_Pertain(lyris.get_Archivo_MAC_Intruso())
try:
    banner()
    if __name__ == '__main__':
        console = Console()
        console.prompt = '\033[92m > '+'\033[0m'
        console.cmdloop(' ')
except KeyboardInterrupt as e:
    print ("Quitting.")
    raise SystemExit    