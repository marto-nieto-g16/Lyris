import nmap
import mostrarOS
import sys
import os

global IPS
global Vendor
global HOSTNAME
global MAC

global nm 
global MAC_FILE

nm = nmap.PortScanner() # se le asigna a nm las funciones de escaner de red  

IPS = []
Vendor = []
HOSTNAME = []
MAC = []
MAC_FILE = []

def Load_File_MAC_Pertain(workspaces):
	try:
		File_MAC_Pertain = open(workspaces, 'r')
		lineas = File_MAC_Pertain.readline()
		index = 0
		while lineas != "":
			MAC_FILE.insert(index, lineas)
			lineas = File_MAC_Pertain.readline()
			index += 1		
		File_MAC_Pertain.close()
	except FileNotFoundError as e:
		print('Error. Archivo No Encontrado: ', workspaces)
	set_Archivo(workspaces)

def Scan_Net(IPScanner):
	set_IPScanners(IPScanner)
	nm.scan(IPScanner+'/24', arguments='-sP', sudo=True) # Comando de Escaner de Nmap
	index = 0
	for hosts in nm.all_hosts():
		if 'mac' in nm[hosts]['addresses']:
			MAC.insert(index, '{}'.format(nm[hosts]['addresses']['mac']))
			IPS.insert(index, '{}'.format(nm[hosts]['addresses']['ipv4']))
			Vendor.insert(index, '{}'.format(nm[hosts]['vendor']))
			if str(nm[hosts].hostname()) != '':
				HOSTNAME.insert(index, '%s (%s)' % ('', nm[hosts].hostname()))
			else:
				HOSTNAME.insert(index, 'Unknown')
			index += 1

def MAC_Pertain():
	index = 0
	hosts_legitimos_activos = 0
	hosts_intrusos_activos = 0
	if len(IPS) != 0:
		print(' ID      Hosts')
		while index != len(MAC):
			if (MAC[index]+'\n' in MAC_FILE) == True:
				hosts_legitimos_activos += 1
				print('\033[92m'+''+str(hosts_legitimos_activos)+' - ', end='')
				print('\033[93m'+IPS[index], end='')
				print('\033[94m'+': '+Vendor[index].strip('{'))
				print('\033[92m Nombre del Hosts: '+'\033[0m'+HOSTNAME[index])
				mostrarOS.sudo_host(IPS[index])
				mostrarOS.Mostrar_OS(IPS[index])
				mostrarOS.Mostrar_Version_OS(IPS[index])
				print('\033[92m'+'Estado: Pertenece a la Red')
				index += 1
			else:
				hosts_intrusos_activos += 1
				index += 1
		print('\n\033[92m Hosts Legitimos Activos: ', '\033[0m'+str(hosts_legitimos_activos))
		print('\033[92m Hosts Intrusos Activos: ', '\033[0m'+str(hosts_intrusos_activos))
		print('\033[92m Total de Hosts Activos: ', '\033[0m'+str(hosts_legitimos_activos + hosts_intrusos_activos))
		Load_File_MAC_Pertain(get_Archivo())
		Scan_Net(get_IPScanners())
	else:
		print('\033[91m Error. No se ha Escaneado la Red!')
		exit()	

def MAC_Not_Pertain():
	index = 0
	hosts_legitimos_activos = 0
	hosts_intrusos_activos = 0
	if len(IPS) != 0:
		while index != len(MAC):
			if (MAC[index]+'\n' in MAC_FILE) != True:
				hosts_intrusos_activos += 1
				print('\n\033[92m'+' '+str(hosts_intrusos_activos)+' - ', end='')
				print('\033[93m'+IPS[index], end='')
				print('\033[94m'+': '+Vendor[index])
				print('\033[92m Nombre del Hosts: '+'\033[0m'+HOSTNAME[index])
				mostrarOS.sudo_host(IPS[index])
				mostrarOS.Mostrar_OS(IPS[index])
				mostrarOS.Mostrar_Version_OS(IPS[index])
				print('\033[91m'+' Estado: No Pertenece a la Red')
				index += 1
			else:
				hosts_legitimos_activos += 1
				index += 1		
		print('\n\033[92m Hosts Legitimos Activos: ', '\033[0m'+str(hosts_legitimos_activos))
		print('\033[92m Hosts Intrusos Activos: ', '\033[0m'+str(hosts_intrusos_activos))
		print('\033[92m Total de Hosts Activos: ', '\033[0m'+str(hosts_legitimos_activos + hosts_intrusos_activos))
		Load_File_MAC_Pertain(get_Archivo())
		Scan_Net(get_IPScanners())
	else:
		print('\033[91m Error. No se ha Escaneado la Red!')
		exit()

def MAC_All():
	index = 0
	hosts_legitimos_activos = 0
	hosts_intrusos_activos = 0
	hosts_activos = 0
	caracter = '{'+'}'
	if len(IPS) != 0:
		while index != len(MAC):
			print('\n\033[0m ID  Direccion IP 	Direccion MAC       Adaptador de Red')
			hosts_activos += 1
			print('\033[92m'+' '+str(hosts_activos)+' - ', end='')
			print('\033[93m'+IPS[index], end='')
			print('\033[94m'+' : '+Vendor[index].strip(caracter))
			print('\033[92m Hostname: '+'\033[0m'+HOSTNAME[index])
			mostrarOS.sudo_host(IPS[index])
			mostrarOS.Mostrar_OS(IPS[index])
			mostrarOS.Mostrar_Version_OS(IPS[index])
			if (MAC[index]+'\n' in MAC_FILE) == True:
				hosts_legitimos_activos += 1
				print('\033[92m'+' Estado: Pertenece a la Red')
				index += 1
			else:
				hosts_intrusos_activos += 1
				print('\033[91m'+' Estado: No Pertenece a la Red')
				index += 1
		print('\n\033[92m Hosts Legitimos Activos: ', '\033[0m'+str(hosts_legitimos_activos))
		print('\033[92m Hosts Intrusos Activos: ', '\033[0m'+str(hosts_intrusos_activos))
		print('\033[92m Total de Hosts Activos: ', '\033[0m'+str(hosts_legitimos_activos + hosts_intrusos_activos))
		Load_File_MAC_Pertain(get_Archivo())
		Scan_Net(get_IPScanners())
	else:
		print('\033[91m Error. No se ha Escaneado la Red!')
		exit()
			
def Save_MAC_Not_Pertain(workspaces):
	index = 0
	if len(IPS) != 0:
		escribir_archivo_mac_intrusa = open((workspaces) , 'w')
		leer_archivo_mac_intrusa = open((workspaces), 'r')
		lineas = leer_archivo_mac_intrusa.readline()
		if len(MAC) != 0:
			while index != len(MAC):
				if (MAC[index] in MAC_FILE) != True:
					if (lineas in MAC)!= True:
						escribir_archivo_mac_intrusa.write(str(MAC[index])+' >>> '+IPS[index]+'\n')
						lineas = leer_archivo_mac_intrusa.readline()
						index += 1
			leer_archivo_mac_intrusa.close()
			escribir_archivo_mac_intrusa.close()
		else:
			print('\033[91m Error. No se Puede Almacenar el Archivo: ', workspaces)
	else:
		print('\033[91m No se Puedo Almacenar el Archivo: ', workspaces)

def Eliminar_Objetos_Duplicados(IPS, Vendor, HOSTNAME, MAC, MAC_FILE):

	IPS = list(set(IPS))
	Vendor = list(set(Vendor))
	HOSTNAME = list(set(HOSTNAME))
	MAC = list(set(MAC))
	MAC_FILE = list(set(MAC_FILE))

def run_MAC_Pertain():
	run = False
	while run != True :
		MAC_Pertain()
		Eliminar_Objetos_Duplicados(IPS, Vendor, HOSTNAME, MAC, MAC_FILE)

def run_MAC_Not_Pertain():
	run =False
	while run != True:
		MAC_Not_Pertain()
		Eliminar_Objetos_Duplicados(IPS, Vendor, HOSTNAME, MAC, MAC_FILE)

def run_MAC_All():
	run = False
	while  run != True:
		MAC_All()
	Eliminar_Objetos_Duplicados(IPS, Vendor, HOSTNAME, MAC, MAC_FILE)

def get_Archivo():
	global archivo
	return archivo

def set_Archivo(archivos):
	global archivo
	archivo = archivos

def get_IPScanners():
	global IPScanners
	return IPScanners

def set_IPScanners(IPScannersx):
	global IPScanners
	IPScanners = IPScannersx
