#Diseñado y Desarrollado por: Menkar Cantor Molina - menkar91@gmail.com // Marto Nieto Guerrero -  marto.nieto.g16@gmail.com 
import nmap
import mostrarOS
import sys
import os

global IPS
global Vendor
global HOSTNAME
global MAC 
global MAC_FILE
global nm

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
				Save_MAC_Not_Pertain(get_Archivo_MAC_Intruso())
				hosts_intrusos_activos += 1
				index += 1
		print('\n\033[92m Hosts Legitimos Activos: ', '\033[0m'+str(hosts_legitimos_activos))
		print('\033[92m Hosts Intrusos Activos: ', '\033[0m'+str(hosts_intrusos_activos))
		print('\033[92m Total de Hosts Activos: ', '\033[0m'+str(hosts_legitimos_activos + hosts_intrusos_activos))
	else:
		print('\033[91m Error. No se ha Escaneado la Red!')
		exit()	

def MAC_Not_Pertain():
	index = 0
	hosts_legitimos_activos = 0
	hosts_intrusos_activos = 0
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
			if (MAC[index]+'\n' in MAC_FILE) != True:
				hosts_intrusos_activos += 1
				print('\033[91m'+' Estado: No Pertenece a la Red')
				Save_MAC_Not_Pertain(get_Archivo_MAC_Intruso())
				index += 1
			else:
				hosts_legitimos_activos += 1
				index += 1
		print('\n\033[92m Hosts Legitimos Activos: ', '\033[0m'+str(hosts_legitimos_activos))
		print('\033[92m Hosts Intrusos Activos: ', '\033[0m'+str(hosts_intrusos_activos))
		print('\033[92m Total de Hosts Activos: ', '\033[0m'+str(hosts_legitimos_activos + hosts_intrusos_activos))
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
				print('\033[91m'+' Estado: No Pertenece a la Red')
				Save_MAC_Not_Pertain(get_Archivo_MAC_Intruso())
				hosts_intrusos_activos += 1
				index += 1
		print('\n\033[92m Hosts Legitimos Activos: ', '\033[0m'+str(hosts_legitimos_activos))
		print('\033[92m Hosts Intrusos Activos: ', '\033[0m'+str(hosts_intrusos_activos))
		print('\033[92m Total de Hosts Activos: ', '\033[0m'+str(hosts_legitimos_activos + hosts_intrusos_activos))
	else:
		print('\033[91m Error. No se ha Escaneado la Red!')
		exit()

def Save_MAC_Not_Pertain(workspaces):
	index = 0
	caracter = '{'+'}'
	if len(IPS) != 0:
		escribir_archivo_mac_intrusa = open(workspaces , 'w')
		leer_archivo_mac_intrusa = open(workspaces, 'r')
		lineas = leer_archivo_mac_intrusa.readline()
		if len(MAC) != 0:
			while index != len(MAC):
				if (MAC[index] in MAC_FILE) != True:
					if (lineas in MAC)!= True:
						escribir_archivo_mac_intrusa.write((lineas+'\n'))
						lineas = leer_archivo_mac_intrusa.readline()
						index += 1
			leer_archivo_mac_intrusa.close()
			escribir_archivo_mac_intrusa.close()
		else:
			print('\033[91m Error. No se Puede Almacenar el Archivo: ', workspaces)
	else:
		print('\033[91m No se Puedo Almacenar el Archivo: ', workspaces)

def run_MAC_Pertain():
	run = False
	while run != True :
		MAC_Pertain()
		init()
		Load_File_MAC_Pertain(get_Archivo())
		Scan_Net(get_IPScanners())

def run_MAC_Not_Pertain():
	run =False
	while run != True:
		MAC_Not_Pertain()
		init()
		Load_File_MAC_Pertain(get_Archivo())
		Scan_Net(get_IPScanners())

def run_MAC_All():
	run = False
	while  run != True:
		MAC_All()
		init()
		Load_File_MAC_Pertain(get_Archivo())
		Scan_Net(get_IPScanners())

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

def get_Archivo_MAC_Intruso():
	global archivos_mac_intruso
	return archivos_mac_intruso

def set_Archivo_MAC_Intruso(archivos_mac_intrusos):
	global archivos_mac_intruso
	archivos_mac_intruso = archivos_mac_intrusos

def init():
	IPS.clear()
	Vendor.clear()
	MAC.clear()
	HOSTNAME.clear()
	MAC_FILE.clear()