import nmap
import mostrarOS
import sys
import os

global archivo_mac_legs # Variable para la cargar el archivo mac_legs
global workspaces
global lineas

global mac_intrusa
global mac_legs
global IP
global IPScanner

global nm 	# Variable declarada para ejecutar los comando de Nmap
nm = nmap.PortScanner() # se le asigna a nm las funciones de escaner de red  

IPScanner = ''
workspaces = ''

mac_intrusa = []
mac_legs = []
IPS = []

print('Archivo con las Mac Legitimas >>> ', end='')
workspaces = input()
print('Direccion IP de La Red a Escanear >>> ', end='')	
IPScanner = input()

def Cargar_Archivo_MAC(workspaces):

	try:	
		archivo_mac_legs = open(workspaces, 'r')

		lineas = archivo_mac_legs.readline()
		index = 0

		while lineas != "":
			mac_legs.insert(index, lineas)
			lineas = archivo_mac_legs.readline()
			index += 1
		archivo_mac_legs.close()

	except FileNotFoundError as e:
		print('Error. No se Localizo el Archivo: ', workspaces)
		print('\nArchivo con las Mac Legitimas >>> ', end='')
		workspaces = input()

	
def MAC_Intusas():

	nm.scan(IPScanner+'/24', arguments='-sP', sudo=True) # Comando de Escaner de Nmap
	
	activos = 0
	index_mac_intrusa = 0
	index_IP = 0

	for hosts in nm.all_hosts():
		if 'mac' in nm[hosts]['addresses']:
			
			activos += 1

			if (str(nm[hosts]['addresses']['mac'])+'\n' in mac_legs)!= True:
				
				print('\033[0m''\nBuscando Hosts Intrusos')
				mac_intrusa.insert(index_mac_intrusa, ('{}'.format(nm[hosts]['addresses']['mac'])))
			
				print('\033[93m''\n'+ '{}'.format(nm[hosts]['addresses']['ipv4']), end='')
				print('\033[96m'' : '+'{}'.format(nm[hosts]['vendor']))
				
				if str(nm[hosts].hostname()) != '':

					print('\033[92m''Nombre del Host : %s (%s)''\033[0m' % ('', nm[hosts].hostname()))

				else:
					print('\033[92m''Nombre del Host :''\033[0m'' Unknown  (Desconocido)')

				mostrarOS.sudo_host('{}'.format(nm[hosts]['addresses']['ipv4']))
				mostrarOS.Mostrar_Version_OS('{}'.format(nm[hosts]['addresses']['ipv4']))

				print('\033[92m'' Estado:''\033[91m'' No Pertenece a la Red')
				index_mac_intrusa += 1

			else:
				IPS.insert(index_IP, '{}'.format(nm[hosts]['addresses']['mac']))
				index_IP += 1

	print('\n\033[0m''Total Hosts Legitimos: ''\033[92m', index_IP )
	print('\033[0m''Total Hosts Intrusos: ''\033[91m', index_mac_intrusa)
	print('\033[0m''Total Hosts Activos: ''\033[92m', activos)

def MAC_Legitimas():

	nm.scan(IPScanner+'/24', arguments='-sP', sudo=True) # Comando de Escaner de Nmap
	
	activos = 0
	index_mac_intrusa = 0
	index_IP = 0

	for hosts in nm.all_hosts():
		if 'mac' in nm[hosts]['addresses']:
			
			activos += 1

			if (str(nm[hosts]['addresses']['mac'])+'\n' in mac_legs)== True:
				
				print('\033[0m''\nBuscando Hosts Legitimos')
				IPS.insert(index_IP, ('{}'.format(nm[hosts]['addresses']['mac'])))
			
				print('\033[93m''\n'+ '{}'.format(nm[hosts]['addresses']['ipv4']), end='')
				print('\033[96m'' : '+'{}'.format(nm[hosts]['vendor']))
				
				if str(nm[hosts].hostname()) != '':

					print('\033[92m''Nombre del Host : %s (%s)''\033[0m' % ('', nm[hosts].hostname()))

				else:
					print('\033[92m''Nombre del Host :''\033[0m'' Unknown  (Desconocido)')

				mostrarOS.sudo_host('{}'.format(nm[hosts]['addresses']['ipv4']))
				mostrarOS.Mostrar_Version_OS('{}'.format(nm[hosts]['addresses']['ipv4']))

				print('\033[92m'' Estado: Pertenece a la Red')
				index_IP += 1

			else:
				mac_intrusa.insert(index_mac_intrusa, '{}'.format(nm[hosts]['addresses']['mac']))
				index_mac_intrusa += 1

	print('\n\033[0m''Total Hosts Legitimos: ''\033[92m', index_IP )
	print('\033[0m''Total Hosts Intrusos: ''\033[91m', index_mac_intrusa)
	print('\033[0m''Total Hosts Activos: ''\033[92m', activos)

def MAC_All():

	nm.scan(IPScanner+'/24', arguments='-sP', sudo=True) # Comando de Escaner de Nmap
	
	activos = 0
	index_mac_intrusa = 0
	index_IP = 0

	for hosts in nm.all_hosts():
		if 'mac' in nm[hosts]['addresses']:
			
			activos += 1

			if (str(nm[hosts]['addresses']['mac'])+'\n' in mac_legs)!= True:
				
				
				mac_intrusa.insert(index_mac_intrusa, ('{}'.format(nm[hosts]['addresses']['mac'])))
			
				print('\033[93m''\n'+ '{}'.format(nm[hosts]['addresses']['ipv4']), end='')
				print('\033[96m'' : '+'{}'.format(nm[hosts]['vendor']))
				
				if str(nm[hosts].hostname()) != '':

					print('\033[92m''Nombre del Host : %s (%s)''\033[0m' % ('', nm[hosts].hostname()))

				else:
					print('\033[92m''Nombre del Host :''\033[0m'' Unknown  (Desconocido)')

				mostrarOS.sudo_host('{}'.format(nm[hosts]['addresses']['ipv4']))
				mostrarOS.Mostrar_Version_OS('{}'.format(nm[hosts]['addresses']['ipv4']))

				print('\033[92m'' Estado:''\033[91m'' No Pertenece a la Red')
				index_mac_intrusa += 1

			else:
				IPS.insert(index_IP, '{}'.format(nm[hosts]['addresses']['mac']))
				mac_intrusa.insert(index_mac_intrusa, ('{}'.format(nm[hosts]['addresses']['mac'])))
			
				print('\033[93m''\n'+ '{}'.format(nm[hosts]['addresses']['ipv4']), end='')
				print('\033[96m'' : '+'{}'.format(nm[hosts]['vendor']))
				
				if str(nm[hosts].hostname()) != '':

					print('\033[92m''Nombre del Host : %s (%s)''\033[0m' % ('', nm[hosts].hostname()))

				else:
					print('\033[92m''Nombre del Host :''\033[0m'' Unknown  (Desconocido)')

				mostrarOS.sudo_host('{}'.format(nm[hosts]['addresses']['ipv4']))
				mostrarOS.Mostrar_Version_OS('{}'.format(nm[hosts]['addresses']['ipv4']))

				print('\033[92m'' Estado:''\033[91m'' Pertenece a la Red')
				index_IP += 1

	print('\n\033[0m''Total Hosts Legitimos: ''\033[92m', index_IP )
	print('\033[0m''Total Hosts Intrusos: ''\033[91m', index_mac_intrusa)
	print('\033[0m''Total Hosts Activos: ''\033[92m', activos)


def Guardar_Mac_Intrusa():

	index = 0
	escribir_archivo_mac_intrusa = open(('intruso_'+workspaces) , 'w')
	leer_archivo_mac_intrusa = open(('intruso_'+workspaces), 'r')
	lineas = leer_archivo_mac_intrusa.readline()

	while index != len(mac_intrusa):
		if (lineas in mac_intrusa)!= True:
			escribir_archivo_mac_intrusa.write(str(mac_intrusa[index])+' >>> '+IPS[index]+'\n')
			lineas = leer_archivo_mac_intrusa.readline()
			index += 1
	leer_archivo_mac_intrusa.close()
	escribir_archivo_mac_intrusa.close()

try:
	run1 = True
	while run1 != False:
		
		comando_lyris = ''
		print('lyris >>> ', end='')
		comando_lyris = input()

		if comando_lyris == 'mac':
			
			run = True
			while run != False:
				
				Cargar_Archivo_MAC(workspaces)
				MAC_Intusas()
				IPS = list(set(IPS))
				mac_intrusa = list(set(mac_intrusa))
				mac_legs = list(set(mac_legs))
				Guardar_Mac_Intrusa()

		elif comando_lyris == ' mac -pertain':
			
			Cargar_Archivo_MAC(workspaces)
			MAC_Legitimas()
			
			IPS = list(set(IPS))
			mac_intrusa = list(set(mac_intrusa))
			mac_legs = list(set(mac_legs))

		elif comando_lyris == 'mac all':
			
			Cargar_Archivo_MAC(workspaces)
			MAC_All()
			IPS = list(set(IPS))
			mac_intrusa = list(set(mac_intrusa))
			mac_legs = list(set(mac_legs))
		else:
			print('Error. Comando Desconocido')

except KeyboardInterrupt as e:
	print(' Proceso Interruntido')