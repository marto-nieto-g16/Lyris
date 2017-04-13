import nmap
import os

global nm
nm = nmap.PortScanner()

def sudo_host(hosts):
    
    lastnm = nm.get_nmap_last_output()

    if len(lastnm) > 0:
        try:
            nm.analyse_nmap_xml_scan(lastnm)
        except:
            pass
        else:
            if nm.command_line() == 'nmap -oX - -O '+str(hosts) :
                return

    if os.getuid() == 0:
        nm.scan(hosts, arguments='-O')
    else :
        nm.scan(hosts, arguments='-O', sudo=True)

def Mostrar_OS(hosts):
    try:
        assert('osmatch' in nm[hosts])
        assert(len(nm[hosts]['osmatch'][0]['osclass']) > 0)
        print('\033[92m Compañia/Organizacion (Comunidad): '+'\033[0m'+'{}'.format(nm[hosts]['osmatch'][0]['osclass'][0]['vendor']))
    except:
        print('\033[92m Compañia/Organizacion (Comunidad): '+'\033[0m'+'Unknown')

def Mostrar_Version_OS(hosts):
     try:        
        assert('osmatch' in nm[hosts])
        print('\033[92m Version OS'+'\033[0m'+': {}'.format(nm[hosts]['osmatch'][0]['name']))
        assert('accuracy' in nm[hosts]['osmatch'][0])
        assert('line' in nm[hosts]['osmatch'][0])

        assert('osclass' in nm[hosts]['osmatch'][0])
        assert('type' in nm[hosts]['osmatch'][0]['osclass'][0])
        assert('osfamily' in nm[hosts]['osmatch'][0]['osclass'][0])
        assert('osgen' in nm[hosts]['osmatch'][0]['osclass'][0])
        assert('accuracy' in nm[hosts]['osmatch'][0]['osclass'][0])
     except:
         print('\033[92m Version OS: '+'\033[0m'+'Unknown')