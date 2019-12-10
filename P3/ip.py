from ethernet import *
from arp import *
from fcntl import ioctl
import subprocess
import math
SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b
#Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
#por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols={}
#Valor inicial para el IPID
IPID = 0
#Valor de ToS por defecto
DEFAULT_TOS = 0
#Tamaño mínimo de la cabecera IP
IP_MIN_HLEN = 20
#Tamaño máximo de la cabecera IP
IP_MAX_HLEN = 60
#Valor de TTL por defecto
DEFAULT_TTL = 64
#Protocolos
ICMP = 1
TCP = 6
UDP = 17


def chksum(msg):
    '''
        Nombre: chksum
        Descripción: Esta función calcula el checksum IP sobre unos datos de entrada dados (msg)
        Argumentos:
            -msg: array de bytes con el contenido sobre el que se calculará el checksum
        Retorno: Entero de 16 bits con el resultado del checksum en ORDEN DE RED
    '''
    s = 0
    for i in range(0, len(msg), 2):
        if (i+1) < len(msg):
            a = msg[i]
            b = msg[i+1]
            s = s + (a+(b << 8))
        elif (i+1)==len(msg):
            s += msg[i]
        else:
            raise 'Error calculando el checksum'
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def getMTU(interface):
    '''
        Nombre: getMTU
        Descripción: Esta función obteiene la MTU para un interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la MTU
        Retorno: Entero con el valor de la MTU para la interfaz especificada
    '''
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    ifr = struct.pack('16sH', interface.encode("utf-8"), 0)
    mtu = struct.unpack('16sH', ioctl(s,SIOCGIFMTU, ifr))[1]

    s.close()

    return mtu

def getNetmask(interface):
    '''
        Nombre: getNetmask
        Descripción: Esta función obteiene la máscara de red asignada a una interfaz
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la máscara
        Retorno: Entero de 32 bits con el valor de la máscara de red
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
       SIOCGIFNETMASK,
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]


def getDefaultGW(interface):
    '''
        Nombre: getDefaultGW
        Descripción: Esta función obteiene el gateway por defecto para una interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar el gateway
        Retorno: Entero de 32 bits con la IP del gateway
    '''
    p = subprocess.Popen(['ip r | grep default | awk \'{print $3}\''], stdout=subprocess.PIPE, shell=True)
    dfw = p.stdout.read().decode('utf-8')
    print(dfw)
    return struct.unpack('!I',socket.inet_aton(dfw))[0]



def process_IP_datagram(us,header,data,srcMac):
    '''
        Nombre: process_IP_datagram
        Descripción: Esta función procesa datagramas IP recibidos.
            Se ejecuta una vez por cada trama Ethernet recibida con Ethertype 0x0800
            Esta función debe realizar, al menos, las siguientes tareas:
                -Extraer los campos de la cabecera IP (includa la longitud de la cabecera)
                -Calcular el checksum sobre los bytes de la cabecera IP
                    -Comprobar que el resultado del checksum es 0. Si es distinto el datagrama se deja de procesar
                -Analizar los bits de de MF y el offset. Si el offset tiene un valor != 0 dejar de procesar el datagrama (no vamos a reensamblar)
                -Loggear (usando logging.debug) el valor de los siguientes campos:
                    -Longitud de la cabecera IP
                    -IPID
                    -Valor de las banderas DF y MF
                    -Valor de offset
                    -IP origen y destino
                    -Protocolo
                -Comprobar si tenemos registrada una función de callback de nivel superior consultando el diccionario protocols y usando como
                clave el valor del campo protocolo del datagrama IP.
                    -En caso de que haya una función de nivel superior registrada, debe llamarse a dicha funciñón
                    pasando los datos (payload) contenidos en el datagrama IP.

        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido del datagrama IP
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''

    if chksum(data) != 0:
        return

    if data[15:16] == 1 or data[16:29] != 0:
        return


    logging.debug(data[4:8]) #IHL (Longitud de cabecera)
    logging.debug(data[11:13]) #IPID
    logging.debug(data[14:15]) #DF
    logging.debug(data[15:16]) #MF
    logging.debug(data[16:29]) #Offset
    logging.debug(data[33:37]) #IP origen
    logging.debug(data[37:41]) #IP destino
    logging.debug(data[30:31]) #Protocolo

    if data[30:31] in protocols:
        funcion = protocols[data[30:31]]
        funcion(us,header,data,data[33:37])






def registerIPProtocol(callback,protocol):
    '''
        Nombre: registerIPProtocol
        Descripción: Esta función recibirá el nombre de una función y su valor de protocolo IP asociado y añadirá en la tabla
            (diccionario) de protocolos de nivel superior dicha asociación.
            Este mecanismo nos permite saber a qué función de nivel superior debemos llamar al recibir un datagrama IP  con un
            determinado valor del campo protocolo (por ejemplo TCP o UDP).
            Por ejemplo, podemos registrar una función llamada process_UDP_datagram asociada al valor de protocolo 17 y otra
            llamada process_ICMP_message asocaida al valor de protocolo 1.
        Argumentos:
            -callback_fun: función de callback a ejecutar cuando se reciba el protocolo especificado.
                La función que se pase como argumento debe tener el siguiente prototipo: funcion(us,header,data,srcIp):
                Dónde:
                    -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
                    -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
                    -data: payload del datagrama IP. Es decir, la cabecera IP NUNCA se pasa hacia arriba.
                    -srcIP: dirección IP que ha enviado el datagrama actual.
                La función no retornará nada. Si un datagrama se quiere descartar basta con hacer un return sin valor y dejará de procesarse.
            -protocol: valor del campo protocolo de IP para el cuál se quiere registrar una función de callback.
        Retorno: Ninguno
    '''
    global protocols
    if protocol is not None and callback is not None and protocol == ICMP:
        protocols[protocol] = callback
    elif protocol is not None and callback is not None and protocol == TCP:
        protocols[protocol] = callback
    elif protocol is not None and callback is not None and protocol == UDP:
        protocols[protocol] = callback
    else:
        return

def initIP(interface,opts=None):
    global myIP, MTU, netmask, defaultGW,ipOpts
    '''
        Nombre: initIP
        Descripción: Esta función inicializará el nivel IP. Esta función debe realizar, al menos, las siguientes tareas:
            -Llamar a initARP para inicializar el nivel ARP
            -Obtener (llamando a las funciones correspondientes) y almacenar en variables globales los siguientes datos:
                -IP propia
                -MTU
                -Máscara de red (netmask)
                -Gateway por defecto
            -Almacenar el valor de opts en la variable global ipOpts
            -Registrar a nivel Ethernet (llamando a registerCallback) la función process_IP_datagram con el Ethertype 0x0800
        Argumentos:
            -interface: cadena de texto con el nombre de la interfaz sobre la que inicializar ip
            -opts: array de bytes con las opciones a nivel IP a incluir en los datagramas o None si no hay opciones a añadir
        Retorno: True o False en función de si se ha inicializado el nivel o no
    '''
    if initARP(interface) == False:
        return False

    myIP = getIP(interface)
    myIP = myIP.to_bytes(4, byteorder='big')
    MTU = getMTU(interface)
    netmask = getNetmask(interface)
    netmask = netmask.to_bytes(4, byteorder='big')
    defaultGW = getDefaultGW(interface)
    defaultGW = defaultGW.to_bytes(4, byteorder='big')
    ipOpts = opts
    registerCallback(process_IP_datagram, b'\x08\x00')
    if myIP is None or MTU is None or netmask is None or defaultGW is None:
        return False
    return True


def sendIPDatagram(dstIP,data,protocol):
    global IPID, ipOpts, netmask, myIP, defaultGW
    '''
        Nombre: sendIPDatagram
        Descripción: Esta función construye un datagrama IP y lo envía. En caso de que los datos a enviar sean muy grandes la función
        debe generar y enviar el número de fragmentos IP que sean necesarios.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Determinar si se debe fragmentar o no y calcular el número de fragmentos
            -Para cada datagrama o fragmento:
                -Construir la cabecera IP con los valores que corresponda.Incluir opciones en caso de que ipOpts sea distinto de None
                -Calcular el checksum sobre la cabecera y añadirlo a la cabecera en la posición correcta
                -Añadir los datos a la cabecera IP
                -En el caso de que sea un fragmento ajustar los valores de los campos MF y offset de manera adecuada
                -Enviar el datagrama o fragmento llamando a sendEthernetFrame. Para determinar la dirección MAC de destino
                al enviar los datagramas:
                    -Si la dirección IP destino está en mi subred:
                        -Realizar una petición ARP para obtener la MAC asociada a dstIP y usar dicha MAC
                    -Si la dirección IP destino NO está en mi subred:
                        -Realizar una petición ARP para obtener la MAC asociada al gateway por defecto y usar dicha MAC
            -Para cada datagrama (no fragmento):
                -Incrementar la variable IPID en 1.
        Argumentos:
            -dstIP: entero de 32 bits con la IP destino del datagrama
            -data: array de bytes con los datos a incluir como payload en el datagrama
            -protocol: valor numérico del campo IP protocolo que indica el protocolo de nivel superior de los datos
            contenidos en el payload. Por ejemplo 1, 6 o 17.
        Retorno: True o False en función de si se ha enviado el datagrama correctamente o no

    '''
    longitud_opciones = 0
    if(ipOpts != None):
        longitud_opciones = len(ipOpts)

    header = bytes()
    #primer_byte = bytes()

    tam_header = bytearray()
    #header += b'\x00'
    primer_byte = "{0:b}".format(4) #Version
    primer_byte = "0" + primer_byte
    tam_header = 20 + longitud_opciones
    print("TAM\n", tam_header)
    tam_header = tam_header/4
    primer_byte += "{0:b}".format(int(tam_header))
    if len(primer_byte) < 8:
        primer_byte = "0" + primer_byte

    for b in getbytes(iter(primer_byte)):
        print("PRUEBA\n", b)
    
    header += b'\x00' #Type of service
    header += bytes([20+longitud_opciones+len(data)]) #Longitud total del datagrama
    header += bytes([IPID])

    if len(data)+longitud_opciones+20 <= MTU: #enviamos paquete completo
        header += b'\x00\x00' #Flags + offset
        header += b'\x40' #Time to live
        header += protocol.to_bytes(1, byteorder='big')
        header += b'\x00\x00' #Por defecto 0
        header += myIP
        header += dstIP.to_bytes(4, byteorder='big')
        if(ipOpts != None):
            header += ipOpts
        checksum = chksum(header)
        header[11:13] = struct.pack('!H',checksum)
        header += data

        #Enviamos el datagrama
        if (dstIP.to_bytes(4, byteorder='big') & netmask) == (myIP & netmask):
            mac = ARPResolution(dstIP)
            if sendEthernetFrame(header,len(header),b'\x08\x00',mac) == -1:
                return False
        else:
            mac = ARPResolution(defaultGW)
            if sendEthernetFrame(header,len(header),b'\x08\x00',mac) == -1:
                return False
        IPID+=1
    else: #aqui fragmentamos
        tam_max_fragmento = MTU - 20 - longitud_opciones
        aux = tam_max_fragmento
        while(aux % 8 != 0):
            aux-=1

        tam_max_fragmento = aux

        num_fragmento = len(data)/tam_max_fragmento

        if len(data) % tam_max_fragmento != 0:
            num_fragmento = math.ceil(len(header)/tam_max_fragmento)

        offset = 0
        for i in range(num_fragmento):
            header += b'\x00\x00' #Flags + offset
            header += b'\x40' #Time to live
            header += protocol.to_bytes(1, byteorder='big')
            header += b'\x00\x00' #Por defecto 0
            header += myIP
            header += dstIP.to_bytes(4, byteorder='big')
            if(ipOpts != None):
                header += ipOpts
            #Enviamos el primer fragmento
            if i == 0:
                header[6:7] = (header[6:7] | b'\x20')
                header[7:8] = (header[7:8] | b'\x00')
                if (dstIP.to_bytes(4, byteorder='big') & netmask) == (myIP & netmask):
                    mac = ARPResolution(dstIP)
                    if sendEthernetFrame(header,len(header),b'\x08\x00',mac) == -1:
                        return False
                else:
                    mac = ARPResolution(defaultGW)
                    if sendEthernetFrame(header,len(header),b'\x08\x00',mac) == -1:
                        return False
                IPID+=1
            #Enviamos el ultimo fragmento
            elif i == num_fragmento-1:
                offset += tam_max_fragmento / 8
                header[6:8] = (b'\x00' << 8 | offset.to_bytes(2, byteorder='big'))
                if (dstIP.to_bytes(4, byteorder='big') & netmask) == (myIP & netmask):
                    mac = ARPResolution(dstIP)
                    if sendEthernetFrame(header,len(header),b'\x08\x00',mac) == -1:
                        return False
                else:
                    mac = ARPResolution(defaultGW)
                    if sendEthernetFrame(header,len(header),b'\x08\x00',mac) == -1:
                        return False
                IPID+=1
            #Enviamos el resto de fragmentos
            else:
                offset += tam_max_fragmento/8
                tam_max_fragmento = tam_max_fragmento + tam_max_fragmento
                header[6:8] = (b'\x20' << 8 | offset.to_bytes(2, byteorder='big'))
                if (dstIP.to_bytes(4, byteorder='big') & netmask) == (myIP & netmask):
                    mac = ARPResolution(dstIP)
                    if sendEthernetFrame(header,len(header),b'\x08\x00',mac) == -1:
                        return False
                else:
                    mac = ARPResolution(defaultGW)
                    if sendEthernetFrame(header,len(header),b'\x08\x00',mac) == -1:
                        return False
                IPID+=1
    return True

#Funcion complementaria para transformar bits a bytes
def getbytes(bits):
    done = False
    while not done:
        byte = 0
        for _ in range(0, 8):
            try:
                bit = next(bits)
            except StopIteration:
                bit = 0
                done = True
            byte = (byte << 1) | int(bit)
        yield byte