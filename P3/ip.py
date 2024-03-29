from ethernet import *
from arp import *
from fcntl import ioctl
import subprocess
import math

import pdb

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
    global ipOpts

    if ipOpts is None:
        print(data[:20])
        if chksum(data[:20]) != 0:
            print("error cheksum\n")
            return
        print("Header IP checksum correcto")
    else:
        if chksum(data[:60]) != 0:
            print("error cheksum con opciones\n")
            return
        print("Header IP checksum correcto con opciones")

    print("PROCESS IP FRAME")
    if data[6:8] == '0x0000':
        print("No reensamblar")
        return

    logging.debug("Longitud cabecera: {}".format(data[0:1])) #IHL (Longitud de cabecera)
    logging.debug("IPID:{}".format(data[4:6])) #IPID
    logging.debug("DF , MF y offset:{}".format(data[6:8])) #DF, MF y offset
    logging.debug("Protocolo:{}".format(data[9:10])) #Protocolo
    logging.debug("IP origen:{}".format(data[12:16])) #IP origen
    logging.debug("IP destino:{}".format(data[16:20])) #IP destino

    if struct.unpack('!B', data[9:10])[0] in protocols:
        print("En ip tenemos protocolo de nivel superior :{}".format(struct.unpack('!B', data[9:10])[0]))
        funcion = protocols[struct.unpack('!B', data[9:10])[0]]
        if ipOpts is None:                  #si no hay opciones mandamos el payload desde el byte 20
            funcion(us,header,data[20:],data[12:16])    #pasamos la IP origen es decir la que nos han enviado
        else:
            funcion(us,header,data[60:],data[12:16])


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
    myIP = myIP.to_bytes(4, byteorder='big')    #bytes
    MTU = getMTU(interface)                     #entero 32 bits
    netmask = getNetmask(interface)
    netmask = netmask.to_bytes(4, byteorder='big')  #bytes
    defaultGW = getDefaultGW(interface)
    defaultGW = defaultGW.to_bytes(4, byteorder='big') #bytes
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
    #pdb.set_trace()
    tamanio_fragmento = 0
    longitud_opciones = 0
    if(ipOpts != None):
        longitud_opciones = len(ipOpts)

    header = bytes() #Header auxiliar para calcular el checksum
    header_final = bytes()
    #primer_byte = bytes()
    tamanio_datagrama = 20+longitud_opciones+len(data)

    print("Tamanio data", len(data))

    tam_header = bytearray()
    #header += b'\x00'
    primer_byte = "{0:04b}".format(4) #Version

    tam_header = 20 + longitud_opciones
    tam_header = tam_header//4

    primer_byte += "{0:04b}".format(tam_header)
    print(primer_byte)
    dato = 0x00

    i = 0
    b = 7
    while i < len(primer_byte):
        dato=dato|(int(primer_byte[i])<<b)
        i+=1
        b-=1


    print(dato.to_bytes(1, byteorder='big'))

    header += dato.to_bytes(1, byteorder='big') #Version e IHL
    header += b'\x00' #Type of service
    header += tamanio_datagrama.to_bytes(2, byteorder='big') #Longitud total del datagrama
    header += IPID.to_bytes(2, byteorder='big') #Identificador

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



        #header_final += bytes(hex(dato),encoding='utf8') #Version e IHL

        header_final += dato.to_bytes(1, byteorder='big')
        header_final += b'\x00' #Type of service
        header_final += tamanio_datagrama.to_bytes(2, byteorder='big') #Longitud total del datagrama
        header_final += IPID.to_bytes(2, byteorder='big') #Identificador
        header_final += b'\x00\x00' #Flags + offset
        header_final += b'\x40' #Time to live
        header_final += protocol.to_bytes(1, byteorder='big') #protocolo
        header_final += checksum.to_bytes(2, byteorder='little') #cheksum calculado previamente
        #header_final += b'\x00\x00' #Por defecto 0
        header_final += myIP #Ip origen
        header_final += dstIP.to_bytes(4, byteorder='big') #Ip destino
        if(ipOpts != None):
            header_final += ipOpts

        print("vamos a enviar unos datos", data)
        print("con cabecera:", header_final)
        print("y checksum:", checksum)
        header_final += data

        #Enviamos el datagrama
        if (dstIP.to_bytes(4, byteorder='big')[0] & netmask[0]) == (myIP[0] & netmask[0]):
            mac = ARPResolution(dstIP)
            print("Envio datagrama en mi subred...\n")
            print(header_final)
            if sendEthernetFrame(header_final,len(header_final),b'\x08\x00',mac) == -1:
                return False
        else:
            print("Envio datagrama fuera de mi subred...\n")
            mac = ARPResolution(defaultGW)
            if sendEthernetFrame(header_final,len(header_final),b'\x08\x00',mac) == -1:
                return False
        IPID+=1
    else: #aqui fragmentamos
        header_fragmento = bytes()

        header += dato.to_bytes(1, byteorder='big') #Version e IHL
        header += b'\x00' #Type of service
        

        tam_max_fragmento = MTU - 20 - longitud_opciones
        aux = tam_max_fragmento
        while(aux % 8 != 0):                                       
            aux-=1

        tam_max_fragmento = aux #1480 en el ejemplo
        tamanio_fragmento = tam_max_fragmento

        header += tamanio_fragmento.to_bytes(2, byteorder='big') #Longitud total del fragmento
        header += bytes([IPID]) #Identificador

        num_fragmento = len(data)/tam_max_fragmento

        if len(data) % tam_max_fragmento != 0:
            num_fragmento = math.ceil(len(data)/tam_max_fragmento) #antes pusistes len(header) creo que es data

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

            checksum = chksum(header)

            #Enviamos el primer fragmento
            if i == 0:
                #Creamos el fragmento que vamos a enviar  partir de la cabecera (header base)

                header_fragmento += dato.to_bytes(1, byteorder='big') #Version e IHL
                header_fragmento += b'\x00' #Type of service
                header_fragmento += tamanio_fragmento.to_bytes(2, byteorder='big') #Longitud total del datagrama
                header_fragmento += bytes([IPID]) #Identificador
                offset_flags_ini = 0x0000
                offset_flags_ini = offset_flags_ini |(1 << 13) #MF = 1, offset = 0
                header_fragmento += offset_flags_ini.to_bytes(2, byteorder='big') #Banderas IP y offset
                header_fragmento += b'\x40' #Time to live
                header_fragmento += protocol.to_bytes(1, byteorder='big')
                header_fragmento += struct.pack('!H',checksum)
                header_fragmento += myIP
                header_fragmento += dstIP.to_bytes(4, byteorder='big')
                if(ipOpts != None):
                    header_fragmento += ipOpts

                header_fragmento += data[0:tam_max_fragmento]

                
            #Enviamos el ultimo fragmento
            elif i == num_fragmento-1:
                #este ultimo tiene tamanyo (tam_max_fragmento - el anterior el de arriba del todo) - tam_max_fragmento (el de ahora)
                header_fragmento += dato.to_bytes(1, byteorder='big') #Version e IHL
                header_fragmento += b'\x00' #Type of service
                header_fragmento += tamanio_fragmento.to_bytes(2, byteorder='big') #Longitud total del datagrama
                header_fragmento += bytes([IPID]) #Identificador

                offset_flags = 0x0000
                offset += tam_max_fragmento / 8
                offset_bits = "{0:b}".format(int(offset))

                i=len(offset_bits)-1
                for bit in offset_bits:
                    offset_flags=offset_flags|(int(bit) << i) #Offset
                    i-=1
                
                cero = 0
                offset_flags=offset_flags|(cero << 13) #MF = 0
                offset_flags=offset_flags|(cero << 14) #DF = 0
                offset_flags=offset_flags|(cero << 15) #Reservado 0

                header_fragmento += offset_flags.to_bytes(2, byteorder='big') #Offset
                header_fragmento += b'\x40' #Time to live
                header_fragmento += protocol.to_bytes(1, byteorder='big')
                header_fragmento += struct.pack('!H',checksum)
                header_fragmento += myIP
                header_fragmento += dstIP.to_bytes(4, byteorder='big')
                if(ipOpts != None):
                    header_fragmento += ipOpts
                header_fragmento += data[tam_max_fragmento:]
               
            #Enviamos el resto de fragmentos
            else:

                header_fragmento += dato.to_bytes(1, byteorder='big') #Version e IHL
                header_fragmento += b'\x00' #Type of service
                header_fragmento += tamanio_fragmento.to_bytes(2, byteorder='big') #Longitud total del datagrama
                header_fragmento += bytes([IPID]) #Identificador
                offset += tam_max_fragmento/8 
                offset_flags = 0x0000
                offset_bits = "{0:b}".format(int(offset))

                i=len(offset_bits)-1
                for bit in offset_bits:
                    offset_flags=offset_flags|(int(bit) << i) #Offset
                    i-=1

                uno = 1
                offset_flags=offset_flags|(uno << 13) #MF = 1     
                    
                inicio_data = tam_max_fragmento
                tam_max_fragmento = tam_max_fragmento + tam_max_fragmento
                header_fragmento += offset_flags.to_bytes(2, byteorder='big')
                header_fragmento += b'\x40' #Time to live
                header_fragmento += protocol.to_bytes(1, byteorder='big')
                header_fragmento += struct.pack('!H',checksum)
                header_fragmento += myIP
                header_fragmento += dstIP.to_bytes(4, byteorder='big')
                if(ipOpts != None):
                    header_fragmento += ipOpts
                header_fragmento += data[inicio_data:tam_max_fragmento]

            #para no liarse tanto
            if (dstIP.to_bytes(4, byteorder='big')[0] & netmask[0]) == (myIP[0] & netmask[0]): #si esta en mi subred
                mac = ARPResolution(dstIP)
                print("Envio fragmento en mi subred")
                if sendEthernetFrame(header_fragmento,len(header_fragmento),b'\x08\x00',mac) == -1:
                    print("Error en envio")
                    return False
                header_fragmento = bytes()
            else:
                print("Envio fragmento fuera de mi subred")
                mac = ARPResolution(defaultGW)
                if sendEthernetFrame(header_fragmento,len(header_fragmento),b'\x08\x00',mac) == -1:
                    return False
                header_fragmento = bytes()
            #IPID+=1 mira a ver esto, creo que esta mal dice que es de cada datagrama no fragmento pero...

    return True

