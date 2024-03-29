import ip
from threading import Lock
import struct
import logging
import time
import pdb
ICMP_PROTO = 1


ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REPLY_TYPE = 0

timeLock = Lock()
icmp_send_times = {}


def icmp_chksum(msg):
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

def process_ICMP_message(us,header,data,srcIp):
    '''
        Nombre: process_ICMP_message
        Descripción: Esta función procesa un mensaje ICMP. Esta función se ejecutará por cada datagrama IP que contenga
        un 1 en el campo protocolo de IP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Calcular el checksum de ICMP:
                -Si es distinto de 0 el checksum es incorrecto y se deja de procesar el mensaje
            -Extraer campos tipo y código de la cabecera ICMP
            -Loggear (con logging.debug) el valor de tipo y código
            -Si el tipo es ICMP_ECHO_REQUEST_TYPE:
                -Generar un mensaje de tipo ICMP_ECHO_REPLY como respuesta. Este mensaje debe contener
                los datos recibidos en el ECHO_REQUEST. Es decir, "rebotamos" los datos que nos llegan.
                -Enviar el mensaje usando la función sendICMPMessage
            -Si el tipo es ICMP_ECHO_REPLY_TYPE:
                -Extraer del diccionario icmp_send_times el valor de tiempo de envío usando como clave los campos srcIP e icmp_id e icmp_seqnum
                contenidos en el mensaje ICMP. Restar el tiempo de envio extraído con el tiempo de recepción (contenido en la estructura pcap_pkthdr)
                -Se debe proteger el acceso al diccionario de tiempos usando la variable timeLock
                -Mostrar por pantalla la resta. Este valor será una estimación del RTT
            -Si es otro tipo:
                -No hacer nada

        Argumentos:
            -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
            -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
            -data: array de bytes con el conenido del mensaje ICMP
            -srcIP: dirección IP que ha enviado el datagrama actual.
        Retorno: Ninguno

    '''
    global icmp_send_times
    if icmp_chksum(data) != 0:
        logging.error('checksum icmp incorrecto')
        return
    else:
        print("checksum icmp correcto")    

    print("PROCESS ICMP MESSAGE")
    logging.debug("Tipo icmp:{}".format(data[:1])) #debug tipo codigo
    logging.debug("Codigo :{}".format(data[1:2])) #debug valor

    if struct.unpack('!B',data[:1])[0] == ICMP_ECHO_REQUEST_TYPE:
        #devolvemos el mensaje ahora reply con tipo reply, codigo del reply id el que nos envian y seqnum tambien el que nos envian
        #y solo los datos
        print("ahora vamos a enviar estos datos en forma de ping")
        print(data[8:])
        icmp_id = struct.unpack('!H',data[4:6])[0]
        icmp_seqnum = struct.unpack('!H',data[6:8])[0]
        srcIp = struct.unpack('!I', srcIp)[0]
        sendICMPMessage(data[8:], ICMP_ECHO_REPLY_TYPE, 0, icmp_id, icmp_seqnum, srcIp)
    elif struct.unpack('!B',data[:1])[0] == ICMP_ECHO_REPLY_TYPE:
        dstIp = srcIp
        icmp_id = data[4:6]
        icmp_seqnum = data[6:8]
        with timeLock:
            clave = bytes(dstIp+icmp_id+icmp_seqnum)
            print("Leyendo clave", clave)
            rtt = icmp_send_times[(clave)]
            rtt = header.ts.tv_sec - rtt                    #recepcion - tenvio es el tiempo total del paquete hasta haber llegado
            print("RTT:{}".format(rtt))
    else:
        return

def sendICMPMessage(data,type,code,icmp_id,icmp_seqnum,dstIP):
    '''
        Nombre: sendICMPMessage
        Descripción: Esta función construye un mensaje ICMP y lo envía.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Si el campo type es ICMP_ECHO_REQUEST_TYPE o ICMP_ECHO_REPLY_TYPE:
                -Construir la cabecera ICMP
                -Añadir los datos al mensaje ICMP
                -Calcular el checksum y añadirlo al mensaje donde corresponda
                -Si type es ICMP_ECHO_REQUEST_TYPE
                    -Guardar el tiempo de envío (llamando a time.time()) en el diccionario icmp_send_times
                    usando como clave el valor de dstIp+icmp_id+icmp_seqnum
                    -Se debe proteger al acceso al diccionario usando la variable timeLock

                -Llamar a sendIPDatagram para enviar el mensaje ICMP

            -Si no:
                -Tipo no soportado. Se devuelve False

        Argumentos:
            -data: array de bytes con los datos a incluir como payload en el mensaje ICMP
            -type: valor del campo tipo de ICMP
            -code: valor del campo code de ICMP
            -icmp_id: entero que contiene el valor del campo ID de ICMP a enviar
            -icmp_seqnum: entero que contiene el valor del campo Seqnum de ICMP a enviar
            -dstIP: entero de 32 bits con la IP destino del mensaje ICMP
        Retorno: True o False en función de si se ha enviado el mensaje correctamente o no

    '''
    global icmp_send_times

    #pdb.set_trace()
    cabecera_prueba = bytes()
    cabecera = bytes()
    mensaje_prueba = bytes()
    datagrama = bytes()

    if type == ICMP_ECHO_REQUEST_TYPE or type == ICMP_ECHO_REPLY_TYPE:
        #Cabecera de prueba para comprobar checksum
        cabecera_prueba += type.to_bytes(1, byteorder='big')        #tipo de mensaje ICMP
        cabecera_prueba += code.to_bytes(1, byteorder='big')      #code del icmp
        cabecera_prueba += b'\x00\x00' #rellenamos checksum con ceros por ahora para calcularlo
        cabecera_prueba += icmp_id.to_bytes(2, byteorder='big')
        cabecera_prueba += icmp_seqnum.to_bytes(2, byteorder='big')

        #calculamos ahora el checksum
        mensaje_prueba += cabecera_prueba
        mensaje_prueba += data


        cabecera += type.to_bytes(1, byteorder='big')
        cabecera += code.to_bytes(1, byteorder='big')
        icmp_checksum = icmp_chksum(mensaje_prueba)
        cabecera += icmp_checksum.to_bytes(2, byteorder='little')     #ojo el checksum se hace sobre cabecera_prueba + datos
        cabecera += icmp_id.to_bytes(2, byteorder='big')
        cabecera += icmp_seqnum.to_bytes(2, byteorder='big')

        datagrama += cabecera
        datagrama += data

        if type == ICMP_ECHO_REQUEST_TYPE:
            with timeLock:
                clave = bytes(dstIP+icmp_id+icmp_seqnum)
                print("Guardando clave", clave)
                icmp_send_times[clave] = time.time()
                

        ip.sendIPDatagram(dstIP, datagrama, ICMP_PROTO)           #ojo esto es un entero

    else:
        return False


def initICMP():
    '''
        Nombre: initICMP
        Descripción: Esta función inicializa el nivel ICMP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar (llamando a registerIPProtocol) la función process_ICMP_message con el valor de protocolo 1

        Argumentos:
            -Ninguno
        Retorno: Ninguno

    '''
    #el valor de ICMP_PROTO ES 1
    ip.registerIPProtocol(process_ICMP_message, ICMP_PROTO)
