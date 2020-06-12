#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

                        Sniffando el trafico DNS de la red local

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from scapy.all import *
import sys
from termcolor import colored       #Libreria para colores

"""
    Funcion auxiliar para sniffar
"""
def dns_sniffer(paquete):
    if IP in paquete:
        ip_source = paquete[IP].src
        ip_destino = paquete[IP].dst
        if paquete.haslayer(DNS) and paquete.getlayer(DNS).qr == 0:
            print (str(ip_source) + " -> " + str(ip_destino) + " : " + "(" + str(paquete.getlayer(DNS).qd.qname) + ")")

"""
    Funcion principal del programa
"""
def main():

    print (colored("\n###############################################################################",'green',attrs=['bold', 'blink']))
    print (colored("\n                  Sniffando trafico DNS en red local\n",'red',attrs=['bold', 'blink']))
    print (colored("###############################################################################\n",'green',attrs=['bold', 'blink']))

    try:
        interfaz = input("[*] Introducir la interfaz que se desea sniffar: ")
    except KeyboardInterrupt:
        print ("[*] Peticion del usuario para cerrar...")
        print ("[*] Saliendo...")
        sys.exit(1)

    sniff(iface = interfaz,filter = "port 53", prn = dns_sniffer, store = 0)
    print ("\n[*] Cerrando la busqueda...")

"""
Programa principal
"""
if __name__ == "__main__":
    main()
