#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

                                USO DE NMAP

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
import sys
import nmap
from termcolor import colored       #Libreria para colores
import os
print (colored("***************************** ",'green',attrs=['bold', 'blink']))
print (colored("------------MENU-------------",'yellow',attrs=['bold']))
print (colored("***************************** ",'green',attrs=['bold', 'blink']))
print ("1.Informacion general")
print ("2.Buscar hosts activos en la red")
print ("3.Escaneo en profundidad de puertos")
opcion=int(raw_input("Escoge una opcion: "))


if opcion==1:
	ip = raw_input("Introduce la IP objetivo: ")
	puertos = raw_input("Introduce los puertos a escanear separados por comas: ")
	nm = nmap.PortScanner()

	print (colored("Puertos a escanear: ",'green',attrs=['bold', 'blink']) + puertos)
	print (colored("IP a escanear: ",'green',attrs=['bold', 'blink']) + ip)
	resultados=nm.scan(ip, puertos)

	print (colored("\n***************************** ",'red',attrs=['bold', 'blink']))
	print (colored("\t SCAN INFO ",'green',attrs=['bold', 'blink']))
	print (colored("***************************** \n",'red',attrs=['bold', 'blink']))

	print(nm.scaninfo())

	print (colored("\n***************************** ",'red',attrs=['bold', 'blink']))
	print (colored("\t COMMAND LINE ",'green',attrs=['bold', 'blink']))
	print (colored("***************************** \n",'red',attrs=['bold', 'blink']))

	print(nm.command_line())

	print (colored("\n***************************** ",'red',attrs=['bold', 'blink']))
	print (colored("\t ALL HOST ",'green',attrs=['bold', 'blink']))
	print (colored("***************************** \n",'red',attrs=['bold', 'blink']))

	print(nm.all_hosts())

	print (colored("\n***************************** ",'red',attrs=['bold', 'blink']))
	print (colored("\t ARCHIVO CSV ",'green',attrs=['bold', 'blink']))
	print (colored("***************************** \n",'red',attrs=['bold', 'blink']))

	print (nm.csv())

	print (colored("\n***************************** ",'red',attrs=['bold', 'blink']))
	print (colored("\t LOCALIZACION ",'green',attrs=['bold', 'blink']))
	print (colored("***************************** \n",'red',attrs=['bold', 'blink']))


	print(dir(nm))
	
	nm.scan(hosts='192.168.1.0/24', arguments='-n -sP -PE -PA21,23,80,3389')



if opcion==2:
	ip = raw_input("Introduce una IP o un rango separado por un guion: ")
	nm = nmap.PortScanner()
	scan=nm.scan(hosts=ip, arguments='-n -sP')
	print (colored("***************************** \n",'red',attrs=['bold', 'blink']))
	print (colored("-----------RESULTADO--------- \n",'red',attrs=['bold', 'blink']))
	print (colored("***************************** \n",'red',attrs=['bold', 'blink']))
	print scan




if opcion==3:
	
	ip = raw_input("Introduce la IP objetivo: ")
	puertos = raw_input("Introduce los puertos a escanear separados por comas: ")
	nm = nmap.PortScanner()
	scan=nm.scan(hosts=ip, arguments='-n -A -sV -PU -PE -PA'+puertos)
	print (colored("***************************** \n",'red',attrs=['bold', 'blink']))
	print (colored("-----------RESULTADO--------- \n",'red',attrs=['bold', 'blink']))
	print (colored("***************************** \n",'red',attrs=['bold', 'blink']))
	nm.all_hosts()
	nm[ip].state()
	nm[ip].all_protocols()
	nm[ip]['tcp'].keys()
	nm[ip].has_tcp(23)
	nm[ip]['tcp'][22]
	nm[ip].tcp(22)
	nm[ip]['tcp'][22]['state']
	
	
	for host in nm.all_hosts():
		print('Host : %s (%s)' % (host, nm[host].hostname()))
    		print('State : %s' % nm[host].state())
	for proto in nm[host].all_protocols():
         	print('----------')
         	print('Protocol : %s' % proto)
 
         	lport = nm[host][proto].keys()
         	lport.sort()
         	for port in lport:
             		print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

	