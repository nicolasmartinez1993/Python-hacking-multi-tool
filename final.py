#!/usr/bin/python3
#coding: utf-8
#!/usr/bin/env python

import dns
import dns.resolver
from termcolor import colored 
import shodan
import pythonwhois
import sys
import os
import pygeoip
import pprintpp
from PyPDF2 import PdfFileReader, PdfFileWriter
from PIL.ExifTags import TAGS
from PIL import Image

ShodanKeyString = "2vG8JozhOfOInJ3MAprDnssnRk2JWopu"

#Realizamos la conexion con la base de datos de Shodan
ShodanApi = shodan.Shodan(ShodanKeyString)


    

def pedirNumeroEntero():
 
    correcto=False
    num=0
    while(not correcto):
        try:
            num = int(input(colored("Elige una opcion: ",'red',attrs=['bold'])))
            correcto=True
        except ValueError:
            print('Error, introduce un numero entero')
     
    return num
 
salir = False
opcion = 0
 
while not salir:
	
 	
    print (colored("------Recoleccion de información-------",'yellow',attrs=['bold']))
    print ("1. Busqueda con Shodan        5. Host con Shodan")
    print ("2. Informacion DNS            6. WHOIS")
    print ("3. GeoIp                      7.Shodan Facets")
    print ("4. GoogleDB                   8. Modificadoe de metadatos")
    
    print (colored("-------Analisis de vulnerabilidades------",'yellow',attrs=['bold']))
    print ("9.TCP Scan                   13.XMAS Scan")
    print ("10. UDP Scan                 14.NMAP Scan")
    print ("11. Null Scan")
    print ("12. ACK Scan")
    print (colored("-------Ataques de red local------------",'yellow',attrs=['bold']))
    print ("15. Ataque DOS")
    print ("16. Ataque fuerza bruta")
         
 
    opcion = pedirNumeroEntero()
 
    if opcion == 1:
        print("--------------")
        try:

            resultados = ShodanApi.search(raw_input("¿Que quieres buscar?: "))
        # Mostramos el resultado
            print ('Cantidad de resultados encontrados: %s' % resultados['total'])
            for i in resultados['matches']:
                print ('IP: %s' % i['ip_str'])
                print ('Data: %s' % i['data'])
                print ('Hostnames: %s' % i['hostnames'])
                print ('Puerto: %s' % i['port'])
                print ('')

        except shodan.APIError as e:
            print ('Ups! Ha ocurrido un error: %s' % e)
        
        print("---------------")

    elif opcion == 2:
        obj=raw_input("Introduce un objetivo: ")               #Libreria para colores

        """Consulta sobre registro IPV4"""
        ansA = dns.resolver.query(obj)

        """Consulta sobre registro IPV6"""
        ansAAAA = dns.resolver.query(obj,'AAAA')

        """Consulta sobre registro MailServers"""
        ansMX = dns.resolver.query(obj,'MX')

        """Consulta sobre registro NameServers"""
        ansNS = dns.resolver.query(obj,'NS')


        print (colored("\nRespuesta de DNS en IPV4: ",'red',attrs=['bold', 'blink']))
        print (ansA.response.to_text())

        print (colored("\nRespuesta de DNS en IPV6: ",'red', attrs=['bold', 'blink']))
        print (ansAAAA.response.to_text())

        print (colored("\nRespuesta de DNS en MailServers: ",'red',attrs=['bold', 'blink']))
        print (ansMX.response.to_text())

        print (colored("\nRespuesta de DNS en NameServers: ",'red',attrs=['bold', 'blink']))
        print (ansNS.response.to_text())
        print("---------------")

    elif opcion == 3:
        
        obj=raw_input("Introduce una pagina objetivo: ")
        obj1=raw_input("Introduce la direccion IP del objetivo: ")
        """Utilizamos la base de datos GeoLite"""
        gi = pygeoip.GeoIP('GeoLiteCity.dat')

        print(colored("\n Código del pais del servidor por dominio: ",'red',attrs=['bold', 'blink']) + gi.country_code_by_name(obj))
        print(colored("\n Código del país del servidor por IP: ",'red',attrs=['bold', 'blink']) + gi.country_code_by_addr(obj1))
        print(colored("\n Time zone del servidor por IP: ",'red',attrs=['bold', 'blink']) + gi.time_zone_by_addr(obj1))

        print(colored("\n Información completa del servidor por IP: ",'red',attrs=['bold', 'blink']))
        pprintpp.pprint(gi.record_by_addr(obj1))

        print("--------------")
    elif opcion == 4:
        #uno=" "+ raw_input("Introduce el archivo raiz: ")
        #dos=" -o " + raw_input("Nombre del archivo donde guardarlo: ")
        #tres=" -s " + raw_input("Nombre de la pagina objetivo: ")
        os.system("python googleDB-tool.py" +" "+raw_input("Introduce el archivo raiz: ") +" -o " + raw_input("Nombre del archivo donde guardarlo: ") +" -s " + raw_input("Nombre de la pagina objetivo: "))
       

        print("--------------")
    elif opcion == 5:
        host = ShodanApi.host(raw_input("Introduce una IP: "))

        # Print general info

        print ('IP: %s ' % host['ip_str'])
        print ('Organizacion: %s ' % host.get('org', 'n/a'))
        print ('Sistema operativo: %s ' % host.get('os', 'n/a'))
        for item in host['data']:
            print ('Puerto: %s ' % item['port'])
            print ('Banner: %s ' % item['data'])

        print("--------------")
    elif opcion == 6:
        #Utilizamos la API de pythonwhois para extraer información desde cualquier script en Python
        objetivo=raw_input("Introduce un objetivo: ")
        """Recuperamos el servidor raiz para un dominio determinado"""
        pythonwhois.net.get_root_server(objetivo)

        """Obtenemos un diccionario con toda la información sobre el dominio"""
        whois = pythonwhois.get_whois(objetivo)

        """Obtenemos la información del dominio de manera 'cruda'"""
        whois_raw = pythonwhois.net.get_whois_raw(objetivo)

        print (colored("\nValores de keys para el servidor: ",'red',attrs=['bold', 'blink']))
        print (whois.keys())

        print (colored("\nValores de la búsqueda para el servidor: ",'red',attrs=['bold', 'blink']))
        print (whois.values())

        print (colored("\nValores de la búsqueda para el servidor crudo: ",'red',attrs=['bold', 'blink']))
        print(whois_raw)
        print("-----------------")
    elif opcion == 7:
        FACETS = [
            'org',
            ('port', 10),
            'os',
            'telnet.option',
            'ssl.alpn',
            'servers',
   
        ]

        FACET_TITLES = {

            'org': '----Organizaciones----',    
            'port': '----Puertos usados----',
            'os': '----Sistemas operativos----',
            'telnet.option': '----Info: Telnet----',
            'ssl.alpn': '----Info: SSL----',
            'servers': 'Servidores',

    
        }

        # Input validation
        """if len(sys.argv) == 1:
        print 'Usage: %s <search query>' % sys.argv[0]
        sys.exit(1)"""

        try:
            # Setup the api
            api = shodan.Shodan(ShodanKeyString)

            # Generate a query string out of the command-line arguments
            query = raw_input("Introduce tu busqueda: ")

            # Use the count() method because it doesn't return results and doesn't require a paid API plan
            # And it also runs faster than doing a search().
            result = api.count(query, facets=FACETS)

            print 'Shodan Summary Information'
            print 'Query: %s' % query
            print 'Total Results: %s\n' % result['total']

            # Print the summary info from the facets
            for facet in result['facets']:
                print FACET_TITLES[facet]

                for term in result['facets'][facet]:
                    print '%s: %s' % (term['value'], term['count'])

                # Print an empty line between summary info
                print ''

        except Exception, e:
            print 'Error: %s' % e
            sys.exit(1)
            print("---------------")
    elif opcion == 8:
        def pedirNumeroEntero():
 
            correcto=False
            num=0
            while(not correcto):
                try:
                    num = int(input("Elige una opcion: "))
                    correcto=True
                except ValueError:
                    print('Error, introduce un numero entero')
             
            return num
         
        salir = False
        opcion = 0
         
        while not salir:
            print("---------------------------------------")
            print("Seleccione la opcion correspondiente: ")
            print("---------------------------------------")
            print ("1. Metadatos de imagenes")
            print ("2. Metadatos de un PDF")
            print("---------------------------------------")

            opcion = pedirNumeroEntero()

            if opcion==1:
                img=raw_input("Introduce el nombre de la imagen: ")

                #Definimos una funcion que lea los datos de una imagen en concreto
                def analisis_imagen(nombre_imagen):

                    metadatos_exif = {}

                    #Abrimos la imagen
                    archivo_imagen = Image.open(nombre_imagen)

                    #Extraemos la información necesaria de ella, los EXIF
                    info = archivo_imagen._getexif()

                    print("\n")
                    print("###############################################################################")
                    print("                         Información general")
                    print("###############################################################################")
                    print("\n")
                    print (info)

                    if (info):
                        for (tag,value) in info.items():
                            decoded = TAGS.get(tag,tag)
                            metadatos_exif[decoded] = value

                        if metadatos_exif:

                            print("\n")
                            print("###############################################################################")
                            print("                         Información metadatos")
                            print("###############################################################################")
                            print("\n")

                            for meta_info in metadatos_exif:
                                print ("[+] " + str(nombre_imagen) + " Datos: " + str(metadatos_exif[meta_info]))


                """""""""""""""""""""""""""""""""""""""""""""""""""
                        USO DE LA FUNCIÓN
                """""""""""""""""""""""""""""""""""""""""""""""""""

                analisis_imagen(img)

            elif opcion==2:
                pdf=raw_input("Introduce el nombre del pdf: ")

                #Definimos una funcion que lea los datos de un pdf en concreto
                def obtenerMetadatos():
                    #El pdf esta situado en el mismo directorio que este script
                    #Leemos el archivo
                    archivo_pdf = PdfFileReader(pdf)

                    #Obtenemos la información que queremos
                    info_documento = archivo_pdf.getDocumentInfo()
                    xmp=archivo_pdf.getXmpMetadata()
                   

                    print("\n")
                    print("###############################################################################")
                    print("                         Información metadatos")
                    print("###############################################################################")
                    print("\n")

                    for metadato in info_documento:
                        print ("[+] " + metadato + ":" + info_documento[metadato])

                    if xmp ==True:
                        for metadato2 in xmp:
                            print ("[+] " + metadato2 + ":" + xmp[metadato2])
                    else:
                        print("[-] No hay metadatos XMP." )  
                    #print("Información en crudo: " + " " + info_documento)


                """""""""""""""""""""""""""""""""""""""""""""""""""
                                USO DE LA FUNCIÓN
                """""""""""""""""""""""""""""""""""""""""""""""""""

                obtenerMetadatos()
                print("")
            #else:
             #   print ("Introduce un numero entre 1 y 7")
    elif opcion == 9:
        import  escaneo_tcp.py

    elif opcion == 10:
    	import escaneo_udp.py

    elif opcion == 11:
    	import escaneo_null.py

    elif opcion == 12:
    	import escaneo_ack.py

    elif opcion == 13:
    	import escaneo_xmas.py

    elif opcion == 14:
    	import uso_nmap.py

    elif opcion == 15:
    	import ataque_dos.py

    elif opcion == 16:
    	import ftp_bruteforcer.py



print ("Fin")
