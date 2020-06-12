#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

                            BANNER GRABBING

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

import socket
import sys
import os

################################################################
# Funcion para obtener el banner de un puerto para una IP dada #
################################################################

def obtenerBanner(ip_address,puerto):
  try:
      print("Establecemos conexion...")
      conexion=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
      conexion.connect((ip_address,puerto))
      banner = conexion.recv(1024)
      print ("Analizado: " + str(ip_address) + " en el puerto " + str(puerto) + ':' + str(banner))
      print("Leemos el archivo.")
      archivo = open('banners_vulnerables.txt','r')
      print("Archivo leido. Vamos a comprobar si es vulnerable")
      for bannervulnerable in archivo:
          if str(bannervulnerable).strip() in str(banner).strip():
              print ('El banner es vulnerable')
          else:
              print ('El banner NO es vulnerable')
  except:
      print("Fallo la conexion")
      return

def main():
  listaPuertos = [21,22,25]
  #La direccion ip de prueba es 172.16.20.128
  for x in range(128,129):
       for puerto in listaPuertos:
            ip_address = '172.16.20.' + str(x)
            print('\nAnalizando la dirección: ' + str(ip_address) + ' en el puerto ' + str(puerto))
            obtenerBanner(ip_address,puerto)
            
if __name__ == '__main__':
  main()
