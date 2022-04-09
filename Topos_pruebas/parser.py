# -*- coding: utf-8 -*-
"""
Created on Tue Mar 22 13:53:37 2022

@author: Victoria
"""
import random


def parser_ficheros(tipo_topologia,n_nodos,n_semilla):
    #n_nodos=80
    id_root=random.randint(1,n_nodos)
    fichero='%s_%d_%d' % (tipo_topologia, n_nodos, n_semilla)
    
    RESULTADOS='../Topos_Pruebas/%s/%d/%s.txt' % (tipo_topologia,n_nodos,fichero)
    
    file = open("../Topos_Pruebas/%s/%d/%s" % (tipo_topologia,n_nodos,fichero), "r")
    file2 = open(RESULTADOS, "w")
    
    coord=''
    i=0
    id_counter = 1
    for line in file:
        #print(line[0:5])
        if line[0:5] == '$node':
            line=line.split(' ')
            num=round(float(line[3][0:len(line[3])-1]))
            if i==0:
                coord='%d' % (num)
            else:
                coord='%s,%d' % (coord,num)
            i=i+1
            
            if i==3:
                i=0
                carga=random.randint(-10,10)
                #coord=coord[0:len(coord)-1]
                #print(coord)
                if id_counter == id_root:
                    file2.write('%s,0,1\n' % coord)
                else:
                    file2.write('%s,%d,0\n' % (coord,carga))
                coord=''
                id_counter +=1
    file.close()
    file2.close()
    
    
####################################################################################################################
for n_semilla in range(0,10):
    for tipo_topologia in ['Berlin','Leizpiz']:
        for n_nodos in (40,60,80):
            parser_ficheros(tipo_topologia,n_nodos,n_semilla+1)