# -*- coding: utf-8 -*-
"""
Created on Tue Mar 22 13:53:37 2022

@author: Victoria
"""

RESULTADOS='Topologia2.txt'

file = open("Topologia2", "r")
file2 = open(RESULTADOS, "w")

coord=''
i=0
for line in file:
    print(line[0:5])
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
            #coord=coord[0:len(coord)-1]
            print(coord)
            file2.write(coord+'\n')
            coord=''

file.close()
file2.close()