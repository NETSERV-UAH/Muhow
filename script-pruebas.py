
import os
import time

path_logs='/home/arppath/TFM/Logs'
#topos=['Berlin','Leizpiz']
#nodos=[40,60,80]
n_topos=10
n_iteraciones=11
losses=[0.005,0.01]
perd=[5,1]

'''
#SET1
for topo in topos:
    for node in nodos:
        for n_t in range(n_topos):
            os.system('rm /home/arppath/TFM/Logs/*')
            file=path_topos+'%s/%d/%s_%d_%d.txt' %(topo,node,topo,node,n_t+1)
            print('-------------------------------------------------------------------------------------------------')
            print('--- Lanzado %s ---' % file)
            os.system('sudo python3 Topologias/topology_generator.py ' + file)
            files = os.listdir(path_logs)
            while ('info_it_12.txt' not in files):# and ('linea_sta1.txt' in files)):
                files = os.listdir(path_logs)
            time.sleep(5)  #Mientras se limpia para el siguiente lanzamiento
            #index=int(FICHERO_TOPO.split('_')[3])
            copia=path_topos+'%s/%d/%s_%d_%d_results' %(topo,node,topo,node,n_t+1)
            os.system('cp /home/arppath/TFM/Logs/info_it_* %s/' % copia)
            os.system('chmod 777 %s/*' % copia)
            #print (files)


#SET2 y SET3
for topo in topos:
    for node in nodos:
        for n_t in range(n_topos):
            copia=path_topos+'%s/%d/%s_%d_%d_results' %(topo,node,topo,node,n_t+1)
            files = os.listdir(copia)
            if files:
                os.system('rm %s/*' % copia)
            for it in range(n_iteraciones):
                os.system('rm /home/arppath/TFM/Logs/*')
                file=path_topos+'%s/%d/%s_%d_%d_%d.txt' %(topo,node,topo,node,n_t+1,it)
                print('-------------------------------------------------------------------------------------------------')
                print('--- Lanzado %s ---' % file)
                os.system('sudo python3 Topologias/topology_generator.py ' + file)
                files = os.listdir(path_logs)
                while ('info_it_1.txt' not in files):# and ('linea_sta1.txt' in files)):
                    files = os.listdir(path_logs)
                time.sleep(5)  #Mientras se limpia para el siguiente lanzamiento
                #index=int(FICHERO_TOPO.split('_')[3])
                #copia=path_topos+'%s/%d/%s_%d_%d_results' %(topo,node,topo,node,n_t+1)
                os.system('cp /home/arppath/TFM/Logs/info_it_0.txt %s/info_it_%d.txt' % (copia,it))
                os.system('chmod 777 %s/*' % copia)
                #print (files)

losses=[0.04]
perd=[4]
nodos=[9]
for loss in losses:
    ind=losses.index(loss)
    path_topos='/home/arppath/TFM/Topologias/Pruebas-protocolo/SET_4_loss_%d/' % (perd[ind])
    criterio=0
    for node in nodos:
        for n_t in range(n_topos):
            copia=path_topos+'%d/Quasi_%d_%d_results_%d' %(node,node,n_t+1,criterio)
            files = os.listdir(copia)
            if files:
                os.system('rm %s/*' % copia)
            for it in range(n_iteraciones):
                os.system('rm /home/arppath/TFM/Logs/*')
                file=path_topos+'%d/Quasi_%d_%d_%d.txt' %(node,node,n_t+1,it)
                print('--------------------------------------------------------------------------------------------------------------------------------')
                print('--- Lanzado %s con criterio %d y pérdidas %f ---' % (file,criterio,loss))
                os.system('sudo python3 Topologias/topology_generator_reint.py %s %d %f' % (file,criterio,loss))
                files = os.listdir(path_logs)
                #print(files)
                while ('info_it_1.txt' not in files):# and ('linea_sta1.txt' in files)):
                    files = os.listdir(path_logs)
                #while not 'info_it_0.txt' in files:# and ('linea_sta1.txt' in files)):
                #    files = os.listdir(path_logs)
                #time.sleep(25)
                #os.system('touch /home/arppath/TFM/Logs/info_it_1.txt')
                time.sleep(2)  #Mientras se limpia para el siguiente lanzamiento
                #index=int(FICHERO_TOPO.split('_')[3])
                #copia=path_topos+'%s/%d/%s_%d_%d_results' %(topo,node,topo,node,n_t+1)
                os.system('cp /home/arppath/TFM/Logs/info_it_0.txt %s/info_it_%d.txt' % (copia,it))
                os.system('cp /home/arppath/TFM/Logs/todas_etiq.txt %s/info_etiquetas_%d.txt' % (copia,it))
                os.system('cp /home/arppath/TFM/Logs/info_root.txt %s/info_root_%d.txt' % (copia,it))

                os.system('chmod 777 %s/*' % copia)
                    #print (files)

n_topos=10
n_iteraciones=[9]
losses=[0.04]
perd=[4]
nodos=[7]
for loss in losses:
    ind=losses.index(loss)
    path_topos='/home/arppath/TFM/Topologias/Pruebas-protocolo/SET_4_loss_%d/' % (perd[ind])
    criterio=1
    for node in nodos:
        n_t=8
        copia=path_topos+'%d/Quasi_%d_%d_results_%d' %(node,node,n_t+1,criterio)
        files = os.listdir(copia)
        #if files:
            #os.system('rm %s/*' % copia)
        for it in n_iteraciones:
            os.system('rm /home/arppath/TFM/Logs/*')
            file=path_topos+'%d/Quasi_%d_%d_%d.txt' %(node,node,n_t+1,it)
            print('--------------------------------------------------------------------------------------------------------------------------------')
            print('--- Lanzado %s con criterio %d y pérdidas %f ---' % (file,criterio,loss))
            os.system('sudo python3 Topologias/topology_generator_reint.py %s %d %f' % (file,criterio,loss))
            files = os.listdir(path_logs)
            while ('info_it_1.txt' not in files):# and ('linea_sta1.txt' in files)):
                files = os.listdir(path_logs)
            #while ('info_it_0.txt' not in files):# and ('linea_sta1.txt' in files)):
                #files = os.listdir(path_logs)
            #print('ESPERO')
            time.sleep(2)
            #os.system('sudo touch /home/arppath/TFM/Logs/info_it_1.txt')
            #time.sleep(30)  #Mientras se limpia para el siguiente lanzamiento
            #index=int(FICHERO_TOPO.split('_')[3])
            #copia=path_topos+'%s/%d/%s_%d_%d_results' %(topo,node,topo,node,n_t+1)
            os.system('cp /home/arppath/TFM/Logs/info_it_0.txt %s/info_it_%d.txt' % (copia,it))
            os.system('cp /home/arppath/TFM/Logs/todas_etiq.txt %s/info_etiquetas_%d.txt' % (copia,it))
            os.system('cp /home/arppath/TFM/Logs/info_root.txt %s/info_root_%d.txt' % (copia,it))

            os.system('chmod 777 %s/*' % copia)
                #print (files)

###################################################################################################################################################################
###################################################################################################################################################################
#---NO REINTENTOS---
#SET4
n_topos=10
n_iteraciones=11
losses=[0.005,0.01,0.02]
perd=[5,1,2]
nodos=[9]
print('INICIADO TEST NO REINTENTOS')
for loss in losses:
    ind=losses.index(loss)
    path_topos='/home/arppath/TFM/Topologias/Pruebas-protocolo/NO_REINT/SET_4_loss_%d/' % (perd[ind])
    for criterio in range(2):
        for node in nodos:
            for n_t in range(n_topos):
                copia=path_topos+'%d/Quasi_%d_%d_results_%d' %(node,node,n_t+1,criterio)
                files = os.listdir(copia)
                if files:
                    os.system('rm %s/*' % copia)
                for it in range(n_iteraciones):
                    os.system('rm /home/arppath/TFM/Logs/*')
                    file=path_topos+'%d/Quasi_%d_%d_%d.txt' %(node,node,n_t+1,it)
                    print('--------------------------------------------------------------------------------------------------------------------------------')
                    print('--- Lanzado %s con criterio %d y pérdidas %f ---' % (file,criterio,loss))
                    os.system('sudo python3 Topologias/topology_generator.py %s %d %f' % (file,criterio,loss))
                    files = os.listdir(path_logs)
                    while ('info_it_1.txt' not in files):# and ('linea_sta1.txt' in files)):
                        files = os.listdir(path_logs)
                    #while ('info_it_0.txt' not in files):# and ('linea_sta1.txt' in files)):
                    #    files = os.listdir(path_logs)
                    time.sleep(2)
                    #os.system('touch /home/arppath/TFM/Logs/info_it_1.txt')
                    #time.sleep(30)  #Mientras se limpia para el siguiente lanzamiento
                    #index=int(FICHERO_TOPO.split('_')[3])
                    #copia=path_topos+'%s/%d/%s_%d_%d_results' %(topo,node,topo,node,n_t+1)
                    os.system('cp /home/arppath/TFM/Logs/info_it_0.txt %s/info_it_%d.txt' % (copia,it))
                    os.system('cp /home/arppath/TFM/Logs/todas_etiq.txt %s/info_etiquetas_%d.txt' % (copia,it))
                    os.system('cp /home/arppath/TFM/Logs/info_root.txt %s/info_root_%d.txt' % (copia,it))

                    os.system('chmod 777 %s/*' % copia)
                        #print (files)

'''
n_topos=10
n_iteraciones=11
losses=[0.02]
perd=[2]
nodos=[7]
print('INICIADO TEST NO REINTENTOS')
for loss in losses:
    ind=losses.index(loss)
    path_topos='/home/arppath/TFM/Topologias/Pruebas-protocolo/NO_REINT/SET_4_loss_%d/' % (perd[ind])
    criterio=1
    for node in nodos:
        for n_t in range(n_topos):
            copia=path_topos+'%d/Quasi_%d_%d_results_%d' %(node,node,n_t+1,criterio)
            files = os.listdir(copia)
            if files:
                os.system('rm %s/*' % copia)
            for it in range(n_iteraciones):
                os.system('rm /home/arppath/TFM/Logs/*')
                file=path_topos+'%d/Quasi_%d_%d_%d.txt' %(node,node,n_t+1,it)
                print('--------------------------------------------------------------------------------------------------------------------------------')
                print('--- Lanzado %s con criterio %d y pérdidas %f ---' % (file,criterio,loss))
                os.system('sudo python3 Topologias/topology_generator.py %s %d %f' % (file,criterio,loss))
                files = os.listdir(path_logs)
                while ('info_it_1.txt' not in files):# and ('linea_sta1.txt' in files)):
                    files = os.listdir(path_logs)
                #while ('info_it_0.txt' not in files):# and ('linea_sta1.txt' in files)):
                #    files = os.listdir(path_logs)
                time.sleep(2)
                #os.system('touch /home/arppath/TFM/Logs/info_it_1.txt')
                #time.sleep(30)  #Mientras se limpia para el siguiente lanzamiento
                #index=int(FICHERO_TOPO.split('_')[3])
                #copia=path_topos+'%s/%d/%s_%d_%d_results' %(topo,node,topo,node,n_t+1)
                os.system('cp /home/arppath/TFM/Logs/info_it_0.txt %s/info_it_%d.txt' % (copia,it))
                os.system('cp /home/arppath/TFM/Logs/todas_etiq.txt %s/info_etiquetas_%d.txt' % (copia,it))
                os.system('cp /home/arppath/TFM/Logs/info_root.txt %s/info_root_%d.txt' % (copia,it))

                os.system('chmod 777 %s/*' % copia)
                    #print (files)
