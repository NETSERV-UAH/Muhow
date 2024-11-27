## Introducción

Este trabajo se ha utilizado para el artículo "MuHoW: Distributed protocol for resource sharing in collaborative edge-computing networks
edge-computing networks" enviado a la revista Computer Networks. Este artículo fue aceptado por la revisa en abril del 2024.

## Cita
Alvarez-Horcajo, J., Martinez-Yelmo, I., Rojas, E., Carral, J. A., & Noci-Luna, V. (2024). MuHoW: Distributed protocol for resource sharing in collaborative edge-computing networks. Computer Networks, 242, 110243.

## Instrucciones de uso

## Instalación de Mininet

Descargar el código fuente de mininet:

    git clone https://github.com/mininet/mininet
    
Tenga en cuenta que el comando git anterior comprobará la última y mejor versión de Mininet (Recomendado) 
Si desea ejecutar la última versión etiquetada/liberada de Mininet - o cualquier otra versión - puede comprobar esa versión explícitamente:

    cd mininet
    git tag  # list available versions
    git checkout -b mininet-2.3.0 2.3.0  # or whatever version you wish to install
    cd ..

Para instalar mininet usar le siguiente comando:
    
    mininet/util/install.sh [options]

## Instalación de Mininet-wifi

Copie el repositorio:

    git clone git://github.com/intrig-unicamp/mininet-wifi

Tenga en cuenta que el comando git anterior comprobará la última y mejor versión de Mininet (Recomendado) 

    cd mininet-wifi

Use el siguiente comando para instalar mininet-wifi:

    sudo util/install.sh -Wlnfv

### Ejecutable
Para ejecutar Muhow debe crear una topología en mininet-wifi y ejecutar dentro de cada una de las STA el fichero nodos_reint.py
