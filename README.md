# Anomaly-Detection-using-ML-in-Telematic-Data-Transmission

## Overview
Implemented a project for efficient handling and encryption of CAN frames, enhancing data security and anomaly detection using AES-GCM and ML models. Identified future enhancements for improved data transmission security contributing to 11% enhanced security.

The file contains two folders: src, which contains scripts and files for the project NIST Test Vectors which contains file for testing nist test vectors
		
**All codes must be executed from inside the main src folder.**

The project requires the following modules for running on Ubuntu 20 or higher:
canutils, pycryptodome, cryptography, scrypt, psutil, matplotlib, pyqt5, python3-pyqt5, pyqtgraph, pandas, statsmodels.

The Ubuntu OS must be updated. It can be updated by the following command:
```bash
$sudo apt update
```

The modules can be installed using apt or pip using the following commands:
```bash
$sudo apt install pip
$sudo apt install can-utils
$sudo apt install python3-pyqt5
$pip install pycryptodome
$pip install scypt
$pip install psutil
$pip install matplotlib
$pip install pyqt5
$pip install pyqtgraph
$pip install pandas
$pip install statsmodels
```

Cryptography module must be updated or it can lead to errors
```bash
$pip install --upgrade --user cryptography
```

The scr folder contains the dump.txt file which conains can logs.

First a Virtual CAN interface must be added. This can be done with:
```bash
$sudo ip link add dev vcan0 type can
```
The interface must be made running using:
```bash
$sudo ip link set vcan0 up
```
The canplayer uses the dump.txt module to simulate an actual can bus. This must be initiated from the src folder on the terminal using:
```bash
$canplayer -l i -I dump.txt vcan0=can1
```

The canplayer can be checked using:
```bash
$candump any
```

The src folder contains multiple scripts all of which should have execution permissions. This can be checked on the terminal from the src folder using:
```bash
&ls -l
```

The respective permissions can be added using:
```bash
chmod u+rwx <filename>
```

The scr folder contains a Exec.sh file which runs all the python scripts in the required sequential manner: Server.py > then > Client.py > then > GUI.py. The Server.py connects to the client acting as fleet operator. It also creates a csv file to store data and check for anomalous data. The Client.py acts as telematic device and read the virtual can bus to send data to the server. The GUI.py opens a GUI to show real-time plots.

The Project is run in two parts:

1. Go to the src folder, open a terminal, execute the following:
```bash
$./Exec.sh
```
This gets the server and client running and open a GUI showing the Engine Speed and other relevant data.

2. Go to the src folder, open a terminal, execute the following:
```bash
$python3 Malicious.py
$./Exec.sh
```

This first replaces the Client.py with malicious codes to inject anomalous data and runs as the previous case. In this case we will be able to anaomalous data detected on the GUI.

The results of the graphs can vary according to the data received from the VCAN. For the sake of reducing execution time, only 2000 CAN frames are processed per execution.

The NIST test vectors can be tested running the two python scripts in the NIST Test Vectors folder:
```bash
$python3 encrypt.py
$python3 decrypt.py
```

**Some common errors encountered are:**
1. xcb plugin cannot be initialized: This requires the python3-pyqt5 module to be installed correctly.
2. load_pem_public_key missing attribute 'backend': this requires cryptography module to be updated to latest version.
