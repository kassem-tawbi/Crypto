Secure P2P File-Sharing for medical reports between hospitals.

**Deployment and Usage**

**Prerequisites**
Python: version 3.10 or later (Python 3.11 was used during development).
pip; Python's package manager (normally installed with Python).
Git; to clone the source code repository.

**Getting the Source Code**
Open a terminal and clone the source code using:

git clone https://github.com/tarek503/Crypto.git__


Navigate to the main folder using:

cd Crypto


Execute the following command:

ls


If you can see: backend, gui, util folders and the file requirements.txt, then the installation was successful.

**Installing Dependencies**
A few dependencies written in the file requirements.txt are needed to successfully run the program, to download the required dependencies, make sure you are in the Crypto/ folder. You can check using the following command:
pwd


The command will print the current working directory, if you are in Crypto/ folder, proceed by executing the following commands to install the dependencies:

pip install -r requirements.txt
pip install certifi


**Initial Configuration**
First, to generate fresh signing and encryption key pairs and create folders for received data and local stored data, execute the following command:

python -m util.setup_keys Hospital_INSE_6110


**Running the Application**
Now to finally run the app, execute the below command:

python -m gui.hospital_webui Hospital_INSE_6110 --ui-port 8002 --p2p-port 65002 --public-host 127.0.0.1

The IP address (--public-host parameter is set as 127.0.0.1 for simplicity), however if you are running the app on two separate devices then make sure to replace this parameter with the value of the actual IP of the device within the network it is connected to, also make sure that the two devices are connected to the same network since this application does not expose any public IPs, this design is employed for simplicity, focusing on cryptographic operations rather than network complexities.
Security Analysis and

