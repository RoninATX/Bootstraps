# Bootstraps
Bootstrap scripts for my various Orange and Raspberry Pi Configs

OrangePi-PythonPipDocker.sh
- Preps a fresh OrangPi install to do things like:
1. Update the OS (apt-get update) 
2. Change the default Orange Pi password
3. Prep the box for SSH security (including registring keys)
4. Disable password login authentication to foce SSH only
5. Install Python
6. Install Pip
7. Install and configure Docker


Docker-Pull-Cogi-Linux.sh
- Run this after OrangePi-PythonPipDocker.sh
- Preps the Pi to specifically host Cogitator Prime:
1. Log into docker to pull down the latest Cogi image for Arm64
2. Makes volume mapping drives in the default OrangePi desktop documents folders for ErrorLogs and SessionLogs
3. Starts up the docker container for Cogi and maps the Error and Session directories out
4. Docker container is set to run in "auto recovery" mode in the event of reboot.