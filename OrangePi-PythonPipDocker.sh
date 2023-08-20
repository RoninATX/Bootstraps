#!/bin/bash
# Variables
ORANGEPI_PASSWORD="0r@ng3p1p1p1"
SSH_KEY="ssh-rsa AAAA..."

#
# PrepOS
#
sudo apt-get update && sudo apt-get upgrade

# Change the OrangePi Password
echo "orangepi:${ORANGEPI_PASSWORD}" | sudo chpasswd

# Modify PermitRootLogin to no
sudo sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Prep SSH Security
mkdir -p ~/.ssh
echo "${SSH_KEY}" >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys

# Disable Password Authentication (SSH only)
sudo sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

#
# Python & Pip
#
sudo apt-get install -y python3
sudo apt-get install -y python3-pip


# 
# Docker
#
# Install Dependencies
sudo apt-get upgrade -y
sudo apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release
	
# Add Docker's Official GPG Key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update package database
sudo apt-get update

# Set Up the Stable Repository
sudo apt-get install -y docker-ce docker-ce-cli containerd.io

# Add $User to the Docker Group (reboot to apply, allows for docker without sudo prefix)
sudo usermod -aG docker $USER

# Verify
sudo docker --version
sudo docker run hello-world
