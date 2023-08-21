# 1Password: Docker
docker login

# Docker Hub - OP5 = ARM64 for Linux
docker pull roninatx/cogitator-docker:latestOP5

# Create the ErrorLogs and SessionLogs directories for mounting
mkdir -p /home/orangepi/Documents/CogiLogs/ErrorLogs
mkdir -p /home/orangepi/Documents/CogiLogs/SessionLogs

# Launch the Docker Container (with restart policy, port forwarding, and volume mounting)
docker run --restart always --name Cogitator-Prime -d -p 8085:80 -v /home/orangepi/Documents/CogiLogs/ErrorLogs:/app/ErrorLogs -v /home/orangepi/Documents/CogiLogs/SessionLogs:/app/SessionLogs roninatx/cogitator-docker:latestOP5

# Change the owner of the mounted volumes to the docker user
sudo chown -R 10001:10001 /home/orangepi/Documents/CogiLogs/ErrorLogs
sudo chown -R 10001:10001 /home/orangepi/Documents/CogiLogs/SessionLogs

# Verify the container is running
docker ps