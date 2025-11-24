# Deploying Cyber Security Tools Portal to AWS EC2

This guide will walk you through hosting your application on an Amazon Web Services (AWS) EC2 instance. Since your application uses a real interactive terminal (`node-pty`), it requires a full virtual machine environment and cannot run on serverless platforms like Vercel.

## Prerequisites
- An AWS Account (you can use the Free Tier).
- Basic familiarity with the terminal.

## Step 1: Launch an EC2 Instance

1.  **Log in to AWS Console** and navigate to **EC2**.
2.  Click **Launch Instance**.
3.  **Name**: Give your instance a name (e.g., "CyberTools-Server").
4.  **OS Image**: Choose **Ubuntu Server 24.04 LTS** (or 22.04 LTS). It's free-tier eligible and works great with Docker.
5.  **Instance Type**: Choose **t2.micro** (Free Tier eligible) or **t3.micro**.
6.  **Key Pair**:
    - Click "Create new key pair".
    - Name it (e.g., "cyber-key").
    - Type: RSA.
    - Format: `.pem`.
    - Click **Create key pair**. The file will download automatically. **Keep this safe!**
7.  **Network Settings**:
    - Check "Allow SSH traffic from" -> **My IP** (for security).
    - Check "Allow HTTP traffic from the internet".
    - Check "Allow HTTPS traffic from the internet".
8.  Click **Launch Instance**.

## Step 2: Configure Security Group (Open Port 3000)

1.  Go to your instance dashboard and click on your new instance ID.
2.  Click the **Security** tab.
3.  Click the **Security Group** link (e.g., `sg-01234...`).
4.  Click **Edit inbound rules**.
5.  Click **Add rule**:
    - **Type**: Custom TCP
    - **Port range**: `3000`
    - **Source**: `0.0.0.0/0` (Anywhere) - *Note: For production, restrict this to your IP or use a reverse proxy like Nginx.*
6.  Click **Save rules**.

## Step 3: Connect to Your Instance

1.  Open your local terminal.
2.  Move your key file to a safe place (e.g., `~/.ssh/`) and restrict permissions:
    ```bash
    chmod 400 ~/.ssh/cyber-key.pem
    ```
3.  Connect via SSH (replace `YOUR_PUBLIC_IP` with the Public IPv4 address from the EC2 dashboard):
    ```bash
    ssh -i ~/.ssh/cyber-key.pem ubuntu@YOUR_PUBLIC_IP
    ```

## Step 4: Install Docker on EC2

Once connected to the server, run these commands to install Docker:

```bash
# Update packages
sudo apt-get update

# Install Docker
sudo apt-get install -y docker.io

# Start Docker and enable it to run on boot
sudo systemctl start docker
sudo systemctl enable docker

# Add your user to the docker group (so you don't need 'sudo' for docker commands)
sudo usermod -aG docker $USER
```

*Log out and log back in for the group change to take effect:*
```bash
exit
# Reconnect
ssh -i ~/.ssh/cyber-key.pem ubuntu@YOUR_PUBLIC_IP
```

## Step 5: Deploy the Application

You have two options to get your code onto the server:

### Option A: Git Clone (Recommended)
If your code is on GitHub:
1.  Clone your repository:
    ```bash
    git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
    cd YOUR_REPO
    ```

### Option B: File Transfer (SCP)
If your code is only local:
1.  On your **local machine**, run:
    ```bash
    # Zip your project (excluding node_modules)
    zip -r cyber-tools.zip . -x "node_modules/*" ".git/*"
    
    # Upload to EC2
    scp -i ~/.ssh/cyber-key.pem cyber-tools.zip ubuntu@YOUR_PUBLIC_IP:~/
    ```
2.  On the **EC2 instance**:
    ```bash
    sudo apt-get install unzip
    unzip cyber-tools.zip -d cyber-tools
    cd cyber-tools
    ```

## Step 6: Build and Run with Docker

Inside your project directory on the server:

1.  **Build the Docker image**:
    ```bash
    docker build -t cyber-tools .
    ```

### 6. Run the Docker Container
Run the container with the following command. Note the `--network host` and `--cap-add=NET_ADMIN` flags, which are required for the **Live Packet Analyzer** to capture network traffic.

```bash
sudo docker run -d \
  --name cyber-tools \
  --network host \
  --cap-add=NET_ADMIN \
  --restart unless-stopped \
  cyber-tools-app
```

> **Note**: `--network host` allows the container to share the host's network stack, which is necessary for `tshark` to see the server's traffic. `--cap-add=NET_ADMIN` grants the necessary privileges to capture packets.

### 7. Access the Application
Open your browser and navigate to:
`http://<your-ec2-public-ip>:3000`

(Since we are using `--network host`, the app binds directly to port 3000 on the host).

You should see your Cyber Security Tools Portal, and the terminal should be fully interactive!

---

### Useful Commands

- **View Logs**: `docker logs -f cyber-app`
- **Stop App**: `docker stop cyber-app`
- **Update App**:
    1. `git pull` (or upload new files)
    2. `docker build -t cyber-tools .`
    3. `docker stop cyber-app`
    4. `docker rm cyber-app`
    5. `docker run -d -p 3000:3000 --restart always --name cyber-app cyber-tools`
