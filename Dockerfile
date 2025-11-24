# Use a base image with Node.js installed
# Using Debian-based image (default) for better compatibility with node-pty/build tools
FROM node:20

# Set the working directory inside the container
WORKDIR /usr/src/app

# Install build dependencies for node-pty (python3, make, g++)
# These are usually present in the standard node image, but good to be explicit if using slim
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 make g++ netcat-openbsd iputils-ping tshark && \
    rm -rf /var/lib/apt/lists/*

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# Expose the port the app runs on
EXPOSE 3000

# Define the command to run the app
CMD [ "npm", "start" ]
