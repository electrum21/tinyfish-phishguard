# Use official Node image
FROM node:20-bullseye

# Install WHOIS
RUN apt-get update && \
    apt-get install -y whois && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy package files first (better caching)
COPY package*.json ./

# Install dependencies
RUN npm install --omit=dev

# Copy rest of the app
COPY . .

# Expose port (Render uses 3000 by default)
EXPOSE 3000

# Start server
CMD ["node", "server.js"]