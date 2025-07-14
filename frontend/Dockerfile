# Multi-stage build for frontend
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Set environment variables for build
ARG VITE_API_URL=https://api.glen.dqx0.com
ARG VITE_APP_NAME="Glen ID Platform"
ARG VITE_WEBAUTHN_ENABLED=true

ENV VITE_API_URL=$VITE_API_URL
ENV VITE_APP_NAME=$VITE_APP_NAME
ENV VITE_WEBAUTHN_ENABLED=$VITE_WEBAUTHN_ENABLED

# Build the application
RUN npm run build

# Production stage
FROM nginx:alpine

# Copy built files from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy health check file
COPY healthcheck.html /usr/share/nginx/html/healthcheck.html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Expose port
EXPOSE 80

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
