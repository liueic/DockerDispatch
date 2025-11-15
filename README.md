# Mirror Registry

A lightweight, high-performance container image proxy that seamlessly integrates public cloud registries and private registries, providing developers with a unified, fast, and economical image pulling experience.

## Features

- **Unified Entry Point**: Single domain (`registry.example.com`) for all Docker client `pull` requests
- **Smart Routing**: Prioritizes "hot" registry (Aliyun ACR) with automatic fallback to "cold" registry (self-hosted)
- **Transparent Proxy**: Completely transparent to Docker clients
- **High Performance**: Uses HTTP 307 redirects to avoid proxying large blob traffic
- **Lightweight**: Minimal resource usage, can run on 1C1G servers
- **Docker Registry V2 API Compatible**: Fully compatible with Docker Registry V2 API

## Architecture

```
                        +---------------------------+
Docker Client <-----> |   registry.example.com    |
                        |      (Nginx/Caddy)        |
                        +-------------+-------------+
                                      | (HTTPS)
                                      v
                        +---------------------------+
                        |      Mirror Service       |  (Go Application)
                        +-------------+-------------+
                         /                         \
                        / (Check Hot)               \ (Check Cold)
                       v                             v
           +--------------------+         +-----------------------+
           | Aliyun ACR API     |         | Self-Hosted Registry  |
           | (registry.aliyuncs.com) |         | (registry:2 on your server) |
           +--------------------+         +-----------------------+
```

## Quick Start

### Using Docker Compose (Recommended for Testing)

1. Clone this repository:
```bash
git clone <repository-url>
cd mirror-registry
```

2. Start the services:
```bash
docker-compose up -d
```

This will start:
- A self-hosted registry on port 5001 (cold backend)
- The mirror registry proxy on port 5000

3. Configure Docker to trust the registry:
```bash
# For local testing without HTTPS
sudo tee /etc/docker/daemon.json > /dev/null <<EOF
{
  "insecure-registries": ["localhost:5000"]
}
EOF
sudo systemctl restart docker
```

4. Test the proxy:
```bash
# Pull an image from Aliyun ACR (will be proxied)
docker pull localhost:5000/library/nginx:latest

# Pull an image that exists only in cold registry
docker pull localhost:5000/test/my-app:latest
```

### Manual Installation

1. Build the application:
```bash
go build -o mirror-registry ./cmd
```

2. Create a configuration file `config.yaml`:
```yaml
server:
  port: 5000

registry:
  hot:
    url: "https://registry.cn-hangzhou.aliyuncs.com"
    username: ""
    password: ""
    headers:
      User-Agent: "mirror-registry/1.0"
  cold:
    url: "http://localhost:5001"
    username: ""
    password: ""
    headers:
      User-Agent: "mirror-registry/1.0"

logging:
  level: "info"
  format: "json"
```

3. Run the application:
```bash
./mirror-registry
```

## Configuration

The application can be configured using:

1. **Configuration file** (`config.yaml`)
2. **Environment variables** (prefix `MIRROR_`)

### Configuration Options

#### Server
- `server.port`: Port to listen on (default: 5000)

#### Registry Backend
- `registry.hot.url`: URL of the hot registry (e.g., Aliyun ACR)
- `registry.hot.username`: Username for hot registry authentication
- `registry.hot.password`: Password for hot registry authentication
- `registry.hot.headers`: Custom headers for hot registry requests

- `registry.cold.url`: URL of the cold registry (e.g., self-hosted)
- `registry.cold.username`: Username for cold registry authentication
- `registry.cold.password`: Password for cold registry authentication
- `registry.cold.headers`: Custom headers for cold registry requests

#### Logging
- `logging.level`: Log level (debug, info, warn, error)
- `logging.format`: Log format (json, console)

### Environment Variables

All configuration options can be overridden using environment variables:

```bash
export MIRROR_SERVER_PORT=5000
export MIRROR_REGISTRY_HOT_URL=https://registry.cn-hangzhou.aliyuncs.com
export MIRROR_REGISTRY_COLD_URL=http://localhost:5001
export MIRROR_LOGGING_LEVEL=info
```

## How It Works

### Manifest Requests (`GET /v2/<name>/manifests/<reference>`)

1. Client requests a manifest from the mirror registry
2. Mirror registry first checks the hot registry (Aliyun ACR)
3. If found in hot registry: Response is proxied back to client
4. If not found in hot registry: Mirror registry checks the cold registry
5. If found in cold registry: Response is proxied back to client
6. If not found in either: Returns 404

### Blob Requests (`GET /v2/<name>/blobs/<digest>`)

1. Client requests a blob from the mirror registry
2. Mirror registry first checks if the blob exists in the hot registry
3. If found in hot registry: Returns HTTP 307 redirect to hot registry
4. If not found in hot registry: Checks the cold registry
5. If found in cold registry: Returns HTTP 307 redirect to cold registry
6. If not found in either: Returns 404

The client follows the 307 redirect and downloads the blob directly from the appropriate backend, ensuring high performance.

## Production Deployment

### Using Docker

1. Build the Docker image:
```bash
docker build -t mirror-registry:latest .
```

2. Run with custom configuration:
```bash
docker run -d \
  --name mirror-registry \
  -p 5000:5000 \
  -v /path/to/config.yaml:/root/config.yaml:ro \
  mirror-registry:latest
```

### Using Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mirror-registry
spec:
  replicas: 2
  selector:
    matchLabels:
      app: mirror-registry
  template:
    metadata:
      labels:
        app: mirror-registry
    spec:
      containers:
      - name: mirror-registry
        image: mirror-registry:latest
        ports:
        - containerPort: 5000
        env:
        - name: MIRROR_REGISTRY_HOT_URL
          value: "https://registry.cn-hangzhou.aliyuncs.com"
        - name: MIRROR_REGISTRY_COLD_URL
          value: "http://cold-registry:5000"
---
apiVersion: v1
kind: Service
metadata:
  name: mirror-registry
spec:
  selector:
    app: mirror-registry
  ports:
  - port: 5000
    targetPort: 5000
```

### HTTPS Setup

For production use, you should place a reverse proxy (Nginx or Caddy) in front of the mirror registry to handle HTTPS:

#### Nginx Configuration
```nginx
server {
    listen 443 ssl http2;
    server_name registry.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Caddy Configuration
```
registry.example.com {
    reverse_proxy localhost:5000
}
```

## Monitoring

### Health Check

The application provides a health check endpoint:

```bash
curl http://localhost:5000/health
```

Response:
```json
{"status":"healthy"}
```

### Logging

The application uses structured logging with zerolog. Log levels can be configured via the configuration file or environment variables.

## Development

### Building

```bash
go build -o mirror-registry ./cmd
```

### Testing

```bash
go test ./...
```

### Running in Development Mode

```bash
go run ./cmd/main.go
```

## Roadmap

- [ ] Cache warming from cold to hot registry
- [ ] Support for `docker push` operations
- [ ] Authentication proxy with user management
- [ ] Prometheus metrics integration
- [ ] Plugin architecture for custom routing strategies

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.