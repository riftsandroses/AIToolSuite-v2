import docker
import logging
import random
import yaml
import subprocess
import os
import platform
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

class DockerService:
    def __init__(self):
        self.client = docker.from_env()

        # Use platform-specific config file path
        if platform.system() == "Windows":
            self.config_file_path = str(Path.home() / ".cloudflared" / "config.yml")
            self.nginx_config_path = "C:/nginx/conf/nginx.conf"  # Adjust to your nginx path
        else:
            self.config_file_path = "/home/ubuntu/.cloudflared/config.yml"
            self.nginx_config_path = "/etc/nginx/nginx.conf"

    def create_container(self, user_id, image_name="r1971d3_aitm", port=8501):
        try:
            container_name = f"r1971d3_aitm_{user_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            labels = {
                "user_id": str(user_id),
                "created_at": datetime.now().isoformat(),
                "app": "stridegpt"
            }
            assigned_port = random.randint(8501, 9000)

            container = self.client.containers.run(
                image=image_name,
                name=container_name,
                detach=True,
                labels=labels,
                ports={"8501/tcp": assigned_port},
                restart_policy={"Name": "unless-stopped"},
                environment={
                    "STREAMLIT_SERVER_HEADLESS": "true",
                    "STREAMLIT_SERVER_PORT": "8501",
                    "STREAMLIT_SERVER_ADDRESS": "0.0.0.0",
                    "STREAMLIT_SERVER_BASE_URL_PATH": "",
                    "STREAMLIT_BROWSER_GATHER_USAGE_STATS": "false",
                    "STREAMLIT_SERVER_ENABLE_CORS": "false",
                    "STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION": "false"
                }
            )

            subdomain = f"user{user_id}.dev.aitoolsuite.xyz"
            
            # Update both Cloudflare config and Nginx config
            self._update_cloudflare_config(subdomain, assigned_port)
            self._update_nginx_config(user_id, assigned_port)
            self._create_dns_route(subdomain)

            logger.info(f"Created container {container.id} for user {user_id} on port {assigned_port} with subdomain {subdomain}")

            return {
                "container_id": container.id,
                "container_name": container_name,
                "port": assigned_port,
                "subdomain": subdomain,
                "status": container.status
            }
        except Exception as e:
            logger.error(f"Error creating container for user {user_id}: {str(e)}")
            raise

    def get_user_container(self, user_id):
        try:
            containers = self.client.containers.list(
                all=True,
                filters={"label": [f"user_id={user_id}", "app=stridegpt"]}
            )
            if not containers:
                return None

            newest_container = max(containers, key=lambda c: c.labels.get('created_at', ''))
            container_info = self.client.api.inspect_container(newest_container.id)
            port_mappings = container_info['NetworkSettings']['Ports'].get('8501/tcp', [])
            host_port = port_mappings[0]['HostPort'] if port_mappings else None
            subdomain = f"user{user_id}.dev.aitoolsuite.xyz"

            return {
                "container_id": newest_container.id,
                "container_name": newest_container.name,
                "port": host_port,
                "subdomain": subdomain,
                "status": newest_container.status
            }
        except Exception as e:
            logger.error(f"Error retrieving container for user {user_id}: {str(e)}")
            raise

    def remove_container(self, container_id, user_id=None):
        try:
            container = self.client.containers.get(container_id)
            if not user_id:
                user_id = container.labels.get('user_id')

            if container.status == "running":
                container.stop()
            container.remove()

            if user_id:
                subdomain = f"user{user_id}.dev.aitoolsuite.xyz"
                self._remove_from_cloudflare_config(subdomain)
                self._remove_from_nginx_config(user_id)
                self._remove_dns_route(subdomain)

            logger.info(f"Removed container {container_id}")
            return True
        except Exception as e:
            logger.error(f"Error removing container {container_id}: {str(e)}")
            raise

    def cleanup_expired_containers(self, hours=168):
        try:
            cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
            containers = self.client.containers.list(
                all=True,
                filters={"label": ["app=stridegpt"]}
            )
            removed_count = 0
            for container in containers:
                created_at = container.labels.get('created_at', '')
                if created_at and created_at < cutoff_time:
                    user_id = container.labels.get('user_id')
                    self.remove_container(container.id, user_id)
                    removed_count += 1
            logger.info(f"Removed {removed_count} expired containers")
            return removed_count
        except Exception as e:
            logger.error(f"Error cleaning up expired containers: {str(e)}")
            raise

    def _update_nginx_config(self, user_id, port):
        """Update nginx config to add a new server block for the user subdomain"""
        try:
            # Read current nginx config
            with open(self.nginx_config_path, 'r') as file:
                nginx_config = file.read()

            # Create new server block for the user subdomain
            new_server_block = f"""
    # Server block for user{user_id}
    server {{
        listen       80;
        server_name  user{user_id}.dev.aitoolsuite.xyz;
        
        # Handle Streamlit's core static files and API endpoints
        location /_stcore/ {{
            proxy_pass         http://127.0.0.1:{port};
            proxy_set_header   Host $host;
            proxy_set_header   X-Real-IP $remote_addr;
            proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto $scheme;
            proxy_set_header   X-Forwarded-Host $host;
            proxy_set_header   X-Forwarded-Port $server_port;
            
            # WebSocket support for Streamlit
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_read_timeout 86400;
        }}
        
        # Handle legacy static files (redirect to _stcore)
        location /static/ {{
            proxy_pass         http://127.0.0.1:{port}/_stcore/static/;
            proxy_set_header   Host $host;
            proxy_set_header   X-Real-IP $remote_addr;
            proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto $scheme;
        }}
        
        # Handle Streamlit's health check
        location /healthz {{
            proxy_pass         http://127.0.0.1:{port};
            proxy_set_header   Host $host;
        }}
        
        # Handle Streamlit's health check (alternative path)
        location /_stcore/health {{
            proxy_pass         http://127.0.0.1:{port};
            proxy_set_header   Host $host;
        }}
        
        # Handle allowed message origins
        location /_stcore/allowed-message-origins {{
            proxy_pass         http://127.0.0.1:{port};
            proxy_set_header   Host $host;
        }}
        
        # Handle vendor files
        location /vendor/ {{
            proxy_pass         http://127.0.0.1:{port};
            proxy_set_header   Host $host;
        }}
        
        # Proxy all other requests to the Streamlit container
        location / {{
            proxy_pass         http://127.0.0.1:{port};
            proxy_set_header   Host $host;
            proxy_set_header   X-Real-IP $remote_addr;
            proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto $scheme;
            proxy_set_header   X-Forwarded-Host $host;
            proxy_set_header   X-Forwarded-Port $server_port;
            
            # WebSocket support for Streamlit
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_read_timeout 86400;
            proxy_buffering off;
        }}
    }}
"""

            # Remove any existing server block for this user
            self._remove_from_nginx_config(user_id, update_file=False)
            
            # Add the new server block before the closing brace of the http block
            # Find the last closing brace
            last_brace_index = nginx_config.rfind('}')
            if last_brace_index != -1:
                nginx_config = nginx_config[:last_brace_index] + new_server_block + nginx_config[last_brace_index:]
            else:
                # If no closing brace found, append at the end
                nginx_config += new_server_block

            # Write updated config
            with open(self.nginx_config_path, 'w') as file:
                file.write(nginx_config)

            # Reload nginx
            self._reload_nginx()
            logger.info(f"Added nginx server block for user{user_id} on port {port}")

        except Exception as e:
            logger.error(f"Error updating nginx config for user {user_id}: {str(e)}")
            raise

    def _remove_from_nginx_config(self, user_id, update_file=True):
        """Remove server block for user subdomain from nginx config"""
        try:
            if not update_file:
                return  # Just skip if we're not updating the file
                
            with open(self.nginx_config_path, 'r') as file:
                nginx_config = file.read()

            # Remove the server block for this user using regex
            import re
            pattern = rf'    # Server block for user{user_id}.*?    \}}\n'
            nginx_config = re.sub(pattern, '', nginx_config, flags=re.DOTALL)

            with open(self.nginx_config_path, 'w') as file:
                file.write(nginx_config)

            self._reload_nginx()
            logger.info(f"Removed nginx server block for user{user_id}")

        except Exception as e:
            logger.error(f"Error removing nginx config for user {user_id}: {str(e)}")

    def _reload_nginx(self):
        """Reload nginx configuration"""
        try:
            if platform.system() == "Windows":
                # For Windows nginx
                subprocess.run(["nginx", "-s", "reload"], check=True)
            else:
                # For Linux nginx
                subprocess.run(["sudo", "nginx", "-s", "reload"], check=True)
            
            logger.info("Nginx reloaded successfully")
        except Exception as e:
            logger.error(f"Error reloading nginx: {str(e)}")
            raise

    def _update_cloudflare_config(self, subdomain, port):
        try:
            # Read current config
            with open(self.config_file_path, 'r') as file:
                config = yaml.safe_load(file)

            # Ensure config structure exists
            if 'ingress' not in config:
                config['ingress'] = []

            # Remove any existing rule for this subdomain first
            config['ingress'] = [
                rule for rule in config['ingress'] 
                if rule.get('hostname') != subdomain
            ]

            # Create new rule - route to nginx (port 80) instead of directly to container
            new_rule = {
                'hostname': subdomain,
                'service': f'http://localhost:80'  # Route to nginx, not directly to container
            }

            # Insert before the catch-all rule (service: http_status:404)
            catch_all_index = -1
            for i, rule in enumerate(config['ingress']):
                if 'service' in rule and 'http_status:404' in rule['service']:
                    catch_all_index = i
                    break
            
            if catch_all_index != -1:
                config['ingress'].insert(catch_all_index, new_rule)
            else:
                config['ingress'].append(new_rule)

            # Write config with proper formatting
            with open(self.config_file_path, 'w') as file:
                yaml.dump(config, file, default_flow_style=False, sort_keys=False, indent=2)

            self._restart_cloudflared()
            logger.info(f"Added {subdomain} to Cloudflare config routing to nginx")
        except Exception as e:
            logger.error(f"Error updating Cloudflare config: {str(e)}")
            raise

    def _remove_from_cloudflare_config(self, subdomain):
        try:
            with open(self.config_file_path, 'r') as file:
                config = yaml.safe_load(file)

            config['ingress'] = [
                rule for rule in config['ingress'] 
                if rule.get('hostname') != subdomain
            ]

            with open(self.config_file_path, 'w') as file:
                yaml.dump(config, file, default_flow_style=False, sort_keys=False, indent=2)

            self._restart_cloudflared()
            logger.info(f"Removed {subdomain} from Cloudflare config")
        except Exception as e:
            logger.error(f"Error removing from Cloudflare config: {str(e)}")

    def _create_dns_route(self, subdomain):
        """Create DNS route for the subdomain through Cloudflare tunnel"""
        try:
            # Extract tunnel name from config
            tunnel_name = self._get_tunnel_name()
            
            # Run the DNS route command
            cmd = ["cloudflared", "tunnel", "route", "dns", tunnel_name, subdomain]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                check=False
            )
            
            if result.returncode == 0:
                logger.info(f"Successfully created DNS route for {subdomain}")
            else:
                # Check if the route already exists (this is often okay)
                if "already exists" in result.stderr.lower() or "conflict" in result.stderr.lower():
                    logger.info(f"DNS route for {subdomain} already exists")
                else:
                    logger.warning(f"DNS route command completed with warnings: {result.stderr}")
            
        except Exception as e:
            logger.error(f"Error creating DNS route for {subdomain}: {str(e)}")
            # Don't raise the exception as DNS route creation failure shouldn't stop container creation

    def _remove_dns_route(self, subdomain):
        """Remove DNS route for the subdomain"""
        try:
            # Get tunnel name
            tunnel_name = self._get_tunnel_name()
            
            # Run the DNS route deletion command
            cmd = ["cloudflared", "tunnel", "route", "dns", "--overwrite-dns", tunnel_name, subdomain]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                check=False
            )
            
            if result.returncode == 0:
                logger.info(f"Successfully removed DNS route for {subdomain}")
            else:
                logger.warning(f"Failed to remove DNS route for {subdomain}: {result.stderr}")
            
        except Exception as e:
            logger.error(f"Error removing DNS route for {subdomain}: {str(e)}")

    def _get_tunnel_name(self):
        """Extract tunnel name from config file"""
        try:
            with open(self.config_file_path, 'r') as file:
                config = yaml.safe_load(file)
            
            tunnel_name = config.get('tunnel', 'dev2')  # Default to 'dev2' if not found
            return tunnel_name
        except Exception as e:
            logger.error(f"Error reading tunnel name from config: {str(e)}")
            return 'dev2'  # Fallback to your tunnel name

    def _restart_cloudflared(self):
        try:
            if platform.system() == "Windows":
                # Kill cloudflared and restart
                subprocess.run(["taskkill", "/F", "/IM", "cloudflared.exe"], check=False)
                # Add a small delay to ensure process is killed
                import time
                time.sleep(2)
                subprocess.Popen(["cloudflared", "tunnel", "run", "dev2"], shell=True)
            else:
                # Try systemd first
                try:
                    subprocess.run(["sudo", "systemctl", "restart", "cloudflared"], check=True)
                except subprocess.CalledProcessError:
                    subprocess.run(["pkill", "-f", "cloudflared"], check=False)
                    import time
                    time.sleep(2)
                    subprocess.Popen(["cloudflared", "tunnel", "run", "dev2"])
            
            logger.info("Cloudflared restarted successfully")
        except Exception as e:
            logger.error(f"Error restarting cloudflared: {str(e)}")
            raise