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
        else:
            self.config_file_path = "/home/ubuntu/.cloudflared/config.yml"  # Adjust based on your Linux env

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
                restart_policy={"Name": "unless-stopped"}
            )

            subdomain = f"user{user_id}.dev.aitoolsuite.xyz"
            self._update_cloudflare_config(subdomain, assigned_port)
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

            # Create new rule with proper formatting
            new_rule = {
                'hostname': subdomain,
                'service': f'http://localhost:{port}'
            }

            # Insert before the catch-all rule (service: http_status:404)
            # Find the catch-all rule index
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
            logger.info(f"Added {subdomain} to Cloudflare config on port {port}")
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