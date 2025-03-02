# docker_service.py
import docker
import logging
import random
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class DockerService:
    def __init__(self):
        self.client = docker.from_env()
        
    def create_container(self, user_id, image_name="r1971d3_aitm", port=8501):
        """Create a new Docker container for the user"""
        try:
            # Create a unique container name
            container_name = f"r1971d3_aitm_{user_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            # Set container labels for tracking
            labels = {
                "user_id": str(user_id),
                "created_at": datetime.now().isoformat(),
                "app": "stridegpt"
            }
            
            # Assign a random available port between 8501 and 9000
            assigned_port = random.randint(8501, 9000)

            # Create the container
            container = self.client.containers.run(
                image=image_name,
                name=container_name,
                detach=True,
                labels=labels,
                ports={f"8501/tcp": assigned_port},  # Dynamically assigns a host port
                restart_policy={"Name": "unless-stopped"}
            )
            
            # Get the assigned port
            # container_info = self.client.api.inspect_container(container.id)
            # port_mappings = container_info['NetworkSettings']['Ports'].get(f'{port}/tcp', [])
            # host_port = port_mappings[0]['HostPort'] if port_mappings else None
            
            logger.info(f"Created container {container.id} for user {user_id} on port {assigned_port}")
            
            return {
                "container_id": container.id,
                "container_name": container_name,
                "port": assigned_port,
                "status": container.status
            }
        except Exception as e:
            logger.error(f"Error creating container for user {user_id}: {str(e)}")
            raise
    
    def get_user_container(self, user_id):
        """Get the active container for a user"""
        try:
            containers = self.client.containers.list(
                all=True,
                filters={
                    "label": [f"user_id={user_id}", "app=stridegpt"]
                }
            )
            
            if not containers:
                return None
            
            # Return the most recently created container
            newest_container = max(containers, key=lambda c: c.labels.get('created_at', ''))
            
            # Get the port mapping
            container_info = self.client.api.inspect_container(newest_container.id)
            port_mappings = container_info['NetworkSettings']['Ports'].get('8501/tcp', [])
            host_port = port_mappings[0]['HostPort'] if port_mappings else None
            
            return {
                "container_id": newest_container.id,
                "container_name": newest_container.name,
                "port": host_port,
                "status": newest_container.status
            }
        except Exception as e:
            logger.error(f"Error retrieving container for user {user_id}: {str(e)}")
            raise
    
    def start_container(self, container_id):
        """Start a stopped container"""
        try:
            container = self.client.containers.get(container_id)
            if container.status != "running":
                container.start()
                logger.info(f"Started container {container_id}")
            return container.status
        except Exception as e:
            logger.error(f"Error starting container {container_id}: {str(e)}")
            raise
    
    def stop_container(self, container_id):
        """Stop a running container"""
        try:
            container = self.client.containers.get(container_id)
            if container.status == "running":
                container.stop()
                logger.info(f"Stopped container {container_id}")
            return container.status
        except Exception as e:
            logger.error(f"Error stopping container {container_id}: {str(e)}")
            raise
    
    def remove_container(self, container_id):
        """Remove a container"""
        try:
            container = self.client.containers.get(container_id)
            if container.status == "running":
                container.stop()
            container.remove()
            logger.info(f"Removed container {container_id}")
            return True
        except Exception as e:
            logger.error(f"Error removing container {container_id}: {str(e)}")
            raise
    
    def cleanup_expired_containers(self, hours=24):
        """Remove containers older than specified hours"""
        try:
            cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
            
            # Get all containers with our app label
            containers = self.client.containers.list(
                all=True,
                filters={"label": ["app=stridegpt"]}
            )
            
            removed_count = 0
            for container in containers:
                created_at = container.labels.get('created_at', '')
                if created_at and created_at < cutoff_time:
                    self.remove_container(container.id)
                    removed_count += 1
            
            logger.info(f"Removed {removed_count} expired containers")
            return removed_count
        except Exception as e:
            logger.error(f"Error cleaning up expired containers: {str(e)}")
            raise