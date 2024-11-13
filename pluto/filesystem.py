import paramiko
import logging
from pathlib import Path
import subprocess


def list_drives(ip_address, key_file, username="ubuntu"):
    """
    List available drives on the remote EC2 instance.

    Args:
        ip_address (str): Public or private IP of the instance.
        key_file (str): Path to the private key file for SSH access.
        username (str): SSH username for the EC2 instance (default: 'ubuntu').

    Returns:
        list: A list of available drives on the remote instance.
    """
    logging.info("Listing available drives on the remote instance.")
    try:
        # Establish an SSH connection
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip_address, username=username, key_filename=key_file)

        # Run the lsblk command to list block devices
        lsblk_command = "lsblk -o NAME,SIZE,TYPE,MOUNTPOINT -d"
        stdin, stdout, stderr = ssh.exec_command(lsblk_command)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            raise Exception(f"Error listing drives: {stderr.read().decode()}")

        # Parse the output
        drives_output = stdout.read().decode().strip()
        logging.info(f"Available drives:\n{drives_output}")
        drives = [line.split()[0] for line in drives_output.splitlines()[1:]]  # Skip the header
        return drives

    except Exception as e:
        logging.error(f"Error listing drives: {e}")
        return []

    finally:
        ssh.close()



def acquire_filesystem_image(instance_id, ip_address, key_file, target_disk, output_dir="filesystem_images", username="ubuntu"):
    """
    Acquire a filesystem image from an EC2 instance using dd and stream it over SSH.

    Args:
        instance_id (str): ID of the target EC2 instance.
        ip_address (str): Public or private IP of the instance.
        key_file (str): Path to the private key file for SSH access.
        target_disk (str): The disk or partition to image (e.g., '/dev/xvda').
        output_dir (str): Local directory to store filesystem images.
        username (str): SSH username for the EC2 instance (default: 'ubuntu').
    """
    logging.info(f"Starting filesystem acquisition for instance: {instance_id}")
    instance_folder = Path(output_dir) / instance_id
    instance_folder.mkdir(parents=True, exist_ok=True)
    local_file_path = instance_folder / f"{instance_id}_filesystem.img"

    try:
        # Create the SSH command to stream data
        logging.info("Setting up SSH command to stream the filesystem image.")
        ssh_command = [
            "ssh",
            "-i", key_file,
            f"{username}@{ip_address}",
            f"sudo dd if={target_disk} bs=4M status=progress"
        ]

        # Create the local command to save the streamed data
        logging.info("Streaming filesystem image to the local machine.")
        with open(local_file_path, "wb") as local_file:
            process = subprocess.Popen(
                ssh_command,
                stdout=local_file,
                stderr=subprocess.PIPE
            )

            # Capture and log stderr for debugging
            _, stderr = process.communicate()

        if process.returncode != 0:
            raise Exception(f"Error acquiring filesystem image: {stderr.decode()}")
        
        logging.info(f"Filesystem image successfully saved to: {local_file_path}")

    except Exception as e:
        logging.error(f"Error during filesystem acquisition: {e}")

