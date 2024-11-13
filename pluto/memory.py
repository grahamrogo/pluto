import paramiko
import os
import logging
from pathlib import Path

def dump_memory(instance_id, ip_address, key_file, output_dir="memory_dumps", local_avml_path="/Users/grahamrogozinski/pluto/pluto/avml", username="ubuntu"):
    """
    Acquire memory from an EC2 instance using AVML and SCP.

    Args:
        instance_id (str): ID of the target EC2 instance.
        ip_address (str): Public or private IP of the instance.
        key_file (str): Path to the private key file for SSH access.
        output_dir (str): Local directory to store memory dumps.
        local_avml_path (str): Path to the local AVML binary.
        username (str): SSH username for the EC2 instance (default: 'ec2-user').
    """
    logging.info(f"Starting memory acquisition for instance: {instance_id}")
    instance_folder = Path(output_dir) / instance_id
    instance_folder.mkdir(parents=True, exist_ok=True)
    local_file_path = instance_folder / "memory.lime"
    remote_avml_path = "/tmp/avml"
    remote_memory_dump_path = f"/tmp/{instance_id}_memory.lime"

    try:
        # Establish an SSH connection
        logging.info("Establishing SSH connection to the instance.")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip_address, username=username, key_filename=key_file)

        # Transfer the AVML binary
        logging.info("Transferring AVML binary to the instance via SCP.")
        scp_transfer(ssh, local_avml_path, remote_avml_path)

        # Run the AVML command on the instance
        logging.info("Running AVML to acquire memory.")
        stdin, stdout, stderr = ssh.exec_command(f"sudo chmod +x {remote_avml_path}")
        # Run the AVML command and adjust permissions
        avml_command = f"sudo {remote_avml_path} {remote_memory_dump_path} && sudo chmod 644 {remote_memory_dump_path}"
        stdin, stdout, stderr = ssh.exec_command(avml_command)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            raise Exception(f"Error running AVML: {stderr.read().decode()}")
        logging.info(f"AVML execution complete. Remote memory dump at: {remote_memory_dump_path}")

        # Check if the file exists remotely
        logging.info("Verifying the existence of the memory dump on the remote instance.")
        with ssh.open_sftp() as sftp:
            if not remote_file_exists(sftp, remote_memory_dump_path):
                raise FileNotFoundError(f"Remote memory dump not found at: {remote_memory_dump_path}")

            # Transfer the memory dump back to the local machine
            logging.info("Downloading memory dump to the local machine.")
            sftp.get(remote_memory_dump_path, str(local_file_path))
            logging.info(f"Memory dump successfully downloaded to: {local_file_path}")

            # Clean up remote files
            logging.info("Cleaning up remote files.")
            ssh.exec_command(f"rm -f {remote_avml_path} {remote_memory_dump_path}")

    except Exception as e:
        logging.error(f"Error during memory acquisition: {e}")
    finally:
        ssh.close()


def scp_transfer(ssh, local_path, remote_path, to_remote=True):
    """
    Transfer files using SCP.

    Args:
        ssh (paramiko.SSHClient): Active SSH connection.
        local_path (str): Path to the local file.
        remote_path (str): Path to the remote file.
        to_remote (bool): Direction of transfer (default: True for local -> remote).
    """
    try:
        with ssh.open_sftp() as sftp:
            if to_remote:
                sftp.put(local_path, remote_path)
                logging.info(f"Transferred {local_path} to {remote_path}.")
            else:
                sftp.get(remote_path, local_path)
                logging.info(f"Transferred {remote_path} to {local_path}.")
    except Exception as e:
        logging.error(f"Error during SCP transfer: {e}")
        raise


def remote_file_exists(sftp, path):
    """
    Check if a file exists on the remote server.

    Args:
        sftp (paramiko.SFTPClient): Active SFTP connection.
        path (str): Remote file path to check.

    Returns:
        bool: True if the file exists, False otherwise.
    """
    try:
        sftp.stat(path)
        return True
    except FileNotFoundError:
        return False


# if __name__ == "__main__":
#     logging.basicConfig(level=logging.INFO)
#     instance_id = "i-0a1b2c3d4e5f6g7h8"
#     ip_address = "44.204.232.168"
#     key_file = "/Users/grahamrogozinski/pluto/aws-config/test.pem"
#     output_dir = "memory_dumps"
#     dump_memory(instance_id, ip_address, key_file, output_dir)