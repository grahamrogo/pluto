import argparse
import logging
from pathlib import Path
import boto3
from memory import dump_memory
from filesystem import list_drives, acquire_filesystem_image


def list_ec2_instances(session):
    """
    List all running EC2 instances in the AWS account.
    """
    ec2 = session.client('ec2')
    try:
        response = ec2.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )
        print(f"{'Instance ID':<20} {'Name':<30} {'Public IP':<15} {'Private IP':<15}")
        print("-" * 80)
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                public_ip = instance.get('PublicIpAddress', 'N/A')
                private_ip = instance.get('PrivateIpAddress', 'N/A')
                name_tag = next(
                    (tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), 'N/A'
                )
                print(f"{instance_id:<20} {name_tag:<30} {public_ip:<15} {private_ip:<15}")
    except Exception as e:
        logging.error(f"Error listing instances: {e}")


def get_instance_ip(session, identifier, use_private_ip=False):
    """
    Fetch the IP address of an EC2 instance based on name or instance ID.
    """
    ec2 = session.client('ec2')
    try:
        filters = [{'Name': 'instance-state-name', 'Values': ['running']}]
        
        if identifier.startswith("i-"):
            filters.append({'Name': 'instance-id', 'Values': [identifier]})
        else:
            filters.append({'Name': 'tag:Name', 'Values': [f"*{identifier}*"]})

        response = ec2.describe_instances(Filters=filters)

        for reservation in response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                ip_field = 'PrivateIpAddress' if use_private_ip else 'PublicIpAddress'
                ip_address = instance.get(ip_field)
                if ip_address:
                    return ip_address
        
        raise ValueError(f"No running instance found for identifier: {identifier}")
    except Exception as e:
        raise ValueError(f"Error fetching instance IP: {e}")


def resolve_instance_id(partial_id, session):
    """
    Resolve a partial instance ID to the full ID.
    """
    ec2 = session.client('ec2')

    try:
        response = ec2.describe_instances()
        matching_instances = []

        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                if instance_id.endswith(partial_id):
                    matching_instances.append(instance_id)

        if len(matching_instances) == 0:
            raise ValueError(f"No instances found matching the partial ID: {partial_id}")
        elif len(matching_instances) > 1:
            raise ValueError(f"Multiple instances found matching the partial ID: {partial_id} - {matching_instances}")

        return matching_instances[0]

    except Exception as e:
        raise ValueError(f"Error resolving instance ID: {e}")


def memory_command(args, session):
    """
    Execute the memory acquisition command.
    """
    try:
        full_instance_id = resolve_instance_id(args.instance_id, session)
        logging.info(f"Resolved partial ID '{args.instance_id}' to full ID '{full_instance_id}'")

        ip_address = get_instance_ip(session, full_instance_id, args.use_private_ip)
        logging.info(f"IP address for instance {full_instance_id}: {ip_address}")

        logging.info("Initiating memory acquisition...")
        dump_memory(
            instance_id=full_instance_id,
            ip_address=ip_address,
            key_file=args.key_file,
            output_dir=args.output_dir
        )
    except Exception as e:
        logging.error(f"Memory acquisition failed: {e}")


def filesystem_command(args, session):
    """
    Execute the filesystem-related commands (list-drives or acquire).
    """
    try:
        full_instance_id = resolve_instance_id(args.instance_id, session)
        logging.info(f"Resolved partial ID '{args.instance_id}' to full ID '{full_instance_id}'")

        ip_address = get_instance_ip(session, full_instance_id, args.use_private_ip)
        logging.info(f"IP address for instance {full_instance_id}: {ip_address}")

        if args.fs_command == 'list-drives':
            logging.info("Listing drives...")
            drives = list_drives(ip_address, args.key_file)
            print("Available drives:")
            for drive in drives:
                print(drive)
        elif args.fs_command == 'acquire':
            logging.info("Acquiring filesystem image...")
            acquire_filesystem_image(
                instance_id=full_instance_id,
                ip_address=ip_address,
                key_file=args.key_file,
                target_disk=args.target_disk,
                output_dir=args.output_dir
            )
    except Exception as e:
        logging.error(f"Filesystem operation failed: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Pluto - Cloud Forensics Tool for AWS EC2 Instances"
    )
    parser.add_argument(
        '-r', '--region',
        help="AWS region (defaults to region in AWS config)",
        default=None
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser('list', help="List all EC2 instances in the specified region")

    memory_parser = subparsers.add_parser(
        'memory', help="Dump memory of a specific EC2 instance"
    )
    memory_parser.add_argument(
        '-i', '--instance-id', required=True, help="Partial or full EC2 Instance ID"
    )
    memory_parser.add_argument(
        '-k', '--key-file', required=True, help="Path to the SSH private key file"
    )
    memory_parser.add_argument(
        '-o', '--output-dir', default="memory_dumps", help="Local directory to store memory dumps"
    )
    memory_parser.add_argument(
        '--use-private-ip', action='store_true', help="Use private IP instead of public IP"
    )

    fs_parser = subparsers.add_parser(
        'filesystem', help="Filesystem-related operations"
    )
    fs_subparsers = fs_parser.add_subparsers(dest="fs_command", required=True)
    
    list_drives_parser = fs_subparsers.add_parser('list-drives', help="List drives on an EC2 instance")
    list_drives_parser.add_argument('-i', '--instance-id', required=True, help="Instance ID")
    list_drives_parser.add_argument('-k', '--key-file', required=True, help="SSH private key file")
    list_drives_parser.add_argument('--use-private-ip', action='store_true', help="Use private IP")

    acquire_fs_parser = fs_subparsers.add_parser('acquire', help="Acquire filesystem image")
    acquire_fs_parser.add_argument('-i', '--instance-id', required=True, help="Instance ID")
    acquire_fs_parser.add_argument('-k', '--key-file', required=True, help="SSH private key file")
    acquire_fs_parser.add_argument('-t', '--target-disk', required=True, help="Target disk to image")
    acquire_fs_parser.add_argument('-o', '--output-dir', default="filesystem_images", help="Directory to store images")
    acquire_fs_parser.add_argument('--use-private-ip', action='store_true', help="Use private IP")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    session = boto3.Session(region_name=args.region)

    if args.command == 'list':
        list_ec2_instances(session)
    elif args.command == 'memory':
        memory_command(args, session)
    elif args.command == 'filesystem':
        filesystem_command(args, session)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
