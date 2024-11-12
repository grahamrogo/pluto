import argparse
import logging
import aws, memory, recovery, filesystem
import boto3
import logging
from memory import dump_memory

def get_instance_ip(session, identifier, use_private_ip=False):
    """
    Fetch the IP address of an EC2 instance based on name or partial ID.

    Args:
        session (boto3.Session): AWS session object.
        identifier (str): Name or partial ID of the instance.
        use_private_ip (bool): Whether to return the private IP (default: False for public IP).

    Returns:
        str: IP address of the instance.
    """
    ec2 = session.client('ec2')
    try:
        # Search for instance based on identifier
        response = ec2.describe_instances(
            Filters=[
                {'Name': 'instance-state-name', 'Values': ['running']},
                {
                    'Name': 'tag:Name',
                    'Values': [f"*{identifier}*"]  # Match partial name
                }
            ]
        )

        # Find the first matching instance
        for reservation in response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                ip_field = 'PrivateIpAddress' if use_private_ip else 'PublicIpAddress'
                ip_address = instance.get(ip_field)
                if ip_address:
                    return ip_address
        raise ValueError(f"No running instance found for identifier: {identifier}")
    except Exception as e:
        raise ValueError(f"Error fetching instance IP: {e}")


def memory(identifier, key_file, region, output_dir, use_private_ip):
    """Acquire memory dump from an EC2 instance."""
    session = boto3.Session(region_name=region)

    try:
        # Fetch the instance IP
        logging.info(f"Fetching IP for instance with identifier: {identifier}")
        ip_address = get_instance_ip(session, identifier, use_private_ip)
        logging.info(f"IP address for instance {identifier}: {ip_address}")

        # Perform memory dump
        dump_memory(identifier, ip_address, key_file, output_dir=output_dir)
    except Exception as e:
        logging.error(f"Memory acquisition failed: {e}")


def resolve_instance_id(partial_id, session):
    """
    Resolve a partial instance ID to the full ID.

    Args:
        partial_id (str): Partial or full EC2 Instance ID.
        session (boto3.Session): AWS session object.

    Returns:
        str: The full EC2 Instance ID if found, else raises an error.
    """
    ec2 = session.client('ec2')

    try:
        response = ec2.describe_instances()
        matching_instances = []

        # Search for instances with matching IDs
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


def main():
    # Main parser
    parser = argparse.ArgumentParser(
        description="Pluto - Cloud Forensics Tool for AWS EC2 Instances"
    )
    parser.add_argument(
        '-r', '--region',
        help="AWS region (defaults to region in AWS config)",
        default=None
    )

    # Subparsers for specific tasks
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: List EC2 instances
    subparsers.add_parser('list', help="List all EC2 instances in the specified region")

    # Subcommand: Memory dump
    memory_parser = subparsers.add_parser(
        'memory', help="Dump memory of a specific EC2 instance"
    )
    memory_parser.add_argument(
        '-i', '--instance-id', required=True, help="Partial or full EC2 Instance ID"
    )
    memory_parser.add_argument(
        '-o', '--output-dir', default="memory_dumps", help="Local directory to store memory dumps"
    )

    # Subcommand: Recover deleted files
    recover_parser = subparsers.add_parser(
        'recover', help="Recover deleted files from a snapshot"
    )
    recover_parser.add_argument(
        '-s', '--snapshot-id', required=True, help="Snapshot ID for recovery"
    )

    # Subcommand: Analyze filesystem
    analyze_parser = subparsers.add_parser(
        'analyze', help="Analyze the filesystem of a specific EC2 instance"
    )
    analyze_parser.add_argument(
        '-i', '--instance-id', required=True, help="Partial or full EC2 Instance ID"
    )

    # Parse arguments
    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(level=logging.INFO)

    # Execute the selected command
    session = aws.get_aws_session(args.region)
    if args.command == 'list':
        aws.list_ec2_instances(session)
    elif args.command == 'memory':
        try:
            # Resolve partial instance ID
            full_instance_id = resolve_instance_id(args.instance_id, session)
            logging.info(f"Resolved partial ID '{args.instance_id}' to full ID '{full_instance_id}'")
            
            # Perform memory dump
            memory.dump_memory(
                instance_id=full_instance_id,
                session=session,
                output_dir=args.output_dir
            )
        except ValueError as e:
            logging.error(e)
    elif args.command == 'recover':
        recovery.recover_deleted_files(args.snapshot_id)
    elif args.command == 'analyze':
        try:
            # Resolve partial instance ID
            full_instance_id = resolve_instance_id(args.instance_id, session)
            logging.info(f"Resolved partial ID '{args.instance_id}' to full ID '{full_instance_id}'")
            
            # Perform filesystem analysis
            filesystem.analyze_filesystem(full_instance_id)
        except ValueError as e:
            logging.error(e)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
