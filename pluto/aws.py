import boto3
import logging

def get_aws_session(region=None):
    session = boto3.session.Session(region_name=region)
    if not region:
        region = session.region_name
        if not region:
            raise ValueError("Region not specified and no default region found in AWS configuration.")
    logging.info(f"Using AWS region: {region}")
    return session

def list_ec2_instances(session):
    ec2 = session.client('ec2')
    instances = ec2.describe_instances()
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            print(f"Instance ID: {instance['InstanceId']} State: {instance['State']['Name']}")
