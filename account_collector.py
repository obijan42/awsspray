#!/usr/bin/env python3

import security_changes as s
import time
import json
from botocore.exceptions import ClientError
import boto3
import logging
import sys



failedaccounts = []


# Assume role in the account to deploy and configure
def assume_role(session, role_arn):
    sts_client = session.client('sts')
    # print(f"DEBUG: Assuming role {role_arn}")
    try:
        assumedRoleObject = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="SecManagerBaseline"
        )
        assumedRoleObject = assumedRoleObject['Credentials']
        return boto3.session.Session(aws_access_key_id=assumedRoleObject['AccessKeyId'],
                                     aws_secret_access_key=assumedRoleObject['SecretAccessKey'],
                                     aws_session_token=assumedRoleObject['SessionToken'], region_name=session.region_name
                                     )
    except Exception as e:
        print(f"ERROR: assuming {role_arn} {e}")
        return None


# Get AWS account alias
def get_aws_account_name(session):
    try:
        account_info = session.client('iam').list_account_aliases()
        account_name = account_info['AccountAliases']
        return account_name[0]
    except Exception as e:
        print(f"ERROR: get_aws_account_name {e} ")
        return None


def get_accounts_all(session):
    # master_session = assume_role(session, MASTER_ROLE)
    return s.extract_ids_from_accountlist( s.list_accounts_for_parent(session=session))


def all_accounts_runner(session,cb, actlist=[], rolename='OrganizationAccountAccessRole'):
    global failedaccounts

    for ac in actlist:
        print(
            f"Processing {ac} ...")
        if ac in failedaccounts:
            print("NOTICE: This account previously failed. Skipping attempt.")
            continue
        else:
            res = assume_role(
                session, f"arn:aws:iam::{ac}:role/{rolename}")
            if res:
                if (cb(res)):
                    print('SUCCESS')
                else:
                    print("NOTICE: Test failed")
            else:
                print("WARNING: Could not assume, skipping")
                failedaccounts.append(ac)


def refresh_accounts_db(session, ou):
    print("INFO: Starting accounts retrieval")
    accounts = get_accounts_all(session, ou)
    print(accounts)


# -------- Callbacks begin --------


def run_all_regions(ses):
    myacts=get_accounts_all(ses)
    print(f"DEBUG: Accounts: {myacts}")
    for region in ['us-west-2', 'us-east-1','us-west-1', 'us-east-2', 'eu-central-1', 'eu-west-1']:
        run_per_region(region,ses,myacts)


def run_per_region(myregion,ses,act_list):
    # Get account ID and account alias

    mysession = boto3.session.Session(region_name=myregion)
    current_account_id = s.get_aws_account_id(mysession)
    print(
        f"Running from {current_account_id} named {get_aws_account_name(mysession)} in {mysession.region_name}...")


    s.master_run_all(mysession, act_list)


    # all_accounts_runner(mysession, s.child_gd_acceptinvite, 'gda_' + myregion)
    # all_accounts_runner(mysession, s.child_sh_acceptinvite, 'sha_' + myregion)
    # all_accounts_runner(mysession, s.child_enable_config, act_list)

    all_accounts_runner(mysession, s.child_config_acceptinvite, act_list)

    # all_accounts_runner(mysession, s.child_stacksetrolefix, 'stackfix')
    # all_accounts_runner(mysession, s.child_fixs3public, 's3pubblock')
    # all_accounts_runner(mysession, s.child_fixSSM, 'ssm1' + myregion)
    # all_accounts_runner(mysession, s.child_fixSHRules, 'SHRules2' + myregion)
    # all_accounts_runner(mysession, s.child_setBucketLogging, 'S3Log1')
    # all_accounts_runner(mysession, s.child_RunInspector, 'RInspect1' + myregion)
    # all_accounts_runner(mysession, fixBucketTags, 'fixS3Tags')


def main():
    # logging.basicConfig(level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(message)s')

    ses = boto3.session.Session()
    s.masteraccount = s.get_aws_account_id(ses)

    print(f"Running in {s.masteraccount} named {get_aws_account_name(ses)} in {ses.region_name}...  Assuming it as master")


    print(f"INFO: Boto version : {boto3.__version__}")

    # child_setBucketLogging(assume_role(boto3.session.Session(), "arn:aws:iam::320514908897:role/devsecops-service"))
    # child_RunInspector(boto3.session.Session())
    # exit(0)


    print("DEBUG: Starting to process all regions.")
    run_all_regions(ses)


def lambda_handler(event, context):
    print("WARNING: Not designed as a lambda!")
    main()


if __name__ == '__main__':
    main()
