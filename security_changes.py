import json
import time

from botocore.exceptions import ClientError

# ---- Utilities ----
masteraccount = ''


def get_gd_detectorid(gd_client):
    try:
        detectors_list = gd_client.list_detectors()
        if not detectors_list["DetectorIds"]:
            print("GuardDuty is not enabled ... enabling.")
            response = gd_client.create_detector(Enable=True,
                                                 FindingPublishingFrequency='FIFTEEN_MINUTES',
                                                 DataSources={'S3Logs': {'Enable': True}})
            # Save DetectorID handler
            DetectorId = response["DetectorId"]
        else:
            print("GuardDuty already enabled on account")
            detectors_list = detectors_list['DetectorIds']

            if len(detectors_list) == 1:
                DetectorId = detectors_list[0]
                print(f"INFO: Active detector: {DetectorId}")
            else:
                print(f"WARNING: Multiple detectors enabled! {detectors_list} ")
                return None
        return DetectorId
    except Exception as e:
        print(f"ERROR: Setting up GD: {e}")
        return None


# Get the AWS account ID
def get_aws_account_id(session):
    return str(session.client("sts").get_caller_identity()["Account"])


'''
 Listing accounts under OU using the paginator
'''


def list_accounts_for_parent(session):
    accounts = []
    client = session.client('organizations')
    for account in client.get_paginator('list_accounts').paginate().build_full_result()[
        'Accounts']:
        if account['Status'] == "ACTIVE":
            # account['ou'] = ou_id
            del account['Arn']
            del account['JoinedMethod']
            # print(f"DEBUG: {account}")
            accounts.append(account)
    return accounts


def extract_ids_from_accountlist(accountlist):
    result = []
    for act in accountlist:
        result.append(act['Id'])
    return result


# ---- Child accounts ----

def child_enable_config(ses):
    if not ses:
        return False

    client = ses.client('config')
    res = client.describe_configuration_recorders()
    if not res:
        return False

    res = res['ConfigurationRecorders']
    if not res:
        return False

    res = res[0]
    if not res:
        return False

    print(f"Config: {res['name']} {res['roleARN']} ")
    return True


def child_gd_acceptinvite(session):
    if not session:
        return False
    res = None
    global masteraccount

    current_account_id = get_aws_account_id(session)

    client = session.client('guardduty')
    detectorid = get_gd_detectorid(client)
    if not detectorid:
        return False

    if not masteraccount:
        print("WARNING: Missing masteraccount config")
        return False

    if masteraccount == current_account_id:
        print("Already in master account, skipping.")
        return True

    masterinfo = None
    try:
        masterinfo = client.get_master_account(DetectorId=detectorid)['Master']
    except Exception as e:
        pass

    if masterinfo:
        print(f"NOTICE: Already connected to master {masterinfo}")
        if masterinfo['AccountId'] == masteraccount:
            return True
        else:
            print(f"WARNING: Wrong master {masterinfo['AccountId']} : Disconnection started")
            client.disassociate_from_master_account(DetectorId=detectorid)

    try:
        res = client.get_paginator('list_invitations').paginate().build_full_result()['Invitations']
    except Exception as e:
        pass

    if not res:
        print("WARNING: No invitations found!")
        return False

    #    print (res)
    try:
        for rec in res:
            if rec['RelationshipStatus'] == 'Invited':
                print(f"NOTICE: Accepting invite {rec['InvitationId']} to {rec['AccountId']}")
                client.accept_invitation(DetectorId=detectorid, MasterId=rec['AccountId'],
                                         InvitationId=rec['InvitationId'])
    except Exception as e:
        print(f"ERROR: {e}")
        return False

    return True


def child_sh_acceptinvite(session):
    if not session:
        return False
    global masteraccount

    client = session.client('securityhub')
    res = None

    try:
        client.enable_security_hub()
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceConflictException':
            pass
        else:
            print(f"Error: Unable to enable Security Hub: {e} ")
            return False

    current_account_id = get_aws_account_id(session)

    if not masteraccount:
        print("WARNING: Missing config")
        return False

    if masteraccount == current_account_id:
        print("Already in master account, skipping.")
        return True

    masterinfo = None
    try:
        masterinfo = client.get_master_account()['Master']
    except Exception as e:
        pass

    if masterinfo:
        print(f"NOTICE: Already connected to master:  {masterinfo}")
        if masteraccount and masteraccount != masterinfo['AccountId']:
            print(f"WARNING: Wrong master {masterinfo['AccountId']} : Disconnection started")
            client.disassociate_from_master_account()
        else:
            return True

    try:
        res = client.get_paginator('list_invitations').paginate().build_full_result()['Invitations']
    except Exception as e:
        print(f"WARNING: Error in invitations: {e}")

    if not res:
        print("WARNING: No invitations found!")
        return False

    #    print (res)
    try:
        for rec in res:
            if rec['MemberStatus'] == 'Invited':
                print(f"NOTICE: Accepting invite {rec['InvitationId']} to {rec['AccountId']}")
                client.accept_invitation(MasterId=rec['AccountId'],
                                         InvitationId=rec['InvitationId'])
                return True
        return False

    except Exception as e:
        print(f"ERROR: {e}")
        return False

def child_config_acceptinvite(session):
    if not session:
        return False
    global masteraccount

    if not masteraccount:
        print("WARNING: Missing config")
        return False

    current_account_id = get_aws_account_id(session)

    if masteraccount == current_account_id:
        print("Already in master account, skipping.")
        return True

    client = session.client('config')
    response = None

    try:
        response = client.put_aggregation_authorization(
            AuthorizedAccountId=masteraccount,
            AuthorizedAwsRegion='us-west-2')
    except ClientError as e:
        #        if e.response['Error']['Code'] == 'ResourceConflictException':
        #            pass
        #        else:
        print(f"Error: Unable to link config: {e} ")
        return False
    print(f"NOTICE: Success on Config auth: {response['AggregationAuthorization']}")
    return True


def child_stacksetrolefix(session):
    if not session:
        return False
    global masteraccount

    if not masteraccount:
        print("WARNING: Missing config")
        return False

    ROLENAME = 'AWSCloudFormationStackSetExecutionRole'
    ADMINPOLICYARN = 'arn:aws:iam::aws:policy/AdministratorAccess'

    current_account_id = get_aws_account_id(session)

    if masteraccount == current_account_id:
        print("Already in master account, skipping.")
        return True

    client = session.client('iam')

    try:
        role = None
        role = client.get_role(RoleName=ROLENAME)['Role']
        if not role:
            return False
        # print(role)
        if 'PermissionsBoundary' in role:
            print(f"WARNING: Permissions boundary detected: {role['PermissionsBoundary']['PermissionsBoundaryArn']}")
            client.delete_role_permissions_boundary(RoleName=role['RoleName'])

        trustpol = (role['AssumeRolePolicyDocument'])
        # print(json.dumps(trustpol, indent=4))
        trustpolgrantees = trustpol['Statement'][0]['Principal']['AWS']

        # It should be list, if not, make it one
        if not type(trustpolgrantees) is list:
            trustpolgrantees = [trustpolgrantees]

        # Check if we are already on the list
        policy_is_good = False
        for tpg in trustpolgrantees:
            if masteraccount in tpg:
                policy_is_good = True

        if not policy_is_good:
            print(f"NOTICE: Policy missing our master {masteraccount}.  Updating...")
            trustpolgrantees.append(f"arn:aws:iam::{masteraccount}:role/AWSCloudFormationStackSetAdministrationRole")
            trustpol['Statement'][0]['Principal']['AWS'] = trustpolgrantees
            client.update_assume_role_policy(RoleName=role['RoleName'], PolicyDocument=json.dumps(trustpol))

        pols = client.list_role_policies(RoleName=role['RoleName'])['PolicyNames']
        if pols:
            print(f"INFO: Found inline policies: {pols}")

        pols = client.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']
        if pols:
            print(f"INFO: Found attached policies: {pols}")
            policy_is_good = False
            for pol in pols:
                if pol['PolicyArn'] == ADMINPOLICYARN:
                    print("NOTICE: Admin policy already attached!")
                    policy_is_good = True
                else:
                    polv = client.get_policy(PolicyArn=pol['PolicyArn'])['Policy']
                    # print(polv)
                    pold = client.get_policy_version(PolicyArn=pol['PolicyArn'], VersionId=polv['DefaultVersionId'])[
                        'PolicyVersion']['Document']
                    print(f"DEBUG Policy: {pold}")
            if not policy_is_good:
                print(f"NOTICE: Policy missing our admin {ADMINPOLICYARN}.  Updating...")
                client.attach_role_policy(RoleName=role['RoleName'], PolicyArn=ADMINPOLICYARN)
    except Exception as e:
        print(f"ERROR: {e}")
        return False
    return True


def child_accessadvisor(session):
    if not session:
        return False

    client = session.client('accessanalyzer')

    try:
        res = None
        res = client.get_paginator('list_analyzers').paginate().build_full_result()['analyzers']

        if res:
            print(f"INFO: Existing analyzer: {res}")
        else:
            print(f"NOTICE: Creating new analyzer")
            res = client.create_analyzer(analyzerName='AutoCreatedAnalyzer', type='ACCOUNT')
            print(f"DEBUG: {res['arn']}")
    except Exception as e:
        print(f"ERROR: {e}")
        return False
    return True


def child_fixs3public(session):
    if not session:
        return False

    current_account_id = get_aws_account_id(session)

    client = session.client('s3control')
    try:
        res = None
        try:
            res = client.get_public_access_block(AccountId=current_account_id)['PublicAccessBlockConfiguration']
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                print("NOTICE: No config found")
                pass
        if res and (res["BlockPublicAcls"]) and (res["IgnorePublicAcls"]) and (res["BlockPublicPolicy"]) and (
                res["RestrictPublicBuckets"]):
            print("NOTICE: S3 Block okay!")
            return True
        else:
            if res:
                print(f"WARNING: Bad config {res}... Deleting...")
                # return False
            print("NOTICE: Applying new policy")
            client.put_public_access_block(AccountId=current_account_id,
                                           PublicAccessBlockConfiguration={'BlockPublicAcls'      : True,
                                                                           'IgnorePublicAcls'     : True,
                                                                           'BlockPublicPolicy'    : True,
                                                                           'RestrictPublicBuckets': True})
            # exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        return False
    return True


def child_fixSHRules(session):
    if not session:
        return False
    MYSTANDARDARN = 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0'
    MYSETTINGS = {'CIS.1.1' : 'DISABLED', 'CIS.1.4': 'DISABLED', 'CIS.1.14': 'DISABLED', 'CIS.1.16': 'DISABLED',
                  'CIS.1.20': 'DISABLED', 'CIS.2.3': 'DISABLED', 'CIS.2.4': 'DISABLED', 'CIS.2.6': 'DISABLED',
                  'CIS.2.7' : 'DISABLED', 'CIS.3.1': 'DISABLED', 'CIS.3.2': 'DISABLED', 'CIS.3.3': 'DISABLED',
                  'CIS.3.4' : 'DISABLED', 'CIS.3.5': 'DISABLED', 'CIS.3.6': 'DISABLED', 'CIS.3.7': 'DISABLED',
                  'CIS.3.8' : 'DISABLED', 'CIS.3.9': 'DISABLED', 'CIS.3.10': 'DISABLED', 'CIS.3.11': 'DISABLED',
                  'CIS.3.12': 'DISABLED', 'CIS.3.13': 'DISABLED', 'CIS.3.14': 'DISABLED'}

    try:
        client = session.client('securityhub')
        res = client.get_enabled_standards()['StandardsSubscriptions']
        # print(f"DEBUG: Enabled standards: {res}")
        if not res:
            print(f"WARNING: No standards active???")
            return False

        mysub = None
        for s in res:
            if (s['StandardsArn'] == MYSTANDARDARN):
                mysub = s['StandardsSubscriptionArn']
                break

        if not mysub:
            print(f"WARNING: Standard {MYSTANDARDARN} not active!")
            return False
        print(f"INFO: Subscription: {mysub}")
        res = client.describe_standards_controls(StandardsSubscriptionArn=mysub)['Controls']
        # print(f"DEBUG: Enabled controls: {res}")
        for s in res:
            # print(f"DEBUG: Controls: {s}")
            myControl = s['ControlId']
            if (myControl in MYSETTINGS) and (MYSETTINGS[myControl] != s['ControlStatus']):
                print(f"NOTICE: Changing control setting {myControl}")
                client.update_standards_control(StandardsControlArn=s['StandardsControlArn'],
                                                ControlStatus=MYSETTINGS[myControl],
                                                DisabledReason='Disabled by central security script')
    except Exception as e:
        print(f"ERROR: {e}")
        return False

    return True


# Not included by default ---

def child_fixSSM(session):
    if not session:
        return False

    ROLENAME = 'INSTANCE-PROFILE-DEFAULT'
    ROLEDESCR = 'Default Instance Profile Role for EC2 '
    MYPOLICYARN = 'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
    ROLETP = '{ "Version": "2012-10-17", "Statement": [ { "Effect": "Allow", "Principal": { "Service": "ec2.amazonaws.com" }, "Action": "sts:AssumeRole" } ] }'
    # current_account_id = get_aws_account_id(session)
    hadError = False
    client = session.client('iam')
    rolesDone = []

    def sub_ensure_policy_in_role(rolename_sub):
        try:
            if '/' in rolename_sub:
                rolename_sub = rolename_sub.split('/').pop()
            pols = client.list_attached_role_policies(RoleName=rolename_sub)['AttachedPolicies']

            if pols:
                # print(f"DEBUG: Found attached on {rolename_sub} policies: {pols}")
                for pol in pols:
                    if pol['PolicyArn'] == MYPOLICYARN:
                        return True
            print(f"NOTICE: Role {rolename_sub} missing our policy {MYPOLICYARN}.  Updating...")
            client.attach_role_policy(RoleName=rolename_sub, PolicyArn=MYPOLICYARN)
        except Exception as e:
            print(f"ERROR: sub_ensure_policy_in_role {e}")
            return False
        return True

    def sub_ensure_policy_in_instprof(instprof_sub):
        try:
            if not instprof_sub:
                return False

            if '/' in instprof_sub:
                instprof_sub = instprof_sub.split('/').pop()

            response = client.get_instance_profile(InstanceProfileName=instprof_sub)['InstanceProfile']['Roles']
            # print(response)
            if not response:
                print(f"WARNING: {instprof_sub} is NOT mapped to a role!! ")
                return False
            response = response[0]['Arn']
            # print(f"DEBUG: {instprof_sub} maps to {response}")
            return sub_ensure_policy_in_role(response)
        except Exception as e:
            print(f"ERROR: sub_ensure_policy_in_instprof {e}")
            return False

    try:
        role = None
        try:
            role = client.get_role(RoleName=ROLENAME)['Role']
        except:
            pass

        if not role:
            print(f"NOTICE: Creating role {ROLENAME}")
            client.create_role(RoleName=ROLENAME, AssumeRolePolicyDocument=ROLETP, Description=ROLEDESCR)
            time.sleep(5)
            response = client.create_instance_profile(InstanceProfileName=ROLENAME)
            # print(f"DEBUG: Create Instance Profile : {response}")
            time.sleep(5)
            response = client.add_role_to_instance_profile(InstanceProfileName=ROLENAME, RoleName=ROLENAME)
            # print(f"DEBUG: Link Instance Profile : {response}")
            time.sleep(5)
        else:
            if 'PermissionsBoundary' in role:
                print(
                    f"WARNING: Permissions boundary detected: {role['PermissionsBoundary']['PermissionsBoundaryArn']}")
                client.delete_role_permissions_boundary(RoleName=ROLENAME)

        if not sub_ensure_policy_in_role(ROLENAME):
            return False

        client2 = session.client('ec2')

        for inst2 in client2.get_paginator('describe_instances').paginate().build_full_result()['Reservations']:
            for inst3 in inst2['Instances']:
                # print(f"DEBUG: {inst3}")
                myrole = ''
                if 'IamInstanceProfile' in inst3:
                    myrole = inst3['IamInstanceProfile']['Arn']
                print(f"INFO: Instance {inst3['InstanceId']} - {myrole} ")
                if inst3['State']['Name'] not in ['stopped', 'running']:
                    print("WARNING: Skipping because instance in transient state")
                    continue

                if not myrole:
                    print(f"NOTICE: No role found, so attaching {ROLENAME} ")
                    client2.associate_iam_instance_profile(IamInstanceProfile={'Name': ROLENAME, },
                                                           InstanceId=inst3['InstanceId'])
                    continue
                if myrole in rolesDone:
                    continue
                rolesDone.append(myrole)
                if not sub_ensure_policy_in_instprof(myrole):
                    hadError = True
    except Exception as e:
        print(f"ERROR: {e}")
        return False
    return not hadError


def child_setBucketLogging(session):
    if not session:
        return False

    client = session.client('s3')
    try:
        hadError = False
        region_bucket = {}
        buckets_without = {}

        for bucket in client.list_buckets()['Buckets']:
            # print(f"INFO: Bucket: {bucket['Name']}")

            # Try to get a Dataset name
            myDS = ''
            try:
                for tag in client.get_bucket_tagging(Bucket=bucket['Name'])['TagSet']:
                    if tag['Key'].upper() == 'DATASETNAME':
                        myDS = tag['Value']
                        break
            except Exception as e:
                print(f"WARNING: Error getting tags {e}")

            # Decide based on DSN
            if not myDS or myDS.lower() in ['unknown', 'none', 'n/a', 'multiple']:
                print(f"DEBUG: Skipping bogus bucket {bucket['Name']} - DS: {myDS}")
                continue

            mylocation = client.get_bucket_location(Bucket=bucket['Name'])['LocationConstraint']
            if not mylocation:
                print("ERROR: Location not found!!")
                hadError = True
                continue

            # Get the logging configuration if it exists
            mylogging = None
            mylogging = client.get_bucket_logging(Bucket=bucket['Name'])
            if 'LoggingEnabled' in mylogging:
                mylogging = mylogging['LoggingEnabled']['TargetBucket']
            else:
                mylogging = None

            if mylogging:
                if not mylocation in region_bucket:
                    region_bucket[mylocation] = mylogging
                else:
                    if region_bucket[mylocation] != mylogging:
                        print(f"ERROR: Mismatched logging buckets: {region_bucket[mylocation]} vs {mylogging} ")
            else:
                buckets_without[bucket['Name']] = mylocation
        print(f"INFO: Bucket mapping: {region_bucket}")
        if not buckets_without:
            print("NOTICE: No buckets to process!")
            return True

        for bucket, region in buckets_without.items():
            if not region in region_bucket:
                print(f"ERROR: Bucket {bucket} in {region} is not mapped!")
                continue
            else:
                print(f"NOTICE: Setting {bucket} to log to {region_bucket[region]}")
                res = client.put_bucket_logging(Bucket=bucket,
                                                BucketLoggingStatus={'LoggingEnabled': {
                                                    'TargetBucket': region_bucket[region],
                                                    'TargetPrefix': f"{bucket}/"
                                                }})


    except Exception as e:
        print(f"ERROR: {e}")
        return False
    return not hadError


def child_RunInspector(session):
    if not session:
        return False
    result = False
    try:
        client = session.client('inspector')

        for tpl in client.list_assessment_templates()['assessmentTemplateArns']:
            res = client.describe_assessment_templates(assessmentTemplateArns=[tpl])['assessmentTemplates'][0]
            print(f"INFO: Template: {res['name']} ARN:{res['arn']} Runs: {res['assessmentRunCount']}")
            if res['name'] == 'Full':
                result = True
                if res['assessmentRunCount'] < 1:
                    print(f"NOTICE: Starting assessments {res['arn']} ")
                    try:
                        client.start_assessment_run(assessmentRunName='AutomaticRun',
                                                    assessmentTemplateArn=res['arn'])
                    except ClientError as e:
                        print(f"WARNING: Failed to start: {e}")
                        pass
            else:
                if res['name'].startswith('NewEc2ScanTemplate'):
                    print(f"NOTICE: Deleting {res['arn']} ")
                    client.delete_assessment_template(assessmentTemplateArn=res['arn'])

    except Exception as e:
        print(f"ERROR: {e}")
        return False

    return result


# ---- Master accounts ----

def master_gd_enable(session, accountslist):
    print("NOTICE: Activating Master account SecurityHub...")

    curaccount = get_aws_account_id(session)
    gd_client = session.client('guardduty')

    DetectorId = get_gd_detectorid(gd_client)
    if not DetectorId:
        return False

    if not accountslist:
        return False

    memberslist = \
        gd_client.get_paginator('list_members').paginate(DetectorId=DetectorId,
                                                         OnlyAssociated='false').build_full_result()[
            'Members']

    accountsToAdd = accountslist.copy()
    del (accountsToAdd[curaccount])

    accountsToInvite = []
    accountsToConfirm = []

    for member in memberslist:
        # print (member)
        print(f"INFO: Existing member: {member['AccountId']} {member['Email']} {member['RelationshipStatus']}")
        if member['AccountId'] in accountsToAdd:
            del (accountsToAdd[member['AccountId']])

        if member['RelationshipStatus'] == 'Created':
            accountsToInvite.append(member['AccountId'])

        if (member['RelationshipStatus'] == 'Invited'):
            accountsToConfirm.append(member['AccountId'])

    if (accountsToAdd):
        for ac_id, ac_email in accountsToAdd.items():
            print(f"Adding: {ac_id} {ac_email}")
            gd_client.create_members(
                AccountDetails=[{'AccountId': ac_id, 'Email': ac_email}], DetectorId=DetectorId)
        accountsToInvite.extend(accountsToAdd)

    if accountsToInvite:
        print(f"Inviting: {accountsToInvite}")
        gd_client.invite_members(
            AccountIds=list(accountsToInvite),
            DetectorId=DetectorId,
            DisableEmailNotification=True,
            Message='Connect GD to security account')

        # for subAccount in accountslist:
    if accountsToConfirm:
        print(f"NOTICE: GD Accounts to confirm: {accountsToConfirm}")
    return True


def master_sh_enable(session, accountslist):
    print("NOTICE: Activating Master account SecurityHub...")

    if not accountslist:
        return False

    curaccount = get_aws_account_id(session)
    client = session.client('securityhub')

    try:
        client.enable_security_hub()
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceConflictException':
            pass
        else:
            print(f"Error: Unable to enable Security Hub: {e} ")

    memberslist = client.get_paginator('list_members').paginate(OnlyAssociated=False).build_full_result()['Members']

    accountsToAdd = accountslist.copy()
    del (accountsToAdd[curaccount])

    accountsToInvite = []
    accountsToConfirm = []

    for member in memberslist:
        # print (member)
        print(f"INFO: Existing member: {member['AccountId']} {member['Email']} {member['MemberStatus']}")
        if member['AccountId'] in accountsToAdd:
            del (accountsToAdd[member['AccountId']])

        if (member['MemberStatus'] == 'Created'):
            accountsToInvite.append(member['AccountId'])

        if (member['MemberStatus'] == 'Invited'):
            accountsToConfirm.append(member['AccountId'])

    if accountsToAdd:
        for ac_id, ac_email in accountsToAdd.items():
            print(f"Adding: {ac_id} {ac_email}")
            client.create_members(AccountDetails=[{'AccountId': ac_id, 'Email': ac_email}])
        accountsToInvite.extend(accountsToAdd)

    print(f"Inviting: {accountsToInvite}")
    client.invite_members(AccountIds=list(accountsToInvite))

    if accountsToConfirm:
        print(f"NOTICE: SecHub Accounts to confirm: {accountsToConfirm}")
    return True


def master_config_enable(session, accountslist):
    if not accountslist:
        return False

    aggname = None
    curaccount = get_aws_account_id(session)
    client = session.client('config')

    try:
        response = client.describe_configuration_aggregators()['ConfigurationAggregators']
    except ClientError as e:
        print(f"Error: Unable query Config: {e} ")
        return False
    if response:
        aggname = response[0]['ConfigurationAggregatorName']

    if not aggname:
        print(f"ERROR: No aggregator")
        return False

    print(f"INFO: Existing aggregator: {aggname}")

    accountsToAdd = accountslist.copy()
    accountsToAdd.remove(curaccount)

    print(f"DEBUG: {'AccountIds':accountsToAdd, 'AllAwsRegions': True}")
    client.put_configuration_aggregator(
        ConfigurationAggregatorName=aggname,
        AccountAggregationSources=[{'AccountIds':accountsToAdd, 'AllAwsRegions': True}])

    return True


# ---- Aggregator  ----

def child_run_all(session):
    result = True
    # print("NOTICE: GuardDuty ")
    # result = child_gd_acceptinvite(session) and result

    # print("NOTICE: SecurityHub")
    # result = child_sh_acceptinvite(session) and result

    print("NOTICE: Config")
    result = child_config_acceptinvite(session) and result

    # child_stacksetrolefix(session)

    print("NOTICE: Access Advisor")
    result = child_accessadvisor(session) and result

    # print("NOTICE: S3 Public Block")
    # result = child_fixs3public(session) and result

    # print("NOTICE: SSM Profile")
    # result = child_fixSSM(session) and result

    return result

def master_run_all(session, accountslist):
    if not accountslist:
        raise Exception('Missing account list')

    # master_config_enable(session, accountslist)
    # master_gd_enable(session, accountslist)
    # master_sh_enable(session, accountslist)
