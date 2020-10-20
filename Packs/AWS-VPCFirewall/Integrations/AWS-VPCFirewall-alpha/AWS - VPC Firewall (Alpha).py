import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import logging
import boto3
import json
import re
from datetime import datetime, date
from botocore.config import Config
from botocore.parsers import ResponseParserError

import urllib3.util

# Disable insecure warnings
urllib3.disable_warnings()
logging.getLogger('botocore').setLevel(logging.CRITICAL)

"""PARAMETERS"""
AWS_DEFAULT_REGION = demisto.params().get('defaultRegion')
AWS_ROLE_ARN = demisto.params().get('roleArn')
AWS_ROLE_SESSION_NAME = demisto.params().get('roleSessionName')
AWS_ROLE_SESSION_DURATION = demisto.params().get('sessionDuration')
AWS_ROLE_POLICY = None
AWS_ACCESS_KEY_ID = demisto.params().get('access_key')
AWS_SECRET_ACCESS_KEY = demisto.params().get('secret_key')
VERIFY_CERTIFICATE = not demisto.params().get('insecure', True)
proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
config = Config(
    connect_timeout=1,
    retries=dict(
        max_attempts=1
    ),
    proxies=proxies
)


"""HELPER FUNCTIONS"""


# noinspection PyTypeChecker,PyTypeChecker
def aws_session(service='vpcfirewall', region=None, roleArn=None, roleSessionName=None, roleSessionDuration=None,
                rolePolicy=None):
    kwargs = {}
    if roleArn and roleSessionName is not None:
        kwargs.update({
            'RoleArn': roleArn,
            'RoleSessionName': roleSessionName,
        })
    elif AWS_ROLE_ARN and AWS_ROLE_SESSION_NAME is not None:
        kwargs.update({
            'RoleArn': AWS_ROLE_ARN,
            'RoleSessionName': AWS_ROLE_SESSION_NAME,
        })

    if roleSessionDuration is not None:
        kwargs.update({'DurationSeconds': int(roleSessionDuration)})
    elif AWS_ROLE_SESSION_DURATION is not None:
        kwargs.update({'DurationSeconds': int(AWS_ROLE_SESSION_DURATION)})

    if rolePolicy is not None:
        kwargs.update({'Policy': rolePolicy})
    elif AWS_ROLE_POLICY is not None:
        kwargs.update({'Policy': AWS_ROLE_POLICY})
    if kwargs and AWS_ACCESS_KEY_ID is None:

        if AWS_ACCESS_KEY_ID is None:
            sts_client = boto3.client('sts', config=config, verify=VERIFY_CERTIFICATE)
            sts_response = sts_client.assume_role(**kwargs)
            if region is not None:
                client = boto3.client(
                    service_name=service,
                    region_name=region,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=VERIFY_CERTIFICATE,
                    config=config
                )
            else:
                client = boto3.client(
                    service_name=service,
                    region_name=AWS_DEFAULT_REGION,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=VERIFY_CERTIFICATE,
                    config=config
                )
    elif AWS_ACCESS_KEY_ID and AWS_ROLE_ARN:
        sts_client = boto3.client(
            service_name='sts',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            verify=VERIFY_CERTIFICATE,
            config=config
        )
        kwargs.update({
            'RoleArn': AWS_ROLE_ARN,
            'RoleSessionName': AWS_ROLE_SESSION_NAME,
        })
        sts_response = sts_client.assume_role(**kwargs)
        client = boto3.client(
            service_name=service,
            region_name=AWS_DEFAULT_REGION,
            aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
            aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
            aws_session_token=sts_response['Credentials']['SessionToken'],
            verify=VERIFY_CERTIFICATE,
            config=config
        )
    else:
        if region is not None:
            client = boto3.client(
                service_name=service,
                region_name=region,
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                verify=VERIFY_CERTIFICATE,
                config=config
            )
        else:
            client = boto3.client(
                service_name=service,
                region_name=AWS_DEFAULT_REGION,
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                verify=VERIFY_CERTIFICATE,
                config=config
            )

    return client


def parse_filter_field(filter_str):
    filters = []
    regex = re.compile(r'name=([\w\d_:.-]+),values=([ /\w\d@_,.*-]+)', flags=re.I)
    for f in filter_str.split(';'):
        match = regex.match(f)
        if match is None:
            demisto.log('could not parse filter: %s' % (f,))
            continue

        filters.append({
            'Name': match.group(1),
            'Values': match.group(2).split(',')
        })

    return filters


def parse_tag_field(tags_str):
    tags = []
    regex = re.compile(r'key=([\w\d_:.-]+),value=([ /\w\d@_,.*-]+)', flags=re.I)
    for f in tags_str.split(';'):
        match = regex.match(f)
        if match is None:
            demisto.log('could not parse field: %s' % (f,))
            continue

        tags.append({
            'Key': match.group(1),
            'Value': match.group(2)
        })

    return tags


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def parse_resource_ids(resource_id):
    id_list = resource_id.replace(" ", "")
    resourceIds = id_list.split(",")
    return resourceIds


def multi_split(data):
    data = data.replace(" ", "")
    data = data.split(";")
    return data


def parse_date(dt):
    try:
        arr = dt.split("-")
        parsed_date = (datetime(int(arr[0]), int(arr[1]), int(arr[2]))).isoformat()
    except ValueError as e:
        return_error("Date could not be parsed. Please check the date again.\n{error}".format(error=e))
    return parsed_date


"""MAIN FUNCTIONS"""
def create_firewall_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {
        'FirewallName': args.get('FirewallName'),
        'FirewallPolicyArn': args.get('FirewallPolicyArn'),
        'SubnetMappings': json.loads(args.get('SubnetMappings')),
        'VpcId': args.get('VpcId')
    }

    if args.get('DeleteProtection') == 'yes':
        kwargs['DeleteProtection'] = True
    else:
        kwargs['DeleteProtection'] = False

    if args.get('Description') is not None:
        kwargs['Description'] = args.get('Description')

    response = client.create_firewall(**kwargs)
    ec = {'AWS.VPCFirewall.Firewall': response}
    human_readable = tableToMarkdown('AWS VPC Firewall - Firewall Created', response)
    return_outputs(human_readable, ec)


def create_firewall_policy_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {
        'FirewallPolicyName': args.get('FirewallPolicyName')
    }

    try:
        kwargs['FirewallPolicy'] = json.loads(args.get('FirewallPolicy'))
    except Exception as e:
        return_error("Error encountered when parsing FirewallPolicy. Expected JSON FirewallPolicy object")

    if args.get('Description') is not None:
        kwargs['Description'] = args.get('Description')

    response = client.create_firewall_policy(**kwargs)

    data = json.loads(json.dumps(response))

    ec = {'AWS.VPCFirewall.FirewallPolicy': data}
    human_readable = tableToMarkdown('AWS VPC Firewall - Firewall Policy Created', data)
    return_outputs(human_readable, ec)


def create_rule_group_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    try:
        rule_group = json.loads(args.get('RuleGroup'))
    except Exception as e:
        return_error("Error encountered when parsing RuleGroup. Expected JSON RuleGroup object")

    kwargs = {
        'Capacity': int(args.get('Capacity')),
        'RuleGroup': rule_group,
        'RuleGroupName': args.get('RuleGroupName'),
        'Type': args.get('Type')
    }


    if args.get('Description') is not None:
        kwargs['Description'] = args.get('Description')

    response = client.create_rule_group(**kwargs)
    data = response['RuleGroupResponse']
    data['UpdateToken'] = response['UpdateToken']

    ec = {'AWS.VPCFirewall.RuleGroup': data}
    human_readable = tableToMarkdown('AWS VPC Firewall - Rule Group Creation', data)
    return_outputs(human_readable, ec)


def describe_firewall_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {}
    if args.get('FirewallArn') is not None:
        kwargs.update({'FirewallArn': args.get('FirewallArn')})
    elif args.get('FirewallName') is not None:
        kwargs.update({'FirewallName': args.get('FirewallName')})
    else:
        return_error("Invalid request . You must specify the FirewallArn or FirewallName.")

    response = client.describe_firewall(**kwargs)

    if 'Firewall' in response and 'FirewallStatus' in response and 'UpdateToken' in response:
        data = {
            'Firewall': response['Firewall'],
            'FirewallStatus': response['FirewallStatus'],
            'UpdateToken': response['UpdateToken']
        }
    else:
        data = response

    ec = {'AWS.VPCFirewall.Firewall': data}
    human_readable = tableToMarkdown('AWS VPC Firewall - Firewall', data)
    return_outputs(human_readable, ec)


def describe_firewall_policy_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {}
    if args.get('FirewallPolicyArn') is not None:
        kwargs.update({'FirewallPolicyArn': args.get('FirewallPolicyArn')})
    elif args.get('FirewallPolicyName') is not None:
        kwargs.update({'FirewallPolicyName': args.get('FirewallPolicyName')})
    else:
        return_error("Invalid request . You must specify the FirewallPolicyArn or FirewallPolicyName.")

    response = client.describe_firewall_policy(**kwargs)

    if 'FirewallPolicy' in response and 'FirewallPolicyResponse' in response and 'UpdateToken' in response:
        data = {
            'FirewallPolicy': response['FirewallPolicy'],
            'FirewallPolicyResponse': response['FirewallPolicyResponse'],
            'UpdateToken': response['UpdateToken'],
        }
    else:
        data = response

    ec = {'AWS.VPCFirewall.FirewallPolicy': data}
    human_readable = tableToMarkdown('AWS VPC Firewall - Firewall Policy', data)
    return_outputs(human_readable, ec)


def describe_rule_group_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {}
    if args.get('RuleGroupArn') is not None:
        kwargs.update({'RuleGroupArn': args.get('RuleGroupArn')})
    elif args.get('RuleGroupName') is not None and args.get('Type') is not None:
        kwargs.update({'RuleGroupName': args.get('RuleGroupName')})
        kwargs.update({'Type': args.get('Type')})
    else:
        return_error("Invalid request . You must specify the RuleGroupArn or RuleGroupName (and Type).")

    response = client.describe_rule_group(**kwargs)

    if 'RuleGroup' in response and 'RuleGroupResponse' in response and 'UpdateToken' in response:
        data = [{
            'RuleGroup': response['RuleGroup'],
            'RuleGroupResponse': response['RuleGroupResponse'],
            'UpdateToken': response['UpdateToken'],
        }]
    else:
        data = response

    ec = {'AWS.VPCFirewall.RuleGroup': data}
    human_readable = tableToMarkdown('AWS VPC Firewall - RuleGroup', data)
    return_outputs(human_readable, ec)


def list_firewalls_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {
        'MaxResults': int(args.get('MaxResults'))
    }

    if args.get('VpcIds') is not None:
        kwargs.update({'VpcIds': args.get('VpcIds')})

    data = []
    response = client.list_firewalls(**kwargs)

    for firewall in response["Firewalls"]:
        data.append(firewall)

    ec = {'AWS.VPCFirewall.Firewalls(val.FirewallArn === obj.FirewallArn)': data}
    human_readable = tableToMarkdown('AWS VPC Firewall - Firewalls', data)
    return_outputs(human_readable, ec)


def list_firewall_policies_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {
        'MaxResults': int(args.get('MaxResults'))
    }

    data = []
    response = client.list_firewall_policies(**kwargs)

    for fw_policy in response["FirewallPolicies"]:
        data.append(fw_policy)

    ec = {'AWS.VPCFirewall.FirewallPolicies(val.Arn === obj.Arn)': data}
    human_readable = tableToMarkdown('AWS VPC Firewall - Firewall Policies', data)
    return_outputs(human_readable, ec)


def list_rule_groups_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {
        'MaxResults': int(args.get('MaxResults'))
    }

    data = []
    response = client.list_rule_groups(**kwargs)

    for rulegroup in response["RuleGroups"]:
        data.append(rulegroup)

    ec = {'AWS.VPCFirewall.RuleGroups(val.Arn === obj.Arn)': data}
    human_readable = tableToMarkdown('AWS VPC Firewall - Rule Groups', data)
    return_outputs(human_readable, ec)


def update_firewall_policy_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {}

    if args.get('FirewallPolicyName') is not None:
            kwargs['FirewallPolicyName'] = args.get('FirewallPolicyName')
    elif args.get('FirewallPolicyArn') is not None:
        kwargs['FirewallPolicyArn'] = args.get('FirewallPolicyArn')
    else:
        return_error("You must specify the FirewallPolicyArn or the FirewallPolicyName, and you can specify both.")

    # Get update token
    current_policy = client.describe_firewall_policy(**kwargs)
    update_token = current_policy['UpdateToken']
    kwargs['UpdateToken'] = update_token

    try:
        kwargs['FirewallPolicy'] = json.loads(args.get('FirewallPolicy'))
    except Exception as e:
        return_error("Error encountered when parsing FirewallPolicy. Expected JSON FirewallPolicy object")

    if args.get('Description') is not None:
        kwargs['Description'] = args.get('Description')

    response = client.update_firewall_policy(**kwargs)

    ec = {'AWS.VPCFirewall.FirewallPolicy': response}
    human_readable = tableToMarkdown('AWS VPC Firewall - Firewall Policy Updated', response)
    return_outputs(human_readable, ec)


def update_rule_group_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {}

    if args.get('RuleGroupName') is not None:
        kwargs['RuleGroupName'] = args.get('RuleGroupName')
    elif args.get('RuleGroupArn') is not None:
        kwargs['RuleGroupArn'] = args.get('RuleGroupArn')
    else:
        return_error("You must specify the RuleGroupArn or the RuleGroupName, and you can specify both.")

    # Get update token
    current_rule_group = client.describe_rule_group(**kwargs)
    kwargs['UpdateToken'] = current_rule_group['UpdateToken']

    if 'RuleGroupArn' not in kwargs:
        kwargs['Type'] = current_rule_group['RuleGroupResponse']['Type']

    try:
        kwargs['RuleGroup'] = json.loads(args.get('RuleGroup'))
    except Exception as e:
        return_error("Error encountered when parsing RuleGroup. Expected JSON RuleGroup object")

    if args.get('Description') is not None:
        kwargs['Description'] = args.get('Description')

    response = client.update_rule_group(**kwargs)
    data = response['RuleGroupResponse']
    data['UpdateToken'] = response['UpdateToken']

    ec = {'AWS.VPCFirewall.RuleGroup': data}
    human_readable = tableToMarkdown('AWS VPC Firewall - Rule Group Updated', data)
    return_outputs(human_readable, ec)


def delete_firewall_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {}

    if args.get('FirewallName') is not None:
        kwargs['FirewallName'] = args.get('FirewallName')
    elif args.get('FirewallArn') is not None:
        kwargs['FirewallArn'] = args.get('FirewallArn')
    else:
        return_error("You must specify the FirewallArn or the FirewallName, and you can specify both.")

    response = client.delete_firewall(**kwargs)
    human_readable = tableToMarkdown('AWS VPC Firewall - Firewall Deletion', response)
    return_outputs(human_readable)


def delete_firewall_policy_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {}

    if args.get('FirewallPolicyName') is not None:
        kwargs['FirewallPolicyName'] = args.get('FirewallPolicyName')
    elif args.get('FirewallPolicyArn') is not None:
        kwargs['FirewallPolicyArn'] = args.get('FirewallPolicyArn')
    else:
        return_error("You must specify the FirewallPolicyArn or the FirewallPolicyName, and you can specify both.")

    response = client.delete_firewall_policy(**kwargs)
    data = response['FirewallPolicyResponse']

    human_readable = tableToMarkdown('AWS VPC Firewall - Firewall Policy Deletion', data)
    return_outputs(human_readable)


def delete_rule_group_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {
        'Type': args.get('Type')
    }

    if args.get('RuleGroupName') is not None:
        kwargs['RuleGroupName'] = args.get('RuleGroupName')
    elif args.get('RuleGroupArn') is not None:
        kwargs['RuleGroupArn'] = args.get('RuleGroupArn')
    else:
        return_error("You must specify the RuleGroupArn or the RuleGroupName, and you can specify both.")

    response = client.delete_rule_group(**kwargs)
    data = response['RuleGroupResponse']

    human_readable = tableToMarkdown('AWS VPC Firewall - Rule Group Deletion', data)
    return_outputs(human_readable)




"""COMMAND BLOCK"""
try:
    LOG('Command being called is {command}'.format(command=demisto.command()))
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        client = aws_session()
        response = client.list_firewalls(MaxResults=6)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            demisto.results('ok')

    elif demisto.command() == 'aws-vpcfirewall-create-firewall':
        create_firewall_command(demisto.args())
    elif demisto.command() == 'aws-vpcfirewall-create-firewall-policy':
        create_firewall_policy_command(demisto.args())
    elif demisto.command() == 'aws-vpcfirewall-create-rule-group':
        create_rule_group_command(demisto.args())
    elif demisto.command() == 'aws-vpcfirewall-describe-firewall':
        describe_firewall_command(demisto.args())
    elif demisto.command() == 'aws-vpcfirewall-describe-firewall-policy':
        describe_firewall_policy_command(demisto.args())
    elif demisto.command() == 'aws-vpcfirewall-describe-rule-group':
        describe_rule_group_command(demisto.args())
    elif demisto.command() == 'aws-vpcfirewall-list-firewalls':
        list_firewalls_command(demisto.args())
    elif demisto.command() == 'aws-vpcfirewall-list-firewall-policies':
        list_firewall_policies_command(demisto.args())
    elif demisto.command() == 'aws-vpcfirewall-list-rule-groups':
        list_rule_groups_command(demisto.args())
    elif demisto.command() == 'aws-vpcfirewall-update-firewall-policy':
        update_firewall_policy_command(demisto.args())
    elif demisto.command() == 'aws-vpcfirewall-update-rule-group':
        update_rule_group_command(demisto.args())
    elif demisto.command() == 'aws-vpcfirewall-delete-firewall':
        delete_firewall_command(demisto.args())
    elif demisto.command() == 'aws-vpcfirewall-delete-firewall-policy':
        delete_firewall_policy_command(demisto.args())
    elif demisto.command() == 'aws-vpcfirewall-delete-rule-group':
        delete_rule_group_command(demisto.args())



except ResponseParserError as e:
    return_error('Could not connect to the AWS endpoint. Please check that the region is valid.\n {error}'.format(
        error=e))
    LOG(e.message)

except Exception as e:
    LOG(str(e))
    return_error('Error has occurred in the AWS VPC Firewall Integration: {code}\n {message}'.format(
        code=type(e), message=str(e)))
