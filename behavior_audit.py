'''
Author: Vreddhi Bhat and Andrew Tsai
Contact: vbhat@akamai.com and aetsai@akamai.com
'''

"""
Copyright 2019 Akamai Technologies, Inc. All Rights Reserved.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""


"""
This code leverages Akamai OPEN API.
In case you need quick explanation contact the initiators.
Initiators: vbhat@akamai.com and aetsai@akamai.com
"""

import argparse
import configparser
import json
import logging
import os
import requests
import sys
from jsonschema import validate
import jsonschema
from akamai.edgegrid import EdgeGridAuth, EdgeRc
import papiWrapper
import csv
from xlsxwriter.workbook import Workbook
PACKAGE_VERSION = "0.1.0"

# Setup logging
if not os.path.exists('logs'):
    os.makedirs('logs')
log_file = os.path.join('logs', 'behavior_audit.log')

# Set the format of logging in console and file separately
log_formatter = logging.Formatter(
    "%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
console_formatter = logging.Formatter("%(message)s")
root_logger = logging.getLogger()

logfile_handler = logging.FileHandler(log_file, mode='w')
logfile_handler.setFormatter(log_formatter)
root_logger.addHandler(logfile_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(console_formatter)
root_logger.addHandler(console_handler)
# Set Log Level to DEBUG, INFO, WARNING, ERROR, CRITICAL
root_logger.setLevel(logging.INFO)


def init_config(edgerc_file, section):
    if not edgerc_file:
        if not os.getenv("AKAMAI_EDGERC"):
            edgerc_file = os.path.join(os.path.expanduser("~"), '.edgerc')
        else:
            edgerc_file = os.getenv("AKAMAI_EDGERC")

    if not os.access(edgerc_file, os.R_OK):
        print("Unable to read edgerc file \"%s\"" % edgerc_file)
        exit(1)

    if not section:
        if not os.getenv("AKAMAI_EDGERC_SECTION"):
            section = "papi"
        else:
            section = os.getenv("AKAMAI_EDGERC_SECTION")

    try:
        edgerc = EdgeRc(edgerc_file)
        base_url = edgerc.get(section, 'host')

        session = requests.Session()
        session.auth = EdgeGridAuth.from_edgerc(edgerc, section)

        return base_url, session
    except configparser.NoSectionError:
        print("Edgerc section \"%s\" not found" % section)
        exit(1)
    except Exception:
        print(
            "Unknown error occurred trying to read edgerc file (%s)" %
            edgerc_file)
        exit(1)


def cli():
    prog = get_prog_name()
    if len(sys.argv) == 1:
        prog += " [command]"

    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument("--edgerc",
                               default=os.path.join(os.path.expanduser("~"), '.edgerc'),
                               help="Location of the credentials file [$AKAMAI_EDGERC]",)

    parent_parser.add_argument("--section",
                               default="papi",
                               help="Section of the credentials file [$AKAMAI_EDGERC_SECTION]")

    parent_parser.add_argument("--debug",
                               action="store_true",
                               help="DEBUG mode to generate additional logs for troubleshooting")

    parent_parser.add_argument("--account-key",
                               default="",
                               help="Account Switch Key")

    parser = argparse.ArgumentParser(
        description='Akamai CLI for Phased Release Cloudlet',
        add_help=False,
        prog=prog)
    parser.add_argument('--version',
                        action='version',
                        version='%(prog)s ' + PACKAGE_VERSION)

    subparsers = parser.add_subparsers(title='Commands', dest="command", metavar="")

    help_parser = subparsers.add_parser(name="help",
                                        help="Show available help",
                                        add_help=False)
    help_parser.add_argument('args',
                             metavar="",
                             nargs=argparse.REMAINDER)

    actions = {}

    audit_parser = subparsers.add_parser(name="audit", parents=[parent_parser],
                                         help="Audit for beahviors in a group/contract")
    audit_parser.add_argument("--contractId", required=True,
                              help="ContractID to be used in API calls")
    audit_parser.add_argument("--productId", required=True,
                              help="productId to be used in API calls")
    audit_parser.add_argument("--behavior",
                              help="Name of behavior to audit")
    audit_parser.add_argument("--version", choices=['production', 'staging', 'latest'],
                              default='production',
                              help="Config version to audit")
    audit_parser.add_argument("--includeMissing",
                              action="store_true",
                              help="Config version to audit")
    audit_parser.set_defaults(func=audit)
    actions["audit"] = audit_parser

    list_parser = subparsers.add_parser(name="list", parents=[parent_parser],
                                        help="Lists all behaviors")
    list_parser.add_argument("--productId", required=True,
                             help="productId to be used in API calls")
    list_parser.set_defaults(func=list)
    actions["list"] = list_parser

    args = parser.parse_args()

    if len(sys.argv) <= 1:
        parser.print_help()
        return 0

    if args.command == "help":
        if len(args.args) > 0:
            if actions[args.args[0]]:
                actions[args.args[0]].print_help()
        else:
            parser.prog = get_prog_name() + " help [command]"
            parser.print_help()
        return 0

    return args.func(args)

product_list = ['']
options_to_be_removed = ['uuid', 'templateUuid', 'locked', 'options']
path = []
title_line_list = []



def criteriaString(rule, parentCriteria):
    if "criteria" not in rule:
        return parentCriteria

    criteria=rule["criteria"]
    satisfy = rule["criteriaMustSatisfy"]

    operator=" <UNKNOWN_OPERATOR> "
    if satisfy == "all":
        operator = " AND "
    if satisfy == "any":
        operator = " OR "

    criteriaStrings = []
    for criterion in criteria:
        criterionName = criterion["name"]
        criterionOptions = criterion["options"]

        criterionMatchOperator = None
        if "matchOperator" in criterionOptions:
            criterionMatchOperator = criterionOptions['matchOperator']

        criterionValue = None

        if "value" in criterionOptions:
            criterionValue = criterionOptions['value']
        elif "values" in criterionOptions:
            criterionValue = str(criterionOptions['values'])
        elif "countryValues" in criterionOptions:
            criterionValue = str(criterionOptions['countryValues'])
        elif "continentValues" in criterionOptions:
            criterionValue = str(criterionOptions['continentValues'])
        elif "regionValues" in criterionOptions:
            criterionValue = str(criterionOptions['regionValues'])

        if criterionName == "matchVariable":
            criterionName = criterionName + ":" + criterionOptions['variableName']
            if "variableExpression" in criterionOptions:
                criterionValue = criterionOptions['variableExpression']
        elif criterionName == "queryStringParameter":
            criterionName = criterionName + ":" + criterionOptions['parameterName']

        if criterionMatchOperator in ["EXISTS", "DOES_NOT_EXIST"]:
            criterionValue = ""

        criteriaStrings.append("%s %s %s" % (criterionName, criterionMatchOperator, criterionValue))


    ruleCriteria = (operator).join(criteriaStrings)
    if parentCriteria and ruleCriteria:
        return "(%s) AND (%s)" % (parentCriteria, ruleCriteria)
    else:
        return parentCriteria or ruleCriteria

# Function to recursively parse the rules
def doAuditBehavior(rules, behavior, propertyName, version, csvFile, parentCriteria=None):
    foundBehaviorCount = 0
    for rule in rules:
        rule_name = rule['name']

        criteria = criteriaString(rule, parentCriteria)

        for eachbehavior in rule['behaviors']:
            if eachbehavior['name'] in behavior:
                #print(json.dumps(eachbehavior, indent=4))
                row = {
                    'Property_Name': propertyName,
                    'Property_Version': str(version),
                    'Rule_name': rule_name,
                    'Rule_criteria': criteria
                }
                for eachTitle in title_line_list:
                    feature = eachbehavior['options']
                    features_location = eachTitle.split('.')
                    for eachSeparator in features_location[0:]:
                        try:
                            feature = feature[eachSeparator]
                        except (KeyError, TypeError) as e:
                            if type(e).__name__ == TypeError:
                                feature = 'SCHEMA MIS-MATCH: Pls check manually'
                            else:
                                feature = ''

                    row[eachTitle]=str(feature)

                csvFile.writerow(row)
                foundBehaviorCount = foundBehaviorCount + 1

        childFoundBehaviorCount = doAuditBehavior(rule['children'], behavior, propertyName, version, csvFile, criteria)
        foundBehaviorCount = foundBehaviorCount + childFoundBehaviorCount
    return foundBehaviorCount


def computeAllBehaviorOptions(schema_response, behaviorData, final_obj):
    if 'type' in behaviorData and behaviorData['type'] == 'object':
        if 'properties' in behaviorData:
            for eachKey in behaviorData['properties'].keys():
                computeAllBehaviorOptions(
                    schema_response, behaviorData['properties'][eachKey], final_obj)
                if '$ref' in behaviorData['properties'][eachKey].keys():
                    features_location = behaviorData['properties'][eachKey]['$ref'].split('/')
                    dict_location = schema_response
                    for eachSeparator in features_location[1:]:
                        dict_location = dict_location[eachSeparator]
                    final_obj[eachKey] = {}
                    computeAllBehaviorOptions(schema_response, dict_location, final_obj[eachKey])
                else:
                    if eachKey not in options_to_be_removed:
                        final_obj[eachKey] = ''
    return final_obj


def walk(d):
    # Function to parse the computed behavior from schema
    global path
    for k, v in d.items():
        if isinstance(v, str) or isinstance(v, int) or isinstance(v, float):
            path.append(k)
            #print("{}={}".format(".".join(path), v))
            title_line_list.append(str("{}={}".format(".".join(path), v)).strip('='))
            path.pop()
        elif v is None:
            path.append(k)
            # do something special
            path.pop()
        elif isinstance(v, dict):
            if len(v.keys()) > 0:
                path.append(k)
                walk(v)
                path.pop()
            else:
                path.append(k)
                #print("{}={}".format(".".join(path), v))
                title_line_list.append(
                    str("{}={}".format(".".join(path), v)).strip('{}').strip('='))
                path.pop()
        else:
            print("###Type {} not recognized: {}.{}={}".format(type(v), ".".join(path), k, v))


def audit(args):
    access_hostname, session = init_config(args.edgerc, args.section)
    account_switch_key = args.account_key
    behavior = args.behavior
    versionType = args.version
    includeMissing = args.includeMissing

    if args.productId:
        productId = args.productId
        # if productId not in product_list:
        #    print('--productId should be one of: ' + str(product_list))
        #    exit(-1)
        # else:
        # valid product
        #    pass
    else:
        print('--productId is mandatory and should be one of ' + str(product_list))
        exit(-1)

    papiObject = papiWrapper.papi(access_hostname, account_switch_key)
    schema_response = papiObject.getSchema(session, productId=productId)

    if schema_response.status_code == 200:
        try:
            behavior_properties = schema_response.json(
            )['definitions']['catalog']['behaviors'][behavior]['properties']['options']['properties']
        except KeyError:
            print(behavior + ' not found in Schema response.')
            exit(-1)
    else:
        print('Unable to get schema for the product: ' + productId)
        exit(-1)

    try:
        behavior_properties = schema_response.json(
        )['definitions']['catalog']['behaviors'][behavior]
        final_obj = {}
        result_behavior = computeAllBehaviorOptions(
            schema_response.json(), behavior_properties, final_obj)
        #print(json.dumps(result_behavior, indent=4))
        walk(result_behavior)
    except KeyError:
        print('Schema for ' + behavior + ' is not found')



    file_name = behavior + '_Audit.csv'
    with open(file_name, "w", newline='') as audit_file:
        fields = ['Property_Name', 'Property_Version', 'Rule_name', 'Rule_criteria']
        fields.extend(title_line_list)
        csvWriter = csv.DictWriter(audit_file, dialect='excel', fieldnames=fields)
        csvWriter.writeheader()

        if args.contractId:
            contractId = args.contractId
        else:
            # Get all the properties of a contract
            contract_response = papiObject.getContracts(session)
            if contract_response.status_code == 200:
                if len(contract_response.json()['contracts']['items']) > 1:
                    print('More than one contracts found. Please use --contractId <contractID>')
                    print('\nAvailable contractIDs are:')
                    counter = 0
                    for eachContract in contract_response.json()['contracts']['items']:
                        counter += 1
                        print(str(counter) + '. ' + eachContract['contractId'])
                    exit(-1)
                else:
                    contractId = contract_response.json()['contracts']['items'][0]['contractId']
            else:
                print('Unable to fetch contracts information')

        # Get all the properties of a contract
        group_response = papiObject.getGroups(session)
        if group_response.status_code != 200:
            print('Unable to fetch list of groups')
            exit(1)
        else:
            groups = {}
            properties = {}
            #print (group_response.json())
            for group in group_response.json()['groups']['items']:
                groupId = group['groupId']
                groupName = group['groupName']
                contractIds = group['contractIds']
                if contractId in contractIds:
                    groups[groupId] = {'name': groupName}


            if len(groups) == 0:
                print('No groups found in contract.')
                exit(-1)
            else:
                totalGroups = len(groups)
                print('Found ' + str(totalGroups) + ' total groups.')
                for currGroupIndex, (groupId, group) in enumerate(groups.items()):
                    print('Processing Group %i/%i: %s: "%s" ' % (currGroupIndex + 1, totalGroups, groupId, group['name']))
                    properties_response = papiObject.getAllProperties(session, contractId, groupId)
                    if properties_response.status_code == 200:
                        properties_response = properties_response.json()
                        properties_in_group = properties_response['properties']['items']
                        print('\tFound %i properties in group %s' % (len(properties_in_group), groupId))

                        for eachProperty in properties_response['properties']['items']:
                            #print (eachProperty)
                            propertyId = eachProperty['propertyId']
                            propertyName = str(eachProperty['propertyName'])
                            propertyVersion = eachProperty[versionType + 'Version']
                            if propertyVersion is not None:
                                print('\t\tProperty %s: v%i' % (propertyName, propertyVersion))
                                properties[propertyId] = {
                                    'name': propertyName,
                                    'version': propertyVersion,
                                    'groupId': groupId
                                }
                            else:
                                print('\t\tProperty %s: (SKIPPING: No %s version found)' % (propertyName, versionType))
            propertyCount = len(properties)
            print('Found %i properties' % (propertyCount))
            for currPropertyIndex, (propertyId, property) in enumerate(properties.items()):
                print ('Processing property %i/%i: %s' % (currPropertyIndex + 1, propertyCount, property['name']))
                rule_tree_response = papiObject.getPropertyRules(
                    session, propertyId, contractId, property['groupId'], property['version'])
                if rule_tree_response.status_code == 200:
                    parentRule = [rule_tree_response.json()['rules']]
                    foundBehaviors = doAuditBehavior(parentRule, behavior, property['name'], property['version'], csvWriter)
                    print ('\tFound %i matching behaviors' % foundBehaviors)
                    if (includeMissing and foundBehaviors == 0):
                        csvWriter.writerow({
                            'Property_Name': property['name'],
                            'Property_Version': property['version'],
                            'Rule_name': 'BEHAVIOR NOT FOUND IN PROPERTY'
                        })
                else:
                    print('Unable to fetch rule tree for: ' +
                          str(eachProperty['propertyName']))

            # Awesome, we are done autiting the behavior
            # Merge CSV files into XLSX
            xlsx_file = file_name.replace('csv', 'xlsx')
            workbook = Workbook(os.path.join(xlsx_file))
            worksheet = workbook.add_worksheet(behavior)
            with open(os.path.join(file_name), 'rt', encoding='utf8') as f:
                reader = csv.reader(f, dialect='excel')
                for r, row in enumerate(reader):
                    for c, col in enumerate(row):
                        worksheet.write(r, c, col)
            workbook.close()

            print('\nSuccess: File written to ' + xlsx_file)
            # os.remove(os.path.join(file_name))


def list(args):
    access_hostname, session = init_config(args.edgerc, args.section)
    account_switch_key = args.account_key

    if args.productId:
        productId = args.productId
        if productId not in product_list:
            print('--productId should be one of: ' + str(product_list))
            exit(-1)
        else:
            # valid product
            pass
    else:
        print('--productId is mandatory and should be one of ' + str(product_list))
        exit(-1)

    papiObject = papiWrapper.papi(access_hostname, account_switch_key)
    schema_response = papiObject.getSchema(session, productId=productId)

    # if schema_response.status_code == 200:
    behavior_definitions = schema_response.json()['definitions']['behavior']['allOf']
    for each_dict in behavior_definitions:
        if 'properties' in each_dict:
            behavior_properties = each_dict['properties']['name']['enum']
    #print(json.dumps(behavior_properties, indent=4))


def get_prog_name():
    prog = os.path.basename(sys.argv[0])
    if os.getenv("AKAMAI_CLI"):
        prog = "akamai behavior-audit-akamai"
    return prog


def get_cache_dir():
    if os.getenv("AKAMAI_CLI_CACHE_DIR"):
        return os.getenv("AKAMAI_CLI_CACHE_DIR")

    return os.curdir


if __name__ == '__main__':
    try:
        status = cli()
        exit(status)
    except KeyboardInterrupt:
        exit(1)
