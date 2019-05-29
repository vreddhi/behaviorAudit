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

"""
This code leverages Akamai OPEN API.
In case you need quick explanation contact the initiators.
Initiators: vbhat@akamai.com and aetsai@akamai.com
"""

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

    parser = argparse.ArgumentParser(
        description='Akamai CLI for Phased Release Cloudlet',
        add_help=False,
        prog=prog)
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s ' +
                PACKAGE_VERSION)

    subparsers = parser.add_subparsers(
        title='Commands', dest="command", metavar="")

    actions = {}

    subparsers.add_parser(
        name="help",
        help="Show available help",
        add_help=False).add_argument(
        'args',
        metavar="",
        nargs=argparse.REMAINDER)

    actions["audit"] = create_sub_command(
        subparsers, "audit", "Audit for beahviors in a group/contract",
        [{"name": "contractId", "help": "ContractID to be used in API calls"},
         {"name": "productId", "help": "productId to be used in API calls"}],
        [{"name": "behavior", "help": "Name of behavior to audit"}])

    actions["list"] = create_sub_command(
        subparsers, "list", "Lists all behaviors",
        [{"name": "productId", "help": "productId to be used in API calls"}],
        [])

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

    return getattr(sys.modules[__name__], args.command.replace("-", "_"))(args)


def create_sub_command(
        subparsers,
        name,
        help,
        optional_arguments=None,
        required_arguments=None):
    action = subparsers.add_parser(name=name, help=help, add_help=False)

    if required_arguments:
        required = action.add_argument_group("required arguments")
        for arg in required_arguments:
            name = arg["name"]
            del arg["name"]
            required.add_argument("--" + name,
                                  required=True,
                                  **arg,
                                  )

    optional = action.add_argument_group("optional arguments")
    if optional_arguments:
        for arg in optional_arguments:
            name = arg["name"]
            del arg["name"]
            optional.add_argument("--" + name,
                                  required=False,
                                  **arg,
                                  )

    optional.add_argument(
        "--edgerc",
        help="Location of the credentials file [$AKAMAI_EDGERC]",
        default=os.path.join(
            os.path.expanduser("~"),
            '.edgerc'))

    optional.add_argument(
        "--section",
        help="Section of the credentials file [$AKAMAI_EDGERC_SECTION]",
        default="papi")

    optional.add_argument(
        "--debug",
        help="DEBUG mode to generate additional logs for troubleshooting",
        action="store_true")

    optional.add_argument(
        "--account-key",
        help="Account Switch Key",
        default="")

    return action

product_list = ['prd_SPM']
options_to_be_removed = ['uuid','templateUuid','locked','options']
path = []
title_line_list = []

#Function to recursively parse the rules
def doAuditBehavior(parentRule, behavior, propertyName, version):
    file_name = behavior + '_Audit.csv'
    for eachRule in parentRule:
        rule_name = eachRule['name']
        for eachbehavior in eachRule['behaviors']:
            if eachbehavior['name'] in behavior:
                #print(json.dumps(eachbehavior, indent=4))
                for eachTitle in title_line_list:
                    if '.' in eachTitle:
                        features_location = eachTitle.split('.')
                        feature = eachbehavior['options']
                        for eachSeparator in features_location[0:]:
                            feature = feature[eachSeparator]
                    else:
                        try:
                            feature = eachbehavior['options'][eachTitle]
                        except KeyError:
                            feature = ''

                    if 'row_value' not in locals():
                        row_value = str(feature)
                    else:
                        row_value = row_value + ',' + str(feature)
                #write the content to file
                row_value = propertyName + ',' + str(version) + ',' + rule_name + ',' + row_value
                with open(file_name,'a') as audit_file:
                    audit_file.write(row_value+'\n')

            else:
                #Behavior did not match
                pass

        #Check whether we have child rules, where in again behavior might be found
        if len(eachRule['children']) != 0:
            doAuditBehavior(eachRule['children'], behavior, propertyName, version)


def computeAllBehaviorOptions(schema_response, behaviorData,final_obj):
    if 'type' in behaviorData and behaviorData['type'] == 'object':
        if 'properties' in behaviorData:
            for eachKey in behaviorData['properties'].keys():
                computeAllBehaviorOptions(schema_response, behaviorData['properties'][eachKey],final_obj)
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
    #Function to parse the computed behavior from schema
    global path
    for k,v in d.items():
      if isinstance(v, str) or isinstance(v, int) or isinstance(v, float):
        path.append(k)
        #print("{}={}".format(".".join(path), v))
        title_line_list.append(str("{}={}".format(".".join(path), v)).strip('='))
        path.pop()
      elif v is None:
        path.append(k)
        ## do something special
        path.pop()
      elif isinstance(v, dict):
          if len(v.keys()) > 0:
              path.append(k)
              walk(v)
              path.pop()
          else:
              path.append(k)
              #print("{}={}".format(".".join(path), v))
              title_line_list.append(str("{}={}".format(".".join(path), v)).strip('{}').strip('='))
              path.pop()
      else:
        print("###Type {} not recognized: {}.{}={}".format(type(v), ".".join(path),k, v))




def audit(args):
    access_hostname, session = init_config(args.edgerc, args.section)
    account_switch_key = args.account_key
    behavior =  args.behavior

    if args.productId:
        productId =  args.productId
        if productId not in product_list:
            print('--productId should be one of: ' + str(product_list))
            exit(-1)
        else:
            #valid product
            pass
    else:
        print('--productId is mandatory and should be one of ' + str(product_list))
        exit(-1)

    with open('/Users/vbhat/Desktop/schema.json','r') as file_reader:
        schema_response = json.load(file_reader)

    try:
        behavior_properties = schema_response['definitions']['catalog']['behaviors'][behavior]
        final_obj = {}
        result_behavior = computeAllBehaviorOptions(schema_response, behavior_properties, final_obj)
        #print(json.dumps(result_behavior, indent=4))
        walk(result_behavior)

        title_line = 'Property_Name, PROD_Version, Rule_name'
        for eachColumn in title_line_list:
            title_line = title_line + ',' + eachColumn

        file_name = behavior + '_Audit.csv'
        with open(file_name,'w') as audit_file:
            audit_file.write(title_line+'\n')

    except KeyError:
        print('Schema for ' + behavior + ' is not found')

    papiObject = papiWrapper.papi(access_hostname, account_switch_key)
    schema_response = papiObject.getSchema(session, productId=productId)

    if schema_response.status_code == 200:
        try:
            behavior_properties = schema_response.json()['definitions']['catalog']['behaviors'][behavior]['properties']['options']['properties']
        except KeyError:
            print(behavior + ' not found in Schema response.')
            exit(-1)
    else:
        print('Unable to get schema for the product')
        exit(-1)


    if args.contractId:
        contractId = args.contractId
    else:
        #Get all the properties of a contract
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

    #Get all the properties of a contract
    group_response = papiObject.getGroups(session)
    if group_response.status_code == 200:
        #Constitute an array of groupIds for the contract
        groupIdList = []
        for everyGroup in group_response.json()['groups']['items']:
            contractIds = everyGroup['contractIds']
            for everycontract in contractIds:
                if everycontract == contractId:
                    groupId = everyGroup['groupId']
                    groupIdList.append(groupId)
        #Dictionary to track properties processed
        track_properties = {}
        if len(groupIdList) != 0:
            #List all the properties in the group
            for groupId in groupIdList:
                properties_response = papiObject.getAllProperties(session, contractId, groupId)
                if properties_response.status_code == 200:
                    for eachProperty in properties_response.json()['properties']['items']:
                        propertyId = eachProperty['propertyId']
                        propertyName = str(eachProperty['propertyName'])
                        print('\nProcessing ' + propertyName)
                        version = eachProperty['productionVersion']
                        if version is not None:
                            #Fetch property rules
                            if propertyId not in track_properties:
                                rule_tree_response = papiObject.getPropertyRules(session, \
                                                                                propertyId, \
                                                                                contractId, \
                                                                                groupId, \
                                                                                version)
                                if rule_tree_response.status_code == 200:
                                    track_properties[propertyId] = True
                                    parentRule = [rule_tree_response.json()['rules']]
                                    doAuditBehavior(parentRule, behavior, propertyName, version)
                                else:
                                    print('Unable to fecth rule tree for: ' + str(eachProperty['propertyName']))
                            else:
                                #Property is already processed
                                print(propertyName +' Property is already processed as part of other group')
                        else:
                            print('No production version found for ' + eachProperty['propertyName'] + '\n')

                else:
                    print('Unable to fetch properties.')
                    exit(-1)

            #Awesome, we are done autiting the behavior
            # Merge CSV files into XLSX
            xlsx_file = file_name.replace('csv','xlsx')
            workbook = Workbook(os.path.join(xlsx_file))
            worksheet = workbook.add_worksheet(behavior)
            with open(os.path.join(file_name), 'rt', encoding='utf8') as f:
                reader = csv.reader(f)
                for r, row in enumerate(reader):
                    for c, col in enumerate(row):
                        worksheet.write(r, c, col)
            workbook.close()

            print('\nSuccess: File written to ' + xlsx_file)
            #os.remove(os.path.join(file_name))

        else:
            print('No groups found in contract.')
            exit(-1)
    else:
        print('Unable to fetch group information')

def list(args):
    access_hostname, session = init_config(args.edgerc, args.section)
    account_switch_key = args.account_key

    if args.productId:
        productId =  args.productId
        if productId not in product_list:
            print('--productId should be one of: ' + str(product_list))
            exit(-1)
        else:
            #valid product
            pass
    else:
        print('--productId is mandatory and should be one of ' + str(product_list))
        exit(-1)

    papiObject = papiWrapper.papi(access_hostname, account_switch_key)
    schema_response = papiObject.getSchema(session, productId=productId)

    #if schema_response.status_code == 200:
    behavior_definitions = schema_response.json()['definitions']['behavior']['allOf']
    for each_dict in behavior_definitions:
        if 'properties' in each_dict:
            behavior_properties = each_dict['properties']['name']['enum']
    print(json.dumps(behavior_properties, indent=4))


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
