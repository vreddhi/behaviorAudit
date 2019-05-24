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
import shutil
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
        [{"name": "behavior", "help": "Name of behavior to audit"}],
        [])

    actions["list"] = create_sub_command(
        subparsers, "list", "Lists all behaviors",
        [],
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


#behavior_list=[args.behavior]

counter = 0

#Function to intelligently loop any behavior within Akamai property JSON
#Depending on the dataType we decide substitutions
def updateBehaviorValues(behavior, var_name, var_value, file_name):
    global counter
    for eachKey in behavior.keys():
        if isinstance(behavior[eachKey],dict):
            updateBehaviorValues(behavior[eachKey], var_name, var_value, file_name)
        elif isinstance(behavior[eachKey],list):
            var_value_list = var_value.split(',')
            if var_value_list == behavior[eachKey]:
                counter += 1
                print(str(counter) + '. Replacing ' + behavior[eachKey][-1] + ' with : ' + var_name + ' in ' + file_name)
                behavior[eachKey] = "${env." + var_name + "}"
        elif str(behavior[eachKey]) == str(var_value):
            print(var_value)
            counter += 1
            print(str(counter) + '. Replacing ' + str(behavior[eachKey]) + ' with : ' + var_name + ' in ' + file_name)
            behavior[eachKey] = "${env." + var_name + "}"
    return behavior

#Function to recursively parse the rules
def getChildRulesandUpdate(parentRule, var_name, var_value, file_name):
    for eachRule in parentRule:
        for eachbehavior in eachRule['behaviors']:
            if eachbehavior['name'] in behavior_list:
                eachbehavior = updateBehaviorValues(eachbehavior, var_name, var_value, file_name)

        #Check whether we have child rules, where in again behavior might be found
        if len(eachRule['children']) != 0:
            getChildRulesandUpdate(eachRule['children'], var_name, var_value, file_name)
    #Awesome, we are done updating behaviors, lets go back
    return parentRule


#Start from default values
default_value = True
title_line = True

def audit(args):
    access_hostname, session = init_config(args.edgerc, args.section)
    account_switch_key = args.account_key
    behavior =  args.behavior
    papiObject = papiWrapper.papi(access_hostname, account_switch_key)
    schema_response = papiObject.getSchema(session, productId='prd_SPM')
    #print(json.dumps(schema_response.json(), indent=4))
    behavior =  args.behavior

    if schema_response.status_code == 200:
        behavior_properties = schema_response.json()['definitions']['catalog']['behaviors'][behavior]['properties']['options']['properties']

    for each_name in behavior_properties.keys():
        #print(each_name)
        if 'column_name' not in locals():
            column_name = each_name
        else:
            column_name = column_name + ',' + each_name

    print(column_name)


def list(args):
    access_hostname, session = init_config(args.edgerc, args.section)
    account_switch_key = args.account_key

    papiObject = papiWrapper.papi(access_hostname, account_switch_key)
    schema_response = papiObject.getSchema(session, productId='prd_SPM')
    #print(json.dumps(schema_response.json(), indent=4))
    '''with open('/Users/vbhat/Desktop/schema.json','r') as schema_file:
        schema_response = json.load(schema_file)'''
    #if schema_response.status_code == 200:
    behavior_definitions = schema_response.json()['definitions']['behavior']['allOf']
    for each_dict in behavior_definitions:
        if 'properties' in each_dict:
            behavior_properties = each_dict['properties']['name']['enum']
    print(json.dumps(behavior_properties, indent=4))

"""with open(InputFilename, 'r') as inputFile:
    content = csv.reader(inputFile)
    for everyLine in content:
        if title_line:
            try:
                column_number = everyLine.index(args.column_name)
            except ValueError:
                print(args.column_name + ' is not found in the First line of Input CSV file. Please check\n')
                exit()
            title_line = False
            continue
        else:
            var_name = everyLine[0]
            var_value = everyLine[column_number]
            #Loop each file in the templates directory
            for root, dirs, files in os.walk(directory):
                for each_file in files:
                    #print(each_file)
                    input_file = os.path.join(directory, each_file)
                    with open(input_file, mode='r') as FileHandler:
                        file_content = FileHandler.read()
                    jsonContent = json.loads(file_content)
                    if 'rules' in jsonContent:
                        #print('\nThis will not work for main.json\n')
                        pass
                    else:
                        cleanContent = getChildRulesandUpdate([jsonContent],var_name,var_value,each_file)
                        #print(json.dumps(cleanContent[0], indent=4))
                        try:
                            with open(input_file, 'w') as outputFile:
                                outputFile.write(json.dumps(cleanContent[0], indent=4))
                        except FileNotFoundError:
                            print('\n Unable to write output\n')

if counter == 0:
    print('\nNothing was replaced. Check behavior name argument and/or column_name of input csv\n')

# Merge CSV files into XLSX
workbook = Workbook(os.path.join('output',originAuditXLSXFile))
worksheet = workbook.add_worksheet('Origin Audit')
with open(os.path.join('output',originAuditCSVFile), 'rt', encoding='utf8') as f:
    reader = csv.reader(f)
    for r, row in enumerate(reader):
        for c, col in enumerate(row):
            worksheet.write(r, c, col)
workbook.close()

rootLogger.info('Success: File written to output/' + originAuditXLSXFile)
os.remove(os.path.join('output', originAuditCSVFile))"""


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
