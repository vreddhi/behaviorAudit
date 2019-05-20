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


#Recursive function to crawl rules and find origin behavior
def getChildRules(parentRule,propertyName):
    for eachRule in parentRule:
        ruleName = eachRule['name']
        for eachBehavior in eachRule['behaviors']:
            if eachBehavior['name'] == 'origin' :
                #print("Inside recursive function of rule ",ruleName)
                writeOriginInfo(eachBehavior,propertyName)

        if len(eachRule['children']) != 0:
            getChildRules(eachRule['children'],propertyName)


def writeOriginInfo(behavior,propertyName):

    try:
        if propertyName is not None:
            #print ("Property Name is ",propertyName)
            originLine = propertyName + ','

        #Start with default value then update it
        originType = 'Unknown'
        if 'originType' in behavior['options'] is not None:
            originType = behavior['options']['originType']
            if originType == 'CUSTOMER':
                originType = 'Customer'

            if originType == 'NET_STORAGE':
                originType = 'NetStorage'


        originLine += originType + ','


        hostname = 'Undefined'
        forwardHostHeader = 'Undefined'
        cacheKeyHostname = 'Undefined'
        verificationMode = 'N/A'
        originSni = 'N/A'
        customValidCnValuesList = 'N/A'
        originCertsToHonor = 'N/A'
        akamaiCertificateStoreEnabled = 'N/A'
        thirdPartyCertificateStoreEnabled = 'N/A'
        pinCertificateAuthority = 'No'
        pinSpecificCertificates = 'No'
        httpPort = 'Undefined'
        httpsPort = 'N/A'


        if 'hostname' in behavior['options'] is not None:
            #print ("Hostname is ",behavior['options']['hostname'])
            #originLine += behavior['options']['hostname']
            hostname = behavior['options']['hostname']

        if 'forwardHostHeader' in behavior['options'] is not None:
            #print ("Hostname is ",behavior['options']['hostname'])
            #originLine += behavior['options']['hostname']
            forwardHostHeader = behavior['options']['forwardHostHeader']

            if forwardHostHeader == 'REQUEST_HOST_HEADER':
                forwardHostHeader = 'Incoming Host Header'

            elif forwardHostHeader == 'ORIGIN_HOSTNAME':
                forwardHostHeader = 'Origin Hostname'

            elif forwardHostHeader == 'CUSTOM':
                forwardHostHeader = 'Custom Value'


        if 'cacheKeyHostname' in behavior['options'] is not None:
            #print ("Hostname is ",behavior['options']['hostname'])
            #originLine += behavior['options']['hostname']
            cacheKeyHostname = behavior['options']['cacheKeyHostname']

            if cacheKeyHostname == 'REQUEST_HOST_HEADER':
                cacheKeyHostname = 'Incoming Host Header'

            elif cacheKeyHostname == 'ORIGIN_HOSTNAME':
                cacheKeyHostname = 'Origin Hostname'

            elif cacheKeyHostname == 'CUSTOM':
                cacheKeyHostname = 'Custom'

        if 'verificationMode' in behavior['options'] is not None:
            #print ("Hostname is ",behavior['options']['hostname'])
            #originLine += behavior['options']['hostname']
            verificationMode = behavior['options']['verificationMode']

            if verificationMode == 'PLATFORM_SETTINGS':
                verificationMode = 'Use Platform Settings'

            elif verificationMode == 'THIRD_PARTY':
                verificationMode = 'Third Party Settings'

            elif verificationMode == 'CUSTOM':
                verificationMode = 'Choose Your Own (Recommended)'



        if 'originSni' in behavior['options'] is not None:
            #print ("Hostname is ",behavior['options']['hostname'])
            #originLine += behavior['options']['hostname']
            originSni = behavior['options']['originSni']
            if  originSni == 'true':
                originSni = 'Yes'
            else:
                originSni = 'No'


        if 'netStorage' in behavior['options'] is not None :
            netStorage = behavior['options']['netStorage']
            if netStorage is not None:
                if netStorage['downloadDomainName'] is not None :
                    #print ("Netstorage domain is ",netStorage['downloadDomainName'])
                    #originLine += netStorage['downloadDomainName']
                    hostname = netStorage['downloadDomainName']
                    cacheKeyHostname='Origin Hostname'
                    forwardHostHeader='Origin Hostname'
                    httpPort='80'
                    httpsPort='443'
                else:
                    #print ("Hostname Undefined")
                    #originLine += 'Undefined'
                    hostname = 'Undefined'

        if 'customValidCnValues' in behavior['options'] is not None:
            customValidCnValuesList = ''
            for customValidCnValues in behavior['options']['customValidCnValues']:
                #print ("Custom Valid CN Value is ",customValidCnValues)
                customValidCnValuesList += customValidCnValues + ' '
        #originLine += customValidCnValuesList + ','

        if 'originCertsToHonor' in behavior['options'] is not None:
            originCertsToHonor = behavior['options']['originCertsToHonor']

            if originCertsToHonor == 'STANDARD_CERTIFICATE_AUTHORITIES':
                originCertsToHonor = 'Akamai-Managed Certificate Authorities Sets'

            if originCertsToHonor == 'CUSTOM_CERTIFICATE_AUTHORITIES':
                originCertsToHonor = 'Custom Certificate Authority Set'

            if originCertsToHonor == 'CUSTOM_CERTIFICATES':
                originCertsToHonor = 'Specific Certificates (pinning)'

            if originCertsToHonor == 'COMBO':
                originCertsToHonor = 'Satisfies any of the trust options below'


        if 'standardCertificateAuthorities' in behavior['options'] is not None:
            akamaiCertificateStoreEnabled = 'Disabled'
            thirdPartyCertificateStoreEnabled = 'Disabled'

            #for standardCertificateAuthorities in behavior['options']['standardCertificateAuthorities']:
            standardCertificateAuthorities = behavior['options']['standardCertificateAuthorities']

            if 'akamai-permissive' in standardCertificateAuthorities:
                akamaiCertificateStoreEnabled = 'Enabled'

            if 'THIRD_PARTY_AMAZON' in standardCertificateAuthorities:
                thirdPartyCertificateStoreEnabled = 'Enabled'

        if 'customCertificateAuthorities' in behavior['options'] is not None:
            pinAuthorityCount = len(behavior['options']['customCertificateAuthorities'])
            if pinAuthorityCount > 0:
                pinCertificateAuthority = 'Yes'

        if 'customCertificates' in behavior['options'] is not None:
            pinSpecificCount = len(behavior['options']['customCertificates'])
            if pinSpecificCount > 0:
                pinSpecificCertificates = 'Yes'

        if 'httpPort' in behavior['options'] is not None:
            httpPort = str(behavior['options']['httpPort'])

        if 'httpsPort' in behavior['options'] is not None:
            httpsPort = str(behavior['options']['httpsPort'])



            #print ("Origin Certs to honor ",originCertsToHonor)
            #originLine += originCertsToHonor
        #originLine += ','


        originLine += hostname+ ',' + forwardHostHeader + ',' + cacheKeyHostname + ',' + verificationMode + ',' + originSni + ',' + customValidCnValuesList + ',' + originCertsToHonor + ',' + akamaiCertificateStoreEnabled + ',' + thirdPartyCertificateStoreEnabled + ',' + pinCertificateAuthority + ',' + pinSpecificCertificates + ',' + httpPort + ',' + httpsPort + ','

        #originLine += ','

    except KeyError:
            rootLogger.info('Error with behavior being passed to write function')

    with open(os.path.join('output',originAuditCSVFile),'a') as fileHandler:
                    fileHandler.write(originLine)
                    fileHandler.write('\n')



def getOriginInfo(OriginPapiToolsObject,propertyName,version,propertyId,groupId,contractId):
    rootLogger.info('Fetching origin details for property: '+propertyName)
    '''
    print ("====================================================")
    rootLogger.info('Fetching ' + propertyName + ' Origin Info')
    rootLogger.info('Fetching ' + propertyId + ' PropertyId Info')
    rootLogger.info('Fetching ' + groupId + ' groupId Info')
    rootLogger.info('Fetching ' + contractId + ' contractId Info')
    '''

    RulesObject = OriginPapiToolsObject.getPropertyRulesfromPropertyId(session, propertyId, version, contractId, groupId)
    if RulesObject.status_code != 200:
       rootLogger.info('Some problem.. Lets start breaking our head now...')
       exit()
    else:
        #Lets start updating the username and password now
        propertyJson = RulesObject.json()
        try:
            rootLogger.debug('Parsing the rules of: ' + propertyName + ' version: ' + str(version))
            #print('Property Name is ',propertyName)
            #print('Property Version is',str(version))
            defaultBehavior = propertyJson['rules']['behaviors']
            for eachDefaultBehavior in defaultBehavior:
                if eachDefaultBehavior['name'] == 'origin' :
                    #print('Behavior Name is ',eachDefaultBehavior['name'])
                    #print('Default Origin type is ',eachDefaultBehavior['options']['originType'])
                    writeOriginInfo(eachDefaultBehavior,propertyName)
        except KeyError:
            print("Looks like there are no default rules")


        try:
            RulesList = propertyJson['rules']['children']
            for eachRule in RulesList:
                ruleName = eachRule['name']
                for eachBehavior in eachRule['behaviors']:
                    #print ('Child Behavior name is ',eachChildBehavior['name'])
                    if eachBehavior['name'] == 'origin' :
                        #print ('**********Printing Origin Behaviors*****************')
                        #print ('Rule name corresponding to origin behavior ',ruleName)
                        writeOriginInfo(eachBehavior,propertyName)
                        #print ('**********End Origin Info ***********')

                if len(eachRule['children']) != 0:
                    getChildRules(eachRule['children'],propertyName)

        except KeyError:
            print("Looks like there are no rules other than default rule")

if  args.generateAudit:
    originAuditCSVFile = 'origin-audit.csv'
    originAuditXLSXFile = 'origin-audit.xlsx'

    if not os.path.exists('output'):
        os.makedirs('output')
    with open(os.path.join('output',originAuditCSVFile),'w') as fileHandler:
       fileHandler.write('Property Name,Origin Type,Origin Server Hostname,Forward Host Header,Cache Key Hostname,Verification Settings,Use SNI TLS Extension,Match CN/SAN To,Trust,Akamai Certificate Store Enabled,Third Party Certificate Store Enabled,Pin Custom Certificate Authority Set, Pin Specific Certificates, HTTP Port,HTTPS Port\n')

    OriginPapiToolsObject = originpapitools.Originpapitools(access_hostname=access_hostname)
    rootLogger.info('Getting property list....')
    propertyDetailsMap = OriginPapiToolsObject.populateDetailsInMemory(session)
    print('Total number of properties are ',len(propertyDetailsMap))

    for everyPropertyDetail in propertyDetailsMap:
        version = everyPropertyDetail['latestVersion']
        propertyName = everyPropertyDetail['propertyName']
        propertyId = everyPropertyDetail['propertyId']
        groupId = everyPropertyDetail['groupId']
        contractId = everyPropertyDetail['contractId']

        #print("Contract ID is ",contractId)
        #print("propertyName  is ",propertyName)
        if args.property and propertyName == args.property:
            getOriginInfo(OriginPapiToolsObject, propertyName, version, propertyId, groupId, contractId)
            break
        elif args.property:
            #Property argument is present but did not match, go for next iteration
            pass
        else:
            getOriginInfo(OriginPapiToolsObject, propertyName, version, propertyId, groupId, contractId)

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
    os.remove(os.path.join('output', originAuditCSVFile))


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
