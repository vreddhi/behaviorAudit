""" Copyright 2019 Akamai Technologies, Inc. All Rights Reserved.
 Licensed under the Apache License, Property 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

import json

class papi(object):
    def __init__(self, access_hostname, account_switch_key):
        self.access_hostname = access_hostname
        if account_switch_key != '':
            self.account_switch_key = '&accountSwitchKey=' + account_switch_key
        else:
            self.account_switch_key = ''

    headers = {
        "Content-Type": "application/json"
    }

    def getSchema(self, session, productId):
        get_schema_url = 'https://' + self.access_hostname + '/papi/v1/schemas/products/' + str(productId) + '/latest'

        if '?' in get_schema_url:
            get_schema_url = get_schema_url + self.account_switch_key
        else:
            #Replace & with ? if there is no query string in URL and DO NOT override object property account_switch_key
            account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            get_schema_url = get_schema_url + account_switch_key
        schema_response = session.get(get_schema_url)

        return schema_response     


    def createProperty(self, session, contractId, groupId, productId, property_name):
        """
        Function to create property
        """

        newPropertyData = """
        {
            "productId": "%s",
            "propertyName": "%s"
        }
        """ % (productId,property_name)

        create_property_url = 'https://' + self.access_hostname + '/papi/v1/properties?contractId=' + contractId + '&groupId=' + groupId

        if '?' in create_property_url:
            create_property_url = create_property_url + self.account_switch_key
        else:
            #Replace & with ? if there is no query string in URL and DO NOT override object property account_switch_key
            account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            create_property_url = create_property_url + account_switch_key

        create_property_response = session.post(create_property_url, data=newPropertyData,headers=self.headers)
        return create_property_response

    def updatePropertyRules(self, session, contractId, groupId, propertyId, ruletree):
        """
        Function to create property
        """

        update_property_url = 'https://' + self.access_hostname + '/papi/v1/properties/' + propertyId +'/versions/1/rules?contractId=' + contractId + '&groupId=' + groupId + '&validateRules=false'

        if '?' in update_property_url:
            update_property_url = update_property_url + self.account_switch_key
        else:
            #Replace & with ? if there is no query string in URL and DO NOT override object property account_switch_key
            account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            update_property_url = update_property_url + account_switch_key

        update_property_response = session.put(update_property_url, data=ruletree,headers=self.headers)
        return update_property_response

    def createEdgehostnameArray(self, hostname_list, edge_hostname_id):
        """
        Function to create Edgehostname array for existing edgehostnames
        """
        edgehostname_list = []

        for eachHostname in hostname_list:
            edgehostnameDetails = {}
            edgehostnameDetails['cnameType'] = 'EDGE_HOSTNAME'
            edgehostnameDetails['edgeHostnameId'] = edge_hostname_id
            edgehostnameDetails['cnameFrom'] = eachHostname
            edgehostname_list.append(edgehostnameDetails)

        return edgehostname_list

    def checkEdgeHostname(self, session, edge_hostname_id):
        """
        Function to check the validity of edgeHostnameId
        """
        get_edgehostnameid_url = 'https://' + self.access_hostname + "/hapi/v1/edge-hostnames/" + str(edge_hostname_id)

        if '?' in get_edgehostnameid_url:
            get_edgehostnameid_url = get_edgehostnameid_url + self.account_switch_key
        else:
            #Replace & with ? if there is no query string in URL and DO NOT override object property account_switch_key
            account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            get_edgehostnameid_url = get_edgehostnameid_url + account_switch_key

        edgehostname_response = session.get(get_edgehostnameid_url)
        return edgehostname_response



    def updatePropertyHostname(self, session, contractId, groupId, propertyId, edgehostnamedata):
        """
        Function to update property hostnames and edgehostname
        """
        update_prop_hostname_url = 'https://' + self.access_hostname + '/papi/v1/properties/' + propertyId + '/versions/1/hostnames?contractId=' + contractId + '&groupId=' + groupId + '&validateHostnames=true'

        if '?' in update_prop_hostname_url:
            update_prop_hostname_url = update_prop_hostname_url + self.account_switch_key
        else:
            account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            update_prop_hostname_url = update_prop_hostname_url + account_switch_key

        update_prop_hostname_response = session.put(update_prop_hostname_url, data=edgehostnamedata, headers=self.headers)
        return update_prop_hostname_response

    def activateConfiguration(self, session, contractId, groupId, propertyId, version, network, emailList, notes):
        """
        Function to activate a configuration or property
        Parameters
        ----------
        session : <string>
            An EdgeGrid Auth akamai session object
        property_name: <string>
            Property or configuration name
        version : <int>
            version number to be activated
        network : <string>
            network type on which configuration has to be activated on
        emailList : <string>
            List of emailIds separated by comma to be notified
        notes : <string>
            Notes that describes the activation reason
        Returns
        -------
        activationResponse : activationResponse
            (activationResponse) Object with all response details.
        """

        emails = []
        emails.append(emailList)
        emails = json.dumps(emails)
        activationDetails = """
             {
                "propertyVersion": %s,
                "network": "%s",
                "note": "%s",
                "notifyEmails": %s
            } """ % (version,network,notes,emails)

        actUrl  = 'https://' + self.access_hostname + '/papi/v0/properties/'+ propertyId + '/activations/?contractId=' + contractId +'&groupId=' + groupId + '&acknowledgeAllWarnings=true'

        if '?' in actUrl:
            actUrl = actUrl + self.account_switch_key
        else:
            account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            actUrl = actUrl + account_switch_key

        activationResponse = session.post(actUrl, data=activationDetails, headers=self.headers)

        try:
            if activationResponse.status_code == 400 and activationResponse.json()['detail'].find('following activation warnings must be acknowledged'):
                acknowledgeWarnings = []
                for eachWarning in activationResponse.json()['warnings']:
                    #print("WARNING: " + eachWarning['detail'])
                    acknowledgeWarnings.append(eachWarning['messageId'])
                    acknowledgeWarningsJson = json.dumps(acknowledgeWarnings)
                print("\nAutomatically acknowledging the warnings.\n")
                #The details has to be within the three double quote or comment format
                updatedactivationDetails = """
                     {
                        "propertyVersion": %s,
                        "network": "%s",
                        "note": "%s",
                        "notifyEmails": %s,
                        "acknowledgeWarnings": %s
                    } """ % (version,network,notes,emails,acknowledgeWarningsJson)
                print("Please wait while we activate the config for you.. Hold on... \n")
                updatedactivationResponse = session.post(actUrl,data=updatedactivationDetails,headers=self.headers)
                if updatedactivationResponse.status_code == 201:
                    print("Here is the activation link, that can be used to track:\n")
                    print(updatedactivationResponse.json()['activationLink'])
                    return updatedactivationResponse
                else:
                    return updatedactivationResponse
            elif activationResponse.status_code == 422 and activationResponse.json()['detail'].find('version already activated'):
                print("Property version already activated")
                return activationResponse
            elif activationResponse.status_code == 404 and activationResponse.json()['detail'].find('unable to locate'):
                print("The system was unable to locate the requested version of configuration")
            return activationResponse
        except KeyError:
            print("Looks like there is some error in configuration. Unable to activate configuration at this moment\n")
            return activationResponse
