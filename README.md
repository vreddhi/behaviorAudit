# behavior-audit

Provides a way to audit behavior information for properties via Open APIs and without manually having to go into the Luna Portal.

## Local Install
* Python 3+
* pip install edgegrid-python
* pip install xlsxwriter
* pip install jsonschema

### Credentials
In order to use this module, you need to:
* Set up your credential files as described in the [authorization](https://developer.akamai.com/introduction/Prov_Creds.html) and [credentials](https://developer.akamai.com/introduction/Conf_Client.html) sections of the Get Started pagegetting started guide on developer.akamai.com (the developer portal).
* Needs Property Manager API Access.  
* The section in your credentials .edgerc file should be called [papi] (by default)

## Functionality
This program provides the following functionality:
* Generates an audit .xlsx file that lists each property and behavior values for the the specified behavior name
* Dynamically tries to fetch the product schema for all possible behavior values


### Sample Usage
Lists each property and behavior details, and outputs to a .xslx file. (Note: Does not look at any behavior references in advanced metadata)

```bash
%  python3 behavior_audit.py audit --behavior <behavior_name> --productId <productId> --contractId <contractId>
%  python3 behavior_audit.py audit --behavior <behavior_name> --productId <productId> --contractId <contractId> --account-key <account_key>
%  python3 behavior_audit.py audit --behavior siteShield --productId prd_SPM --contractId ctr_1-28TBWN --account-key 1-1CES
```

(Note: Unfortunately productId is not part of property or not exposed, so you have to find out the productId is known for the specified contract.)

### Misc 

**Get contract ids:** 

http --auth-type edgegrid -a creds: :"/papi/v1/contracts?accountSwitchKey=<switch_key>"

**Get product ids:**

http --auth-type edgegrid -a creds: :"/papi/v1/products?contractId=<switch_key>&accountSwitchKey=<switch_key>"

**Get behavior names:**

[https://developer.akamai.com/api/core_features/property_manager/vlatest.html#behaviors](https://developer.akamai.com/api/core_features/property_manager/vlatest.html#behaviors)





