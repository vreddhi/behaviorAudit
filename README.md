# behabior-audit

Provides a way to audit behavior information for properties via Open APIs and without manually having to go into the Luna Portal.

## Local Install
* Python 3+
* pip install edgegrid-python
* pip install xlsxwriter

### Credentials
In order to use this module, you need to:
* Set up your credential files as described in the [authorization](https://developer.akamai.com/introduction/Prov_Creds.html) and [credentials](https://developer.akamai.com/introduction/Conf_Client.html) sections of the Get Started pagegetting started guide on developer.akamai.com (the developer portal).
* When working through this process you need to give grants for the Property Manager API.  The section in your configuration file should be called 'papi'.

## Functionality
This program provides the following functionality:
* Generates an audit file that lists each property and behavior details to a .xslx file


### generateAudit
Lists each property and behavior details, and outputs to a .xslx file

(Note: Does not look at any behavior references in advanced metadata)

```bash
%  python3 behavior_audit.py audit --behavior <behavior_name>
```
