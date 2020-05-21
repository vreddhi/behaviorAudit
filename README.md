# behavior-audit

Provides a way to audit behavior information for properties via Open APIs and without manually having to go into the Luna Portal.

## Local Install
* Python 3+
* Create Python virtual environment
  * python3 -m venv
* Activate virtual environment
  * Mac: source venv/bin/activate
  * Windows (cmd): venv\Scripts\activate.bat
  * Windows (PowerShell) venv\Scripts\Activate.ps1
* Install Python dependencies to virtual environment
  * pip install -r requirements.txt

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
%  python3 behavior_audit.py audit --behavior origin --productId prd_SPM --contractId ctr_1-28TBWN --account-key 1-1CES
%  python3 behavior_audit.py audit --behavior siteShield --productId prd_SPM --contractId ctr_1-28TBWN --account-key 1-1CES --includeMissing
```

(Note: Unfortunately productId is not part of property or not exposed, so you have to find out the productId is known for the specified contract.)

```bash
Example: Web Performance Products
Dynamic Site Accelerator = "prd_Site_Accel"
Ion Standard = "prd_Fresca"
Ion Premier = "prd_SPM"
IoT Edge Connect = "prd_IoT"
Web Security Products
Kona Site Defender = "prd_Site_Defender"
Legacy Web Products
Dynamic Site Delivery = "prd_Site_Del"
Rich Media Accelerator = "prd_Rich_Media_Accel"
Web Application Accelerator = "prd_Web_App_Accel"
Terra Alta = "prd_Alta"
Media Products
Object Delivery = "prd_Obj_Delivery"
Download Delivery = "prd_Download_Delivery"
Adaptive Media Delivery = "prd_Adaptive_Media_Delivery"
Legacy Media Products
Object Caching = "prd_Obj_Caching"
Progressive Media Downloads = "prd_Progressive_Media"
HTTP Downloads = "prd_HTTP_Downloads"
```

### Misc

**Get contract ids:**

http --auth-type edgegrid -a creds: :"/papi/v1/contracts?accountSwitchKey=<switch_key>"

**Get product ids:**

http --auth-type edgegrid -a creds: :"/papi/v1/products?contractId=<switch_key>&accountSwitchKey=<switch_key>"

**Get behavior names:**

[https://developer.akamai.com/api/core_features/property_manager/vlatest.html#behaviors](https://developer.akamai.com/api/core_features/property_manager/vlatest.html#behaviors)
