# business_ready
## A Python CLI that transforms Cisco CLIs and REST APIs into "Business Ready" Documents

## Getting Started
### Business Ready has two modes of operation:

#### Cisco Command Line Interface (CLI) output transformation using pyATS (Linux required)

#### Cisco REST API output transformation using Python Requests (Windows or Linux friendly)

### Each Business Ready Function provides the user with 5 output files:

#### Comma-separated values (CSV) - Spreadsheets!
#### HyperText Markup Language (HTML) - Webpages!
#### Markdown (tabular) - GitHub Ready Tables!
#### Markdown (markmap) - Mind Maps! 
#### JavaScript Object Notation (JSON) - The Raw payload

### The VS Code Terminal can be used, either with Windows (REST APIs) or WSL Ubuntu (pyATS), to create a Python virtual environment and run Business Ready.

### The following extensions can be used to maximize the user experience:

#### Markmap (MD files)
#### Markdown Preview (MD files)
#### Excel Preview (CSV files)
#### Open in Default Browser (HTML files)

## Installation Guides

### Cisco IOS / NXOS CLI 
#### Linux and pyATS Required
#### The following instructions are based on Windows WSL2 and Ubuntu however any flavour of Linux will work with possibly slightly different commands.

##### Confirm Python 3.9 is installed 

#####
```console

$ python3 -V
Python 3.9.10

```

##### Create and activate a virtual environment

#####
```console

$ sudo apt install python3-venv
$ python3 -m venv demo
$ source demo/bin/activate
(demo)$

```

##### Install pyATS[full]

######
```console

(demo)$ pip install pyats[full]

```

##### Install businessready

######
```console

(demo)$ pip install businessready

```

### Cisco REST APIs - Windows or Linux Compatible

#### Confirm Python 3.9 is installed
##### [Download Python](https://python.org)

#### Create and activate a virtual environment

#####
```console

C:\>python3 -m venv demo
C:\>demo\Scripts\activate
(demo) C:\>

```

#### Install businessready

#####
``` console

(demo) C:\>pip install buisnessready

```

## Usage
### Once businessready is installed it can be used from the Python command-line

### Python CLI
#### Linux
#####
```console

(demo)$ python3 
>>> import businessready

```
#### Windows
#####
```console

(demo) C:\>python3 
>>> import businessready

```
### Cisco CLI

#### Connecting - Business Ready functions that extend pyATS require 4 parameters 
##### hostname
##### username
##### password
##### IP / DNS Address

#### Cisco IOS-XE
##### All - You can run all IOS-XE Learn And Show functions to fully document a device with one command
###### 
``` console

>>> import businessready 
>>> businessready.IOS_all("hostname","username","password","IP / DNS Address")

```
##### Learn All - You can run all IOS-XE Learn functions to fully learn a device with one command
###### 
``` console

>>> import businessready 
>>> businessready.IOS_learn_all("hostname","username","password","IP / DNS Address")

```

##### Show All - You can run all IOS-XE Show functions to fully parse a device with one command
###### 
``` console

>>> import businessready 
>>> businessready.IOS_show_all("hostname","username","password","IP / DNS Address")

```
##### Individual Learn / Show Functions - You can run individual learn or show commands as well if you are looking for something specific 
###### 
``` console

>>> import businessready 
>>> businessready.IOS_learn_{{ function }}("hostname","username","password","IP / DNS Address")
>>> businessready.IOS_show_{{ show command }}("hostname","username","password","IP / DNS Address")

```

#### Cisco NXOS
##### All - You can run all NXOS Learn And Show functions to fully document a device with one command
###### 
``` console

>>> import businessready 
>>> businessready.NXOS_all("hostname","username","password","IP / DNS Address")

```
##### Learn All - You can run all NXOS Learn functions to fully learn a device with one command
###### 
``` console

>>> import businessready 
>>> businessready.NXOS_learn_all("hostname","username","password","IP / DNS Address")

```

##### Show All - You can run all NXOS-XE Show functions to fully parse a device with one command
###### 
``` console

>>> import businessready 
>>> businessready.NXOS_show_all("hostname","username","password","IP / DNS Address")

```
##### Individual Learn / Show Functions - You can run individual learn or show commands as well if you are looking for something specific 
###### 
``` console

>>> import businessready 
>>> businessready.NXOS_learn_{{ function }}("hostname","username","password","IP / DNS Address")
>>> businessready.NXOS_show_{{ show command }}("hostname","username","password","IP / DNS Address")

```

### Cisco Digital Network Architecture Center (DNAC)
#### Connecting - Business Ready functions that extend DNAC REST APIs require 3 parameters 
##### DNAC URL
##### username
##### password
##### IP / DNS Address
#### All - You can run all DNAC REST API functions to fully document a device with one command
###### 
``` console

>>> import businessready 
>>> businessready.DNAC_all("url","username","password")

```
#### Individual REST APIs - You can run individual REST API as well if you are looking for something specific 
##### 
``` console

>>> import businessready 
>>> businessready.DNAC_{{ REST API }}("url","username","password")

```
### Meraki Dashboard
#### Connecting - Business Ready functions that extend Meraki Dashboard REST APIs require 3 parameters 
##### Meraki URL
##### Dashboard Token
#### All - You can run all Meraki REST API functions to fully document a device with one command
###### 
``` console

>>> import businessready 
>>> businessready.Meraki_all("url","Dashboard Token")

```
#### Individual REST APIs - You can run individual REST API as well if you are looking for something specific 
##### 
``` console

>>> import businessready 
>>> businessready.Meraki_{{ REST API }}("url","Dashboard Token")

```

* In Development
### Cisco Identity Services Engine (ISE)
* In Development

## Topology Examples

### If you have more than one device you want to transform Business Ready can handle multiple devices in a variety of ways

### Python Array Source

#### The included python_for_loop_example.py file

#### 
```python

import businessready

device01_info = ["dist-rtr01", "cisco", "cisco", "10.10.20.175"]
device02_info = ["dist-rtr02", "cisco", "cisco", "10.10.20.176"]

device_list = [device01_info, device02_info]

for device in device_list:
    businessready.NXOS_learn_all(*device)

```

### pyATS YAML Testbed Source

#### The included from_testbed_example.py

####

```python

import businessready
import yaml

with open('testbed.yml') as info:
    info_dict = yaml.safe_load(info)

for device in info_dict['devices']:
    if info_dict['devices'][device]['os'] == "iosxe":
        businessready.IOS_learn_all(device,info_dict['devices'][device]['credentials']['default']['username'],info_dict['devices'][device]['credentials']['default']['password'],info_dict['devices'][device]['connections']['cli']['ip'])
    elif info_dict['devices'][device]['os'] == "nxos":
        businessready.NXOS_learn_all(device,info_dict['devices'][device]['credentials']['default']['username'],info_dict['devices'][device]['credentials']['default']['password'],info_dict['devices'][device]['connections']['cli']['ip'])

```

### CSV Source

#### The included from_csv_example.py

####

```python

import businessready
import csv

with open('spreadsheet.csv') as info:
    for line in csv.DictReader(info):
	    info_dict = line
        print(info_dict)
	    if info_dict['os'] == "iosxe":
            businessready.IOS_all(info_dict['hostname'],info_dict['username'],info_dict['password'],info_dict['ip'])
	    elif info_dict['os'] == "nxos":
            businessready.NXOS_all(info_dict['hostname'],info_dict['username'],info_dict['password'],info_dict['ip'])

```

## Function Libary
### IOS-XE
#### All
##### businessready.IOS_all()
##### businessready.IOS_learn_all()
##### businessready.IOS_show_all()
#### Learn
##### businessready.IOS_learn_all()
##### businessready.IOS_learn_acl()
##### businessready.IOS_learn_arp()
##### businessready.IOS_learn_bgp()
##### businessready.IOS_learn_dot1x()
##### businessready.IOS_learn_hsrp()
##### businessready.IOS_learn_interface()
##### businessready.IOS_learn_lldp()
##### businessready.IOS_learn_ntp()
##### businessready.IOS_learn_ospf(ho 
##### businessready.IOS_learn_routing()
##### businessready.IOS_learn_stp()
##### businessready.IOS_learn_vlan()
##### businessready.IOS_learn_vrf()
#### Show
##### businessready.IOS_show_all()
##### businessready.IOS_show_access_lists()
##### businessready.IOS_show_cdp_neighbors()
##### businessready.IOS_show_cdp_neighbors_detail()
##### businessready.IOS_show_environment_all()
##### businessready.IOS_show_etherchannel_summary()
##### businessready.IOS_show_interfaces()
##### businessready.IOS_show_interfaces_status()
##### businessready.IOS_show_interfaces_trunk()
##### businessready.IOS_show_inventory_9000()
##### businessready.IOS_show_ip_arp()
##### businessready.IOS_show_ip_interface_brief()
##### businessready.IOS_show_ip_ospf()
##### businessready.IOS_show_ip_ospf_database()
##### businessready.IOS_show_ip_ospf_interface()
##### businessready.IOS_show_ip_ospf_neighbor()
##### businessready.IOS_show_ip_ospf_neighbor_detail()
##### businessready.IOS_show_ip_route()
##### businessready.IOS_show_license_summary()
##### businessready.IOS_show_mac_address_table()
##### businessready.IOS_show_ntp_associations()
##### businessready.IOS_show_wlan_all()
##### businessready.IOS_show_wlan_client_stats()
##### businessready.IOS_show_wlan_summary()
##### businessready.IOS_show_wireless_profile_summary()
##### businessready.IOS_show_wireless_profile_detailed()
##### businessready.IOS_show_version()
##### businessready.IOS_show_vlan()
##### businessready.IOS_show_vrf()
### NXOS
#### All
##### businessready.NXOS_all()
##### businessready.NXOS_learn_all()
##### businessready.NXOS_show_all()
#### Learn
##### businessready.NXOS_learn_all()
##### businessready.NXOS_learn_acl()
##### businessready.NXOS_learn_arp()
##### businessready.NXOS_learn_bgp()
##### businessready.NXOS_learn_hsrp()
##### businessready.NXOS_learn_interface()
##### businessready.NXOS_learn_ospf()
##### businessready.NXOS_learn_platform()
##### businessready.NXOS_learn_routing()
##### businessready.NXOS_learn_vlan()
##### businessready.NXOS_learn_vrf()
#### Show
##### businessready.NXOS_show_access_lists()
##### businessready.NXOS_show_bgp_process_vrf_all()
##### businessready.NXOS_show_bgp_sessions()
##### businessready.NXOS_show_cdp_neighbors()
##### businessready.NXOS_show_cdp_neighbors_detail()
##### businessready.NXOS_show_environment()
##### businessready.NXOS_show_interface()
##### businessready.NXOS_show_interface_status()
##### businessready.NXOS_show_interface_transceiver()
##### businessready.NXOS_show_inventory()
##### businessready.NXOS_show_ip_arp_vrf()
##### businessready.NXOS_show_ip_interface_brief()
##### businessready.NXOS_show_ip_ospf()
##### businessready.NXOS_show_ip_ospf_interface()
##### businessready.NXOS_show_ip_ospf_neighbors_deta)
##### businessready.NXOS_show_ip_ospf_neighbors_detail_vrf()
##### businessready.NXOS_show_ip_ospf_vrf()
##### businessready.NXOS_show_ip_ospf_interface_vrf()
##### businessready.NXOS_show_ip_route()
##### businessready.NXOS_show_ip_route_vrf()
##### businessready.NXOS_show_mac_address_table()
##### businessready.NXOS_show_port_channel_summary()
##### businessready.NXOS_show_version()
##### businessready.NXOS_show_vlan()
##### businessready.NXOS_show_vrf()
##### businessready.NXOS_show_vrf_all_detail()
##### businessready.NXOS_show_vrf_all_interface()
##### businessready.NXOS_show_vrf_detail()
### DNAC
#### businessready.DNAC_sites()
#### businessready.DNAC_sites()
#### businessready.DNAC_site_health()
#### businessready.DNAC_site_member()
#### businessready.DNAC_vlan()
#### businessready.DNAC_vlan_topology()
#### businessready.DNAC_physical_topology()
#### businessready.DNAC_routing_topology()
#### businessready.DNAC_network_health()
#### businessready.DNAC_device()
#### businessready.DNAC_swim()
#### businessready.DNAC_projects()
#### businessready.DNAC_templates()
#### businessready.DNAC_rf_profiles()
#### businessready.DNAC_assurance_tests()
#### businessready.DNAC_flow_analysis()
### Meraki
#### businessready.Meraki_all()
#### businessready.Meraki_organizations()
#### businessready.Meraki_organization_devices()
#### businessready.Meraki_organization_licenses()
#### businessready.Meraki_organization_adaptive_policies()
#### businessready.Meraki_organization_admins()
#### businessready.Meraki_organization_alert_profiles()
#### businessready.Meraki_organization_branding_policy()
#### businessready.Meraki_organization_clients()