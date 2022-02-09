# ----------------
# Copyright
# ----------------
# Written by John Capobianco, February 2022
# Copyright (c) 2022 John Capobianco

from pathlib import Path
import logging
import requests
from pyats.topology import Testbed, Device
from genie import testbed
from jinja2 import Environment, FileSystemLoader

# ----------------
# Jinja2 Setup and Templates
# ----------------

template_dir = Path(__file__).resolve().parent
env = Environment(loader=FileSystemLoader(template_dir))

# ----------------
# Logging Setup
# ----------------

log = logging.getLogger(__name__)

# ----------------
# Filetype Loop
# ----------------

filetype_loop = ["csv","md","html","md"]

def IOS_learned_acl(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'iosxe',
                    credentials = {
                        'default': {
                            'username': username,
                            'password': password,
                        }
                    },
                    connections = {
                        'cli': {
                            'protocol': 'ssh',
                            'ip': ip,
                            'port': 22,
                            'arguements': {
                                'connection_timeout': 360
                            }
                        }
                    })
        testbed_device.testbed = first_testbed
        new_testbed = testbed.load(first_testbed)
        # ---------------------------------------
        # Loop over devices
        # ---------------------------------------
        for device in new_testbed:
            device.connect()

        # Learn ACL to JSON

            learned_acl = device.learn("acl").info

        # Pass to template 

        if learned_acl is not None:
            IOS_learned_acl_template = env.get_template('IOS_learned_acl.j2')
            loop_counter = 0
        # Render Templates
            print_me = []
            for filetype in filetype_loop:
                parsed_output = IOS_learned_acl_template.render(to_parse_access_list=learned_acl['acls'],filetype_loop=loop_counter)
                print_me.append(parsed_output)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn ACL.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn ACL Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()                        
        return(print_me)
    except Exception as e:
        logging.exception(e)

def IOS_show_ip_interface_brief(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'iosxe',
                    credentials = {
                        'default': {
                            'username': username,
                            'password': password,
                        }
                    },
                    connections = {
                        'cli': {
                            'protocol': 'ssh',
                            'ip': ip,
                            'port': 22,
                            'arguements': {
                                'connection_timeout': 360
                            }
                        }
                    })
        testbed_device.testbed = first_testbed
        new_testbed = testbed.load(first_testbed)
        # ---------------------------------------
        # Loop over devices
        # ---------------------------------------
        for device in new_testbed:
            device.connect()

        # Show IP Interface Brief to JSON

            show_ip_interface_brief = device.parse("show ip interface brief")

        # Pass to template 

        if show_ip_interface_brief is not None:
            IOS_show_ip_interface_brief_template = env.get_template('IOS_show_ip_interface_brief.j2')
            loop_counter = 0
        # Render Templates
            print_me = []
            for filetype in filetype_loop:
                parsed_output = IOS_show_ip_interface_brief_template.render(to_parse_interfaces=show_ip_interface_brief['interface'],filetype_loop=loop_counter)
                print_me.append(parsed_output)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show IP Interface Brief.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show IP Interface Brief Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()                        
        return(print_me)
    except Exception as e:
        logging.exception(e)

def DNAC_Sites(url, token):
    try:
        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Auth-Token': token,
        }
    
        sitesRAW = requests.request("GET", f"{ url }/dna/intent/api/v1/site/", headers=headers)
        print(sitesRAW)
        sitesJSON = sitesRAW.json()

        # Pass to template 

        if sitesJSON is not None:
            sites_template = env.get_template('DNAC_sites.j2')
            loop_counter = 0
        # Render Templates
            print_me = []
            for filetype in filetype_loop:
                parsed_output = sites_template.render(sites = sitesJSON['response'],filetype_loop=loop_counter)
                print_me.append(parsed_output)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"DNAC Sites.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("DNAC Sites Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()                        
        return(print_me)
    except Exception as e:
        logging.exception(e)