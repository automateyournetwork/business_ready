# ----------------
# Copyright
# ----------------
# Written by John Capobianco, February 2022
# Copyright (c) 2022 John Capobianco

from pathlib import Path
import os
import logging
import requests
import json
import base64
import xmltodict
import urllib3
from pyats.topology import Testbed, Device
from genie import testbed
from jinja2 import Environment, FileSystemLoader

urllib3.disable_warnings()
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

# -------------------------
# DNA-C REST APIs
# -------------------------

# ----------------
# DNAC ALL
# ----------------

def DNAC_all(url, username, password):
    DNAC_sites(url, username, password)
    DNAC_site_health(url, username, password)
    DNAC_site_member(url, username, password)
    DNAC_vlan(url, username, password)
    DNAC_vlan_topology(url, username, password)
    DNAC_physical_topology(url, username, password)
    DNAC_routing_topology(url, username, password)
    DNAC_network_health(url, username, password)
    DNAC_device(url, username, password)
    DNAC_swim(url, username, password)
    DNAC_projects(url, username, password)
    DNAC_templates(url, username, password)
    DNAC_rf_profiles(url, username, password)
    DNAC_assurance_tests(url, username, password)
    DNAC_flow_analysis(url, username, password)
    return("All DNA-C APIs Converted to Business Ready Documents")

def DNAC_sites(url, username, password):
    try:
        # -------------------------
        # Headers
        # -------------------------
        encodedCredentials=base64.b64encode(bytes(f'{ username}:{ password}', 'utf-8')).decode()
        
        auth_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic { encodedCredentials }'
            }

        dnac = "https://sandboxdnac.cisco.com"

        # -------------------------
        # Get OAuth Token
        # -------------------------

        oAuthTokenRAW = requests.request("POST", f"{ dnac }/dna/system/api/v1/auth/token", headers=auth_headers)
        oAuthTokenJSON = oAuthTokenRAW.json()
        token = oAuthTokenJSON['Token']

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Auth-Token': token,
        }
    
        sitesRAW = requests.request("GET", f"{ url }/dna/intent/api/v1/site/", headers=headers)
        sitesJSON = sitesRAW.json()

        # Pass to template 

        if sitesJSON is not None:
            sites_template = env.get_template('DNAC_sites.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = sites_template.render(sites = sitesJSON['response'],filetype_loop=loop_counter)
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
                with open(f"DNAC Sites.json", "w") as fh:
                    json.dump(sitesJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(sitesJSON)
    except Exception as e:
        logging.exception(e)

def DNAC_site_health(url, username, password):
    try:
        # -------------------------
        # Headers
        # -------------------------
        encodedCredentials=base64.b64encode(bytes(f'{ username}:{ password}', 'utf-8')).decode()
        
        auth_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic { encodedCredentials }'
            }

        dnac = "https://sandboxdnac.cisco.com"

        # -------------------------
        # Get OAuth Token
        # -------------------------

        oAuthTokenRAW = requests.request("POST", f"{ dnac }/dna/system/api/v1/auth/token", headers=auth_headers)
        oAuthTokenJSON = oAuthTokenRAW.json()
        token = oAuthTokenJSON['Token']

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Auth-Token': token,
        }
    
        sitesHealthRAW = requests.request("GET", f"{ url }/dna/intent/api/v1/site-health/", headers=headers)
        sitesHealthJSON = sitesHealthRAW.json()

        # Pass to template 

        if sitesHealthRAW is not None:
            site_health_template = env.get_template('DNAC_site_health.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = site_health_template.render(siteHealth = sitesHealthJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"DNAC Site Health.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("DNAC Site Health Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"DNAC Site Health.json", "w") as fh:
                    json.dump(sitesHealthJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(sitesHealthJSON)
    except Exception as e:
        logging.exception(e)

def DNAC_site_member(url, username, password):
    try:
        # -------------------------
        # Headers
        # -------------------------
        encodedCredentials=base64.b64encode(bytes(f'{ username}:{ password}', 'utf-8')).decode()
        
        auth_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic { encodedCredentials }'
            }

        dnac = "https://sandboxdnac.cisco.com"

        # -------------------------
        # Get OAuth Token
        # -------------------------

        oAuthTokenRAW = requests.request("POST", f"{ dnac }/dna/system/api/v1/auth/token", headers=auth_headers)
        oAuthTokenJSON = oAuthTokenRAW.json()
        token = oAuthTokenJSON['Token']

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Auth-Token': token,
        }
    
        sitesRAW = requests.request("GET", f"{ url }/dna/intent/api/v1/site/", headers=headers)
        sitesJSON = sitesRAW.json()

        # Pass to template 

        if sitesJSON is not None:
            loop_counter = 0
            for site in sitesJSON['response']:
                sitesMembersRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/membership/{ site['id'] }", headers=headers)
                sitesMembersJSON = sitesMembersRAW.json()

                if sitesMembersJSON is not None:
                    site_member_template = env.get_template('DNAC_site_member.j2')
                # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = site_member_template.render(site = site['name'],siteMembers = sitesMembersJSON['device'],filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"DNAC Site { site['name'] } Member.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                        else:
                            with open(f"DNAC Site { site['name'] } Member Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                                loop_counter = 0
                        with open(f"DNAC Site { site['name'] } Member.json", "w") as fh:
                            json.dump(sitesMembersJSON, fh, indent=4, sort_keys=True)
                            fh.close()
                        
        return(sitesMembersJSON)
    except Exception as e:
        logging.exception(e)

def DNAC_vlan(url, username, password):
    try:
        # -------------------------
        # Headers
        # -------------------------
        encodedCredentials=base64.b64encode(bytes(f'{ username}:{ password}', 'utf-8')).decode()
        
        auth_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic { encodedCredentials }'
            }

        dnac = "https://sandboxdnac.cisco.com"

        # -------------------------
        # Get OAuth Token
        # -------------------------

        oAuthTokenRAW = requests.request("POST", f"{ dnac }/dna/system/api/v1/auth/token", headers=auth_headers)
        oAuthTokenJSON = oAuthTokenRAW.json()
        token = oAuthTokenJSON['Token']

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Auth-Token': token,
        }
    
        vlansRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/topology/vlan/vlan-names", headers=headers)
        vlansJSON = vlansRAW.json()

        # Pass to template 

        if vlansJSON is not None:
            vlans_template = env.get_template('DNAC_vlans.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = vlans_template.render(vlans = vlansJSON['response'],DNAC=url,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"DNAC VLANs.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()                       
                else:
                    with open("DNAC VLANs Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"DNAC VLANs.json", "w") as fh:
                    json.dump(vlansJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(vlansJSON)
    except Exception as e:
        logging.exception(e)

def DNAC_vlan_topology(url, username, password):
    try:
        # -------------------------
        # Headers
        # -------------------------
        encodedCredentials=base64.b64encode(bytes(f'{ username}:{ password}', 'utf-8')).decode()
        
        auth_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic { encodedCredentials }'
            }

        dnac = "https://sandboxdnac.cisco.com"

        # -------------------------
        # Get OAuth Token
        # -------------------------

        oAuthTokenRAW = requests.request("POST", f"{ dnac }/dna/system/api/v1/auth/token", headers=auth_headers)
        oAuthTokenJSON = oAuthTokenRAW.json()
        token = oAuthTokenJSON['Token']

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Auth-Token': token,
        }
    
        vlansRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/topology/vlan/vlan-names", headers=headers)
        vlansJSON = vlansRAW.json()

        # Pass to template 

        if vlansJSON is not None:
            loop_counter = 0
            for vlan in vlansJSON['response']:
                vlanTopologyRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/topology/l2/{ vlan }", headers=headers)
                vlanTopologyJSON = vlanTopologyRAW.json()

                if vlanTopologyJSON is not None:
                    vlanToplogy_template = env.get_template('DNAC_vlan_topology.j2')
                # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = vlanToplogy_template.render(vlan = vlan,vlanTopology = vlanTopologyJSON['response'],filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"DNAC { vlan } Topology.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()                             
                        else:
                            with open(f"DNAC { vlan } Topology Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                                loop_counter = 0
                        with open(f"DNAC { vlan } Topology.json", "w") as fh:
                            json.dump(vlanTopologyJSON, fh, indent=4, sort_keys=True)
                            fh.close()
        return(vlanTopologyJSON)
    except Exception as e:
        logging.exception(e)

def DNAC_physical_topology(url, username, password):
    try:
        # -------------------------
        # Headers
        # -------------------------
        encodedCredentials=base64.b64encode(bytes(f'{ username}:{ password}', 'utf-8')).decode()
        
        auth_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic { encodedCredentials }'
            }

        dnac = "https://sandboxdnac.cisco.com"

        # -------------------------
        # Get OAuth Token
        # -------------------------

        oAuthTokenRAW = requests.request("POST", f"{ dnac }/dna/system/api/v1/auth/token", headers=auth_headers)
        oAuthTokenJSON = oAuthTokenRAW.json()
        token = oAuthTokenJSON['Token']

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Auth-Token': token,
        }
    
        physicalRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/topology/physical-topology", headers=headers)
        physicalJSON = physicalRAW.json()

        # Pass to template 

        if physicalJSON is not None:
            physical_template = physical_template = env.get_template('DNAC_physical_topology.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = physical_template.render(physicalTopology = physicalJSON['response'],DNAC=url,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"DNAC Physical Topology.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()                       
                else:
                    with open("DNAC Physical Topology Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"DNAC Physical Topology.json", "w") as fh:
                    json.dump(physicalJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(physicalJSON)
    except Exception as e:
        logging.exception(e)

def DNAC_routing_topology(url, username, password):
    try:
        # -------------------------
        # Headers
        # -------------------------
        encodedCredentials=base64.b64encode(bytes(f'{ username}:{ password}', 'utf-8')).decode()
        
        auth_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic { encodedCredentials }'
            }

        dnac = "https://sandboxdnac.cisco.com"

        # -------------------------
        # Get OAuth Token
        # -------------------------

        oAuthTokenRAW = requests.request("POST", f"{ dnac }/dna/system/api/v1/auth/token", headers=auth_headers)
        oAuthTokenJSON = oAuthTokenRAW.json()
        token = oAuthTokenJSON['Token']

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Auth-Token': token,
        }
    
        protocols = ['ospf','eigrp','isis','static']
        all_protocols = []
        for protocol in protocols:    
            routingTopologyRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/topology/l3/{ protocol }", headers=headers)
            routingTopologyJSON = routingTopologyRAW.json()
            all_protocols.append(routingTopologyJSON)

        # Pass to template 

            if routingTopologyJSON is not None:
                routingToplogy_template = env.get_template('DNAC_routing_topology.j2')
                loop_counter = 0
        # Render Templates
                for filetype in filetype_loop:
                    parsed_output = routingToplogy_template.render(protocol = protocol,routingTopology = routingTopologyJSON['response'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                    if loop_counter <= 3:
                        with open(f"DNAC { protocol } Topology.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    else:
                        with open(f"DNAC { protocol } Topology Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"DNAC { protocol } Topology.json", "w") as fh:
                        json.dump(routingTopologyJSON, fh, indent=4, sort_keys=True)
                        fh.close()                            
        return(all_protocols)
    except Exception as e:
        logging.exception(e)

def DNAC_network_health(url, username, password):
    try:
        # -------------------------
        # Headers
        # -------------------------
        encodedCredentials=base64.b64encode(bytes(f'{ username}:{ password}', 'utf-8')).decode()
        
        auth_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic { encodedCredentials }'
            }

        dnac = "https://sandboxdnac.cisco.com"

        # -------------------------
        # Get OAuth Token
        # -------------------------

        oAuthTokenRAW = requests.request("POST", f"{ dnac }/dna/system/api/v1/auth/token", headers=auth_headers)
        oAuthTokenJSON = oAuthTokenRAW.json()
        token = oAuthTokenJSON['Token']

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Auth-Token': token,
        }
    
        networkHealthRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/network-health", headers=headers)
        networkHealthJSON = networkHealthRAW.json()

        # Pass to template 

        if networkHealthJSON is not None:
            networkHealth_template = env.get_template('DNAC_network_health.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = networkHealth_template.render(health = networkHealthJSON,DNAC=url,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"DNAC Network Health.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()                       
                else:
                    with open("DNAC Network Health Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"DNAC Network Health.json", "w") as fh:
                    json.dump(networkHealthJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(networkHealthJSON)
    except Exception as e:
        logging.exception(e)

def DNAC_device(url, username, password):
    try:
        # -------------------------
        # Headers
        # -------------------------
        encodedCredentials=base64.b64encode(bytes(f'{ username}:{ password}', 'utf-8')).decode()
        
        auth_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic { encodedCredentials }'
            }

        dnac = "https://sandboxdnac.cisco.com"

        # -------------------------
        # Get OAuth Token
        # -------------------------

        oAuthTokenRAW = requests.request("POST", f"{ dnac }/dna/system/api/v1/auth/token", headers=auth_headers)
        oAuthTokenJSON = oAuthTokenRAW.json()
        token = oAuthTokenJSON['Token']

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Auth-Token': token,
        }
    
        # -------------------------
        # Get Sites to find global site ID
        # -------------------------    

        sitesRAW = requests.request("GET", f"{ url }/dna/intent/api/v1/site/", headers=headers)
        sitesJSON = sitesRAW.json()

        # Pass to template 

        if sitesJSON is not None:
            loop_counter = 0
            for site in sitesJSON['response']:
                sitesMembersRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/membership/{ site['id'] }", headers=headers)
                sitesMembersJSON = sitesMembersRAW.json()
                if site['name'] == "Global":
                    globalSiteID = site['id']                

        # -------------------------
        # Get All Devices
        # -------------------------

        devicesRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/network-device/", headers=headers)
        devicesJSON = devicesRAW.json()

        # -------------------------
        # Device Health
        # -------------------------

        healthRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/device-health/", headers=headers)
        healthJSON = healthRAW.json()

        for device in devicesJSON['response']:           
        
        # -------------------------
        # create folders to hold files
        # -------------------------
            if not os.path.exists(f"{ device['hostname'] }"):
                os.mkdir(f"{ device['hostname'] }")
            else:
                print("Directory already exists")

        # -------------------------
        # Base Details per Device
        # -------------------------

            deviceRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/network-device/{ device['id'] }", headers=headers)
            deviceJSON = deviceRAW.json()

        # -------------------------
        # Chassis per Device
        # -------------------------

            deviceChassisRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/network-device/{ device['id'] }/chassis", headers=headers)
            deviceChassisJSON = deviceChassisRAW.json()

            if deviceChassisJSON['response'] != []:
                device_chassis_template = env.get_template('DNAC_device_chassis.j2')
                loop_counter = 0
                # Render Templates
                for filetype in filetype_loop:
                    parsed_output = device_chassis_template.render(chassis = deviceChassisJSON['response'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

            # -------------------------
            # Save the files
            # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ device['hostname']}/ { device['hostname'] } Chassis.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()                       
                    else:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Chassis Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Chassis.json", "w") as fh:
                        json.dump(deviceChassisJSON, fh, indent=4, sort_keys=True)
                        fh.close()
                print(f"{ device['hostname'] } Chassis transformed")

        # -------------------------
        # PowerSupply
        # -------------------------

            powerSupplyRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/network-device/{ device['id'] }/equipment?type=PowerSupply", headers=headers)
            powerSupplyJSON = powerSupplyRAW.json()

            if powerSupplyJSON['response'] != []:
                device_power_template = env.get_template('DNAC_device_power.j2')
                loop_counter = 0
            # Render Templates
                for filetype in filetype_loop:
                    parsed_output = device_power_template.render(powersupply = powerSupplyJSON['response'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

            # -------------------------
            # Save the files
            # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Power Supplies.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()                       
                    else:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Power Supplies Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Power Supplies.json", "w") as fh:
                        json.dump(powerSupplyJSON, fh, indent=4, sort_keys=True)
                        fh.close()
                print(f"{ device['hostname'] } Power Supply transformed")
        # -------------------------
        # Fan
        # -------------------------

            fanRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/network-device/{ device['id'] }/equipment?type=Fan", headers=headers)
            fanJSON = fanRAW.json()

            if fanJSON['response'] != []:
                device_fan_template = env.get_template('DNAC_device_fan.j2')
                loop_counter = 0
            # Render Templates
                for filetype in filetype_loop:
                    parsed_output = device_fan_template.render(fan = fanJSON['response'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

                # -------------------------
                # Save the files
                # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Fans.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()                       
                    else:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Fans Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Fans.json", "w") as fh:
                        json.dump(fanJSON, fh, indent=4, sort_keys=True)
                        fh.close()
                print(f"{ device['hostname'] } Fan transformed")
        # -------------------------
        # Backplane
        # -------------------------

            backplaneRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/network-device/{ device['id'] }/equipment?type=Backplane", headers=headers)
            backplaneJSON = backplaneRAW.json()

            if backplaneJSON['response'] != []:
                device_backplane_template = env.get_template('DNAC_device_backplane.j2')
                loop_counter = 0
            # Render Templates
                for filetype in filetype_loop:
                    parsed_output = device_backplane_template.render(backplane = backplaneJSON['response'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

                # -------------------------
                # Save the files
                # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Backplane.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()                       
                    else:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Backplane Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Backplane.json", "w") as fh:
                        json.dump(backplaneJSON, fh, indent=4, sort_keys=True)
                        fh.close()
                print(f"{ device['hostname'] } Backplane transformed")
        # -------------------------
        # Module
        # -------------------------

            moduleRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/network-device/{ device['id'] }/equipment?type=Module", headers=headers)
            moduleSON = moduleRAW.json()

            if moduleSON['response'] != []:
                device_module_template = env.get_template('DNAC_device_module.j2')
                loop_counter = 0
                # Render Templates
                for filetype in filetype_loop:
                    parsed_output = device_module_template.render(module = moduleSON['response'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

                # -------------------------
                # Save the files
                # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Modules.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()                       
                    else:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Modules Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Modules.json", "w") as fh:
                        json.dump(moduleSON, fh, indent=4, sort_keys=True)
                        fh.close()
                print(f"{ device['hostname'] } Modules transformed")
        # -------------------------
        # PROCESSOR
        # -------------------------

            processorRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/network-device/{ device['id'] }/equipment?type=PROCESSOR", headers=headers)
            processorJSON = processorRAW.json()

            if processorJSON['response'] != []:
                device_processor_template = env.get_template('DNAC_device_processor.j2')
                loop_counter = 0
                # Render Templates
                for filetype in filetype_loop:
                    parsed_output = device_processor_template.render(processor = processorJSON['response'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

                # -------------------------
                # Save the files
                # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Processors.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()                       
                    else:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Processors Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Processors.json", "w") as fh:
                        json.dump(processorJSON, fh, indent=4, sort_keys=True)
                        fh.close()
                print(f"{ device['hostname'] } Processors transformed")
        # -------------------------
        # Other
        # -------------------------

            otherRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/network-device/{ device['id'] }/equipment?type=Other", headers=headers)
            otherJSON = otherRAW.json()

            if otherJSON['response'] != []:
                device_other_template = env.get_template('DNAC_device_other.j2')
                loop_counter = 0
                # Render Templates
                for filetype in filetype_loop:
                    parsed_output = device_other_template.render(other = otherJSON['response'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

                # -------------------------
                # Save the files
                # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Other Parts.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()                       
                    else:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Other Parts Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Other Parts.json", "w") as fh:
                        json.dump(otherJSON, fh, indent=4, sort_keys=True)
                        fh.close()
                print(f"{ device['hostname'] } Other Parts transformed")
        # -------------------------
        # PoE
        # -------------------------

            poeRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/network-device/{ device['id'] }/interface/poe-detail", headers=headers)
            poeJSON = poeRAW.json()

            if poeJSON['response'] != []:
                device_poe_template = env.get_template('DNAC_device_poe.j2')
                loop_counter = 0
                # Render Templates
                for filetype in filetype_loop:
                    parsed_output = device_poe_template.render(poe = poeJSON['response'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

                # -------------------------
                # Save the files
                # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Power over Ethernet.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()                       
                    else:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Power over Ethernet Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Power over Ethernet.json", "w") as fh:
                        json.dump(poeJSON, fh, indent=4, sort_keys=True)
                        fh.close()
                print(f"{ device['hostname'] } Power over Ethernet transformed")
        # -------------------------
        # VLANs
        # -------------------------

            deviceVlanRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/network-device/{ device['id'] }/vlan", headers=headers)
            deviceVlanJSON = deviceVlanRAW.json()

            if deviceVlanJSON['response'] != []:
                device_vlan_template = env.get_template('DNAC_device_vlan.j2')
                loop_counter = 0
                # Render Templates
                for filetype in filetype_loop:
                    parsed_output = device_vlan_template.render(vlan = deviceVlanJSON['response'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

                # -------------------------
                # Save the files
                # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } VLANs.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()                       
                    else:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } VLANs Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"{ device['hostname'] }/DNAC { device['hostname'] } VLANs.json", "w") as fh:
                        json.dump(deviceVlanJSON, fh, indent=4, sort_keys=True)
                        fh.close()
                print(f"{ device['hostname'] } VLANs transformed")
        # -------------------------
        # Interfaces
        # -------------------------

            interfacesRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/interface/network-device/{ device['id'] }", headers=headers)
            interfacesJSON = interfacesRAW.json()

            if interfacesJSON['response'] != []:
                device_interface_template = env.get_template('DNAC_device_interface.j2')
                loop_counter = 0
                # Render Templates
                for filetype in filetype_loop:
                    parsed_output = device_interface_template.render(interfaces = interfacesJSON['response'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

                # -------------------------
                # Save the files
                # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Interfaces.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()                       
                    else:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Interfaces Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Interfaces.json", "w") as fh:
                        json.dump(interfacesJSON, fh, indent=4, sort_keys=True)
                        fh.close()
                print(f"{ device['hostname'] } Interfaces transformed")
        # -------------------------
        # Stack
        # -------------------------

            stackRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/network-device/{ device['id'] }/stack", headers=headers)
            stackJSON = stackRAW.json()

            if stackJSON['response'] != []:
                device_stack_template = env.get_template('DNAC_device_stack.j2')
                loop_counter = 0
                # Render Templates
                for filetype in filetype_loop:
                    parsed_output = device_stack_template.render(stack = stackJSON['response'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

                # -------------------------
                # Save the files
                # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Stack.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()                       
                    else:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Stack Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Stack.json", "w") as fh:
                        json.dump(stackJSON, fh, indent=4, sort_keys=True)
                        fh.close()
                print(f"{ device['hostname'] } Stack transformed")

        # -------------------------
        # Health
        # -------------------------

            if healthJSON['response'] != []:
                device_health_template = env.get_template('DNAC_device_health.j2')
                loop_counter = 0
            # Render Templates
                for filetype in filetype_loop:
                    parsed_output = device_health_template.render(health = healthJSON['response'],device = deviceJSON['response'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1
        
                # -------------------------
                # Save the files
                # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ device['hostname'] }/DNAC Device Health.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()                       
                    else:
                        with open(f"{ device['hostname'] }/DNAC Device Health Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"{ device['hostname'] }/DNAC Device Health.json", "w") as fh:
                        json.dump(healthJSON, fh, indent=4, sort_keys=True)
                        fh.close()  
                print(f"{ device['hostname'] } Health transformed")


                # -------------------------
                # Link Mismatch - VLAN
                # -------------------------

            insightVlanRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/network-device/insight/{ globalSiteID }/device-link?category=vlan", headers=headers)
            insightVlanJSON = insightVlanRAW.json()

            if insightVlanJSON['response'] != []:
                device_insightVLAN_template = env.get_template('DNAC_device_insight_vlan.j2')
                loop_counter = 0
            # Render Templates
                for filetype in filetype_loop:
                    parsed_output = device_insightVLAN_template.render(insightVLAN = insightVlanJSON['response'],device = deviceJSON['response'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

                # -------------------------
                # Save the files
                # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ device['hostname'] }/DNAC Insight VLANs.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()                       
                    else:
                        with open(f"{ device['hostname'] }/DNAC Insight VLANs Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"{ device['hostname'] }/DNAC Insight VLANs.json", "w") as fh:
                        json.dump(insightVlanJSON, fh, indent=4, sort_keys=True)
                        fh.close()                            
                print(f"{ device['hostname'] } Insight VLAN transformed")

                # -------------------------
                # Link Mismatch - Speed Duplex
                # -------------------------

            insightSpeedDuplexRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/network-device/insight/{ globalSiteID }/device-link?category=speed-duplex", headers=headers)
            insightSpeedDuplexJSON = insightSpeedDuplexRAW.json()

            if insightSpeedDuplexJSON['response'] != []:
                device_insightSpeedDuplex_template = env.get_template('DNAC_device_insight_speed_duplex.j2')
                loop_counter = 0
                # Render Templates
                for filetype in filetype_loop:
                    parsed_output = device_insightSpeedDuplex_template.render(insightSpeedDuplex = insightSpeedDuplexJSON['response'],device = deviceJSON['response'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

                # -------------------------
                # Save the files
                # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ device['hostname'] }/DNAC Insight Speed Duplex.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()                       
                    else:
                        with open(f"{ device['hostname'] }/DNAC Insight Speed Duplex Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"{ device['hostname'] }/DNAC Insight Speed Duplex.json", "w") as fh:
                        json.dump(insightSpeedDuplexJSON, fh, indent=4, sort_keys=True)
                        fh.close()  
                print(f"{ device['hostname'] } Insight Speed Duplex transformed")

        # -------------------------
        # Compliance
        # -------------------------

            complianceRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/compliance/{ device['id'] }/detail", headers=headers)
            complianceJSON = complianceRAW.json()

            if complianceJSON['response'] != []:
                device_compliance_template = env.get_template('DNAC_device_compliance.j2')
                loop_counter = 0
                # Render Templates
                for filetype in filetype_loop:
                    parsed_output = device_compliance_template.render(compliance = complianceJSON['response'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

                # -------------------------
                # Save the files
                # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Compliance.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()                       
                    else:
                        with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Compliance Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"{ device['hostname'] }/DNAC { device['hostname'] } Compliance.json", "w") as fh:
                        json.dump(complianceJSON, fh, indent=4, sort_keys=True)
                        fh.close()
                print(f"{ device['hostname'] } Compliance transformed")
            device_template = env.get_template('DNAC_device.j2')
            loop_counter = 0

        # -------------------------
        # Pass to Jinja2 Template 
        # -------------------------
            for filetype in filetype_loop:
                parsed_output = device_template.render(
                        device = deviceJSON['response'],
                        chassis = deviceChassisJSON['response'],
                        powersupply = powerSupplyJSON['response'],
                        fan = fanJSON['response'],
                        backplane = backplaneJSON['response'],
                        module = moduleSON['response'],
                        processor = processorJSON['response'],
                        other = otherJSON['response'],
                        poe = poeJSON['response'],
                        vlan = deviceVlanJSON['response'],
                        insightVLAN = insightVlanJSON['response'],
                        insightSpeedDuplex = insightSpeedDuplexJSON['response'],
                        interfaces = interfacesJSON['response'],
                        stack = stackJSON['response'],
                        health = healthJSON['response'],
                        compliance = complianceJSON['response'],
                        filetype_loop=loop_counter
                )
                loop_counter = loop_counter + 1
    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ device['hostname'] }/DNAC Device { device['hostname'] }.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                else:
                    with open(f"{ device['hostname'] }/DNAC Device { device['hostname'] } Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                        loop_counter = 0
                with open(f"{ device['hostname'] }/DNAC Device { device['hostname'] }.json", "w") as fh:
                    json.dump(deviceJSON, fh, indent=4, sort_keys=True)
                    fh.close()
            print(f"{ device['hostname'] } transformed")
                        
        return(devicesJSON)
    except Exception as e:
        logging.exception(e)

def DNAC_swim(url, username, password):
    try:
        # -------------------------
        # Headers
        # -------------------------
        encodedCredentials=base64.b64encode(bytes(f'{ username}:{ password}', 'utf-8')).decode()
        
        auth_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic { encodedCredentials }'
            }

        dnac = "https://sandboxdnac.cisco.com"

        # -------------------------
        # Get OAuth Token
        # -------------------------

        oAuthTokenRAW = requests.request("POST", f"{ dnac }/dna/system/api/v1/auth/token", headers=auth_headers)
        oAuthTokenJSON = oAuthTokenRAW.json()
        token = oAuthTokenJSON['Token']

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Auth-Token': token,
        }
    
        swimRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/image/importation", headers=headers)
        swimJSON = swimRAW.json()

        # Pass to template 

        if swimJSON is not None:
            swim_template = env.get_template('DNAC_swim.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = swim_template.render(swim = swimJSON['response'],DNAC=url,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"DNAC Software Image Management.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()                       
                else:
                    with open("DNAC Software Image Management Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"DNAC Software Image Management.json", "w") as fh:
                    json.dump(swimJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(swimJSON)
    except Exception as e:
        logging.exception(e)

def DNAC_projects(url, username, password):
    try:
        # -------------------------
        # Headers
        # -------------------------
        encodedCredentials=base64.b64encode(bytes(f'{ username}:{ password}', 'utf-8')).decode()
        
        auth_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic { encodedCredentials }'
            }

        dnac = "https://sandboxdnac.cisco.com"

        # -------------------------
        # Get OAuth Token
        # -------------------------

        oAuthTokenRAW = requests.request("POST", f"{ dnac }/dna/system/api/v1/auth/token", headers=auth_headers)
        oAuthTokenJSON = oAuthTokenRAW.json()
        token = oAuthTokenJSON['Token']

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Auth-Token': token,
        }
    
        projectsRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/template-programmer/project", headers=headers)
        projectsJSON = projectsRAW.json()

        # Pass to template 

        if projectsJSON is not None:
            projects_template = env.get_template('DNAC_projects.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = projects_template.render(projects = projectsJSON,DNAC=url,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"DNAC Projects.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()                       
                else:
                    with open("DNAC Projects Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"DNAC Projects.json", "w") as fh:
                    json.dump(projectsJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(projectsJSON)
    except Exception as e:
        logging.exception(e)

def DNAC_templates(url, username, password):
    try:
        # -------------------------
        # Headers
        # -------------------------
        encodedCredentials=base64.b64encode(bytes(f'{ username}:{ password}', 'utf-8')).decode()
        
        auth_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic { encodedCredentials }'
            }

        dnac = "https://sandboxdnac.cisco.com"

        # -------------------------
        # Get OAuth Token
        # -------------------------

        oAuthTokenRAW = requests.request("POST", f"{ dnac }/dna/system/api/v1/auth/token", headers=auth_headers)
        oAuthTokenJSON = oAuthTokenRAW.json()
        token = oAuthTokenJSON['Token']

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Auth-Token': token,
        }
    
        projectsRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/template-programmer/project", headers=headers)
        projectsJSON = projectsRAW.json()

        # Pass to template 

        if projectsJSON is not None:
            for item in projectsJSON:
                for template in item['templates']:
                    templatesRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/template-programmer/template/{ template['id'] }", headers=headers)
                    templatesJSON = templatesRAW.json()

        # -------------------------
        # create folders to hold files
        # -------------------------
                    if not os.path.exists(f"{ template['name'] }"):
                        os.mkdir(f"{ template['name'] }")
                    else:
                        print("Directory already exists")

                    if templatesJSON is not None:
                        templates_template = env.get_template('DNAC_templates.j2')
                        loop_counter = 0
        # Render Templates
                        for filetype in filetype_loop:
                            parsed_output = templates_template.render(project = item['name'],template = templatesJSON,filetype_loop=loop_counter)
                            loop_counter = loop_counter + 1
    # -------------------------
    # Save the files
    # -------------------------
                            if loop_counter <= 3:
                                with open(f"{ template['name'] }/DNAC { template['name'] } Template.{ filetype }", "w") as fh:
                                    fh.write(parsed_output)               
                                    fh.close()                       
                            else:
                                with open(f"{ template['name'] }/DNAC { template['name'] } Template Mind Map.md", "w") as fh:
                                    fh.write(parsed_output)               
                                    fh.close()
                            with open(f"{ template['name'] }/DNAC { template['name'] } Template.json", "w") as fh:
                                json.dump(templatesJSON, fh, indent=4, sort_keys=True)
                                fh.close()                            
        return(templatesJSON)
    except Exception as e:
        logging.exception(e)

def DNAC_rf_profiles(url, username, password):
    try:
        # -------------------------
        # Headers
        # -------------------------
        encodedCredentials=base64.b64encode(bytes(f'{ username}:{ password}', 'utf-8')).decode()
        
        auth_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic { encodedCredentials }'
            }

        dnac = "https://sandboxdnac.cisco.com"

        # -------------------------
        # Get OAuth Token
        # -------------------------

        oAuthTokenRAW = requests.request("POST", f"{ dnac }/dna/system/api/v1/auth/token", headers=auth_headers)
        oAuthTokenJSON = oAuthTokenRAW.json()
        token = oAuthTokenJSON['Token']

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Auth-Token': token,
        }
    
        rfProfileRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/wireless/rf-profile", headers=headers)
        rfProfileJSON = rfProfileRAW.json()

        # Pass to template 

        if rfProfileJSON is not None:
            rf_profiles_template = env.get_template('DNAC_rf_profiles.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = rf_profiles_template.render(rfProfiles = rfProfileJSON['response'],DNAC=url,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"DNAC RF Profiles.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()                       
                else:
                    with open("DNAC RF Profiles Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"DNAC RF Profiles.json", "w") as fh:
                    json.dump(rfProfileJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(rfProfileJSON)
    except Exception as e:
        logging.exception(e)

def DNAC_assurance_tests(url, username, password):
    try:
        # -------------------------
        # Headers
        # -------------------------
        encodedCredentials=base64.b64encode(bytes(f'{ username}:{ password}', 'utf-8')).decode()
        
        auth_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic { encodedCredentials }'
            }

        dnac = "https://sandboxdnac.cisco.com"

        # -------------------------
        # Get OAuth Token
        # -------------------------

        oAuthTokenRAW = requests.request("POST", f"{ dnac }/dna/system/api/v1/auth/token", headers=auth_headers)
        oAuthTokenJSON = oAuthTokenRAW.json()
        token = oAuthTokenJSON['Token']

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Auth-Token': token,
        }
    
        assuranceTestsRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/AssuranceGetSensorTestResults", headers=headers)
        assuranceTestsJSON = assuranceTestsRAW.json()

        # Pass to template 

        if assuranceTestsJSON is not None:
            assurance_tests_template = env.get_template('DNAC_assurance_tests.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = assurance_tests_template.render(assurance_tests = assuranceTestsJSON['response'],DNAC=url,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"DNAC Assurance Tests.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()                       
                else:
                    with open("DNAC Assurance Tests Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"DNAC Assurance Tests.json", "w") as fh:
                    json.dump(assuranceTestsJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(assuranceTestsJSON)
    except Exception as e:
        logging.exception(e)

def DNAC_flow_analysis(url, username, password):
    try:
        # -------------------------
        # Headers
        # -------------------------
        encodedCredentials=base64.b64encode(bytes(f'{ username}:{ password}', 'utf-8')).decode()
        
        auth_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic { encodedCredentials }'
            }

        dnac = "https://sandboxdnac.cisco.com"

        # -------------------------
        # Get OAuth Token
        # -------------------------

        oAuthTokenRAW = requests.request("POST", f"{ dnac }/dna/system/api/v1/auth/token", headers=auth_headers)
        oAuthTokenJSON = oAuthTokenRAW.json()
        token = oAuthTokenJSON['Token']

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Auth-Token': token,
        }
    
        flowAnalysisRAW = requests.request("GET", f"{ dnac }/dna/intent/api/v1/flow-analysis", headers=headers)
        flowAnalysisJSON = flowAnalysisRAW.json()

        # Pass to template 

        if flowAnalysisJSON is not None:
            flow_template = env.get_template('DNAC_flow_analysis.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = flow_template.render(flow_analysis = flowAnalysisJSON['response'],DNAC=url,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"DNAC Flow Analysis.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()                       
                else:
                    with open("DNAC Flow Analysis Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"DNAC Flow Analysis.json", "w") as fh:
                    json.dump(flowAnalysisJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(flowAnalysisJSON)
    except Exception as e:
        logging.exception(e)

# -------------------------
# ISE REST APIs
# -------------------------

# ----------------
# ISE ALL
# ----------------

def ISE_all(url, username, password):
    ISE_ers_all(url, username, password)
    ISE_open_api_all(url, username, password)
    ISE_mnt_all(url, username, password)
    return("All ISE APIs Converted to Business Ready Documents")

# ----------------
# ISE ERS
# ----------------

def ISE_ers_all(url, username, password):
    ISE_allowed_protocols(url, username, password)
    ISE_admin_users(url, username, password)
    ISE_active_directory(url, username, password)
    ISE_authorization_profile(url, username, password)
    ISE_dacl(url, username, password)
    ISE_endpoint(url, username, password)
    ISE_endpoint_groups(url, username, password)
    ISE_identity_groups(url, username, password)
    ISE_identity_store_sequence(url, username, password)
    ISE_internal_users(url, username, password)
    ISE_network_devices(url, username, password)
    ISE_network_device_groups(url, username, password)
    ISE_nodes(url, username, password)
    ISE_portals(url, username, password)
    ISE_profiler(url, username, password)
    ISE_deployment_info(url, username, password)
    ISE_sgt(url, username, password)
    ISE_sgt_acl(url, username, password)
    ISE_self_registration_portal(url, username, password)
    ISE_sponsor_groups(url, username, password)
    ISE_sponsor_portal(url, username, password)
    ISE_sponsored_guest_portal(url, username, password)
    return("All ISE ERS REST APIs Converted to Business Ready Documents")

# ----------------
# ISE Open API
# ----------------

def ISE_open_api_all(url, username, password):
    ISE_last_backup(url, username, password)
    ISE_csr(url, username, password)
    ISE_system_certificates(url, username, password)
    ISE_trusted_certificates(url, username, password)
    ISE_deployment_node(url, username, password)
    ISE_pan_ha(url, username, password)
    ISE_node_interfaces(url, username, password)
    ISE_node_profile(url, username, password)
    ISE_license_connection_type(url, username, password)
    ISE_eval_license(url, username, password)
    ISE_license_feature_map(url, username, password)
    ISE_license_register(url, username, password)
    ISE_license_smart_state(url, username, password)
    ISE_license_tier_state(url, username, password)
    ISE_patch(url, username, password)
    ISE_hot_patch(url, username, password)
    ISE_repository(url, username, password)
    ISE_proxy(url, username, password)
    ISE_transport_gateway(url, username, password)
    ISE_nbar_app(url, username, password)
    ISE_command_set(url, username, password)
    ISE_condition(url, username, password)
    ISE_authentication_dictionary(url, username, password)
    ISE_authorization_dictionary(url, username, password)
    ISE_policy_set_dictionary(url, username, password)
    ISE_identity_stores(url, username, password)
    ISE_policy_sets(url, username, password)
    ISE_authentication_policy_sets(url, username, password)
    ISE_authorization_policy_sets(url, username, password)
    ISE_service_names(url, username, password)
    ISE_shell_profiles(url, username, password)
    ISE_network_authorization_profiles(url, username, password)
    ISE_network_access_condition(url, username, password)
    ISE_network_access_condition_authentication(url, username, password)
    ISE_network_access_condition_authorization(url, username, password)
    ISE_network_access_condition_policy_set(url, username, password)
    ISE_network_access_dictionaries(url, username, password)
    ISE_network_access_dictionaries_authentication(url, username, password)
    ISE_network_access_dictionaries_authorization(url, username, password)
    ISE_network_access_dictionaries_policy_set(url, username, password)
    ISE_network_access_identity_stores(url, username, password)
    ISE_network_access_policy_set(url, username, password)
    ISE_network_access_policy_authentication(url, username, password)
    ISE_network_access_policy_authorization(url, username, password)
    ISE_network_access_security_groups(url, username, password)
    ISE_network_access_service_names(url, username, password)
    return("All ISE OPEN REST APIs Converted to Business Ready Documents")

# ----------------
# ISE MNT
# ----------------

def ISE_mnt_all(url, username, password):
    ISE_active_sessions(url, username, password)
    ISE_posture_count(url, username, password)
    ISE_profiler_count(url, username, password)
    ISE_version(url, username, password)
    ISE_failure_codes(url, username, password)
    return("All ISE MnT REST APIs Converted to Business Ready Documents")

# ----------------
# ISE ERS
# ----------------

def ISE_allowed_protocols(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        allowedProtocols = requests.request("GET", f"{ url }/ers/config/allowedprotocols", headers=headers, auth=(username, password), verify=False)
        allowedProtocolsJSON = allowedProtocols.json()

        # Pass to template 

        if allowedProtocolsJSON is not None:
            allowedProtocols_template = env.get_template('ISE_allowed_protocols.j2')
            loop_counter = 0
            allowedProtocolsDetails = []
            for href in allowedProtocolsJSON['SearchResult']['resources']:
                allowedProtocolHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                allowedProtocolHrefJSON = allowedProtocolHref.json()
                allowedProtocolsDetails.append(allowedProtocolHrefJSON)            
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = allowedProtocols_template.render(allowedProtocolsDetails = allowedProtocolsDetails,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Allowed Protocols.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Allowed Protocols Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Allowed Protocols.json", "w") as fh:
                    json.dump(allowedProtocolsDetails, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(allowedProtocolsDetails)
    except Exception as e:
        logging.exception(e)

def ISE_admin_users(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        adminUsers = requests.request("GET", f"{ url }/ers/config/adminuser", headers=headers, auth=(username, password), verify=False)
        adminUsersJSON = adminUsers.json()

        # Pass to template 

        if adminUsersJSON is not None:
            adminUsers_template = env.get_template('ISE_admin_users.j2')
            loop_counter = 0
            adminUsersDetails = []
            for href in adminUsersJSON['SearchResult']['resources']:
                adminUserHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                adminUserHrefJSON = adminUserHref.json()
                adminUsersDetails.append(adminUserHrefJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = adminUsers_template.render(adminUsersDetails = adminUsersDetails,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Admin Users.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Admin Users Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Admin Users.json", "w") as fh:
                    json.dump(adminUsersDetails, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(adminUsersDetails)
    except Exception as e:
        logging.exception(e)

def ISE_active_directory(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        activeDirectoryAll = requests.request("GET", f"{ url }/ers/config/activedirectory", headers=headers, auth=(username, password), verify=False)
        activeDirectoryAllJSON = activeDirectoryAll.json()

        # Pass to template 

        if activeDirectoryAllJSON is not None:
            activeDirectory_template = env.get_template('ISE_active_directory.j2')
            loop_counter = 0
            activeDirectory = []
            for href in activeDirectoryAllJSON['SearchResult']['resources']:
                activeDirectoryHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                activeDirectoryJSON = activeDirectoryHref.json()
                activeDirectory.append(activeDirectoryJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = activeDirectory_template.render(activeDirectory = activeDirectory,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Active Directory.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Active Directory Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Active Directory.json", "w") as fh:
                    json.dump(activeDirectory, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(activeDirectory)
    except Exception as e:
        logging.exception(e)

def ISE_authorization_profile(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        authorizationProfileAll = requests.request("GET", f"{ url }/ers/config/authorizationprofile", headers=headers, auth=(username, password), verify=False)
        authorizationProfileAllJSON = authorizationProfileAll.json()

        # Pass to template 

        if authorizationProfileAllJSON is not None:
            authorizationProfile_template = env.get_template('ISE_authorization_profile.j2')
            loop_counter = 0
            authorizationProfile = []
            for href in authorizationProfileAllJSON['SearchResult']['resources']:
                authorizationProfileHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                authorizationProfileJSON = authorizationProfileHref.json()
                authorizationProfile.append(authorizationProfileJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = authorizationProfile_template.render(authorizationProfile = authorizationProfile,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Authorization Profile.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Authorization Profile Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Authorization Profile.json", "w") as fh:
                    json.dump(authorizationProfile, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(authorizationProfile)
    except Exception as e:
        logging.exception(e)

def ISE_dacl(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        daclAll = requests.request("GET", f"{ url }/ers/config/downloadableacl", headers=headers, auth=(username, password), verify=False)
        daclAllJSON = daclAll.json()

        # Pass to template 

        if daclAllJSON is not None:
            dacl_template = env.get_template('ISE_dacl.j2')
            loop_counter = 0
            dacl = []
            for href in daclAllJSON['SearchResult']['resources']:
                daclHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                daclHrefJSON = daclHref.json()
                dacl.append(daclHrefJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = dacl_template.render(dacl = dacl,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Downloadable ACLs.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Downloadable ACLs Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Downloadable ACLs.json", "w") as fh:
                    json.dump(dacl, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(dacl)
    except Exception as e:
        logging.exception(e)

def ISE_endpoint(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        endpointAll = requests.request("GET", f"{ url }/ers/config/endpoint", headers=headers, auth=(username, password), verify=False)
        endpointAllJSON = endpointAll.json()

        # Pass to template 

        if endpointAllJSON is not None:
            endpoint_template = env.get_template('ISE_endpoints.j2')
            loop_counter = 0
            endpoint = []
            for href in endpointAllJSON['SearchResult']['resources']:
                endpointHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                endpointHrefJSON = endpointHref.json()
                endpoint.append(endpointHrefJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = endpoint_template.render(endpoint = endpoint,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Endpoints.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Endpoints Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Endpoints.json", "w") as fh:
                    json.dump(endpoint, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(endpoint)
    except Exception as e:
        logging.exception(e)

def ISE_endpoint_groups(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        endpointGroupsAll = requests.request("GET", f"{ url }/ers/config/endpointgroup", headers=headers, auth=(username, password), verify=False)
        endpointGroupsAllJSON = endpointGroupsAll.json()

        # Pass to template 

        if endpointGroupsAllJSON is not None:
            endpointGroup_template = env.get_template('ISE_endpoint_groups.j2')
            loop_counter = 0
            endpointGroup = []
            for href in endpointGroupsAllJSON['SearchResult']['resources']:
                endpointGroupHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                endpointGroupHrefJSON = endpointGroupHref.json()
                endpointGroup.append(endpointGroupHrefJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = endpointGroup_template.render(endpointGroup = endpointGroup,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Endpoint Groups.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Endpoint Groups Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Endpoint Groups.json", "w") as fh:
                    json.dump(endpointGroup, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(endpointGroup)
    except Exception as e:
        logging.exception(e)

def ISE_identity_groups(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        identityGroupsAll = requests.request("GET", f"{ url }/ers/config/identitygroup", headers=headers, auth=(username, password), verify=False)
        identityGroupsAllJSON = identityGroupsAll.json()

        # Pass to template 

        if identityGroupsAllJSON is not None:
            identityGroup_template = env.get_template('ISE_identity_groups.j2')
            loop_counter = 0
            identityGroup = []
            for href in identityGroupsAllJSON['SearchResult']['resources']:
                identityGroupHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                identityGroupHrefJSON = identityGroupHref.json()
                identityGroup.append(identityGroupHrefJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = identityGroup_template.render(identityGroup = identityGroup,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Identity Groups.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Identity Groups Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Identity Groups.json", "w") as fh:
                    json.dump(identityGroup, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(identityGroup)
    except Exception as e:
        logging.exception(e)

def ISE_identity_store_sequence(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        idStoreSequenceAll = requests.request("GET", f"{ url }/ers/config/idstoresequence", headers=headers, auth=(username, password), verify=False)
        idStoreSequenceAllJSON = idStoreSequenceAll.json()

        # Pass to template 

        if idStoreSequenceAllJSON is not None:
            idStoreSequence_template = env.get_template('ISE_identity_store_sequence.j2')
            loop_counter = 0
            identityStoreSequence = []
            for href in idStoreSequenceAllJSON['SearchResult']['resources']:
                identityStoreHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                identityStoreHrefJSON = identityStoreHref.json()
                identityStoreSequence.append(identityStoreHrefJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = idStoreSequence_template.render(identityStoreSequence = identityStoreSequence,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Identity Store Sequence.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Identity Store Sequence Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Identity Store Sequence.json", "w") as fh:
                    json.dump(identityStoreSequence, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(identityStoreSequence)
    except Exception as e:
        logging.exception(e)

def ISE_internal_users(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        internalUserAll = requests.request("GET", f"{ url }/ers/config/internaluser", headers=headers, auth=(username, password), verify=False)
        internalUserAllJSON = internalUserAll.json()

        # Pass to template 

        if internalUserAllJSON is not None:
            internalUser_template = env.get_template('ISE_internal_users.j2')
            loop_counter = 0
            internalUser = []
            for href in internalUserAllJSON['SearchResult']['resources']:
                internalUserHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                internalUserHrefJSON = internalUserHref.json()
                internalUser.append(internalUserHrefJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = internalUser_template.render(internalUser = internalUser,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Internal Users.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Internal Users Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Internal Users.json", "w") as fh:
                    json.dump(internalUser, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(internalUser)
    except Exception as e:
        logging.exception(e)

def ISE_network_devices(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        networkDeviceAll = requests.request("GET", f"{ url }/ers/config/networkdevice", headers=headers, auth=(username, password), verify=False)
        networkDeviceAllJSON = networkDeviceAll.json()

        # Pass to template 

        if networkDeviceAllJSON is not None:
            networkDevices_template = env.get_template('ISE_network_devices.j2')
            loop_counter = 0
            networkDevice = []
            for href in networkDeviceAllJSON['SearchResult']['resources']:
                networkDeviceHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                networkDeviceHrefJSON = networkDeviceHref.json()
                networkDevice.append(networkDeviceHrefJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = networkDevices_template.render(networkDevice = networkDevice,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Network Devices.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Network Devices Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Network Devices.json", "w") as fh:
                    json.dump(networkDevice, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(networkDevice)
    except Exception as e:
        logging.exception(e)

def ISE_network_device_groups(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        networkDeviceGroupAll = requests.request("GET", f"{ url }/ers/config/networkdevicegroup", headers=headers, auth=(username, password), verify=False)
        networkDeviceGroupAllJSON = networkDeviceGroupAll.json()

        # Pass to template 

        if networkDeviceGroupAllJSON is not None:
            networkDeviceGroups_template = env.get_template('ISE_network_device_groups.j2')
            loop_counter = 0
            networkDeviceGroup = []
            for href in networkDeviceGroupAllJSON['SearchResult']['resources']:
                networkDeviceGroupHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                networkDeviceGroupHrefJSON = networkDeviceGroupHref.json()
                networkDeviceGroup.append(networkDeviceGroupHrefJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = networkDeviceGroups_template.render(networkDeviceGroup = networkDeviceGroup,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Network Device Groups.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Network Device Groups Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Network Device Groups.json", "w") as fh:
                    json.dump(networkDeviceGroup, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(networkDeviceGroup)
    except Exception as e:
        logging.exception(e)

def ISE_nodes(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        nodeAll = requests.request("GET", f"{ url }/ers/config/node", headers=headers, auth=(username, password), verify=False)
        nodeAllJSON = nodeAll.json()

        # Pass to template 

        if nodeAllJSON is not None:
            nodes_template = env.get_template('ISE_nodes.j2')
            loop_counter = 0
            node = []
            for href in nodeAllJSON['SearchResult']['resources']:
                nodeHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                nodeHrefJSON = nodeHref.json()
                node.append(nodeHrefJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = nodes_template.render(node = node,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Nodes.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Nodes Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Nodes.json", "w") as fh:
                    json.dump(node, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(node)
    except Exception as e:
        logging.exception(e)

def ISE_portals(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        portalAll = requests.request("GET", f"{ url }/ers/config/portal", headers=headers, auth=(username, password), verify=False)
        portalAllJSON = portalAll.json()

        # Pass to template 

        if portalAllJSON is not None:
            portals_template = env.get_template('ISE_portals.j2')
            loop_counter = 0
            portal = []
            for href in portalAllJSON['SearchResult']['resources']:
                portalHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                portalHrefJSON = portalHref.json()
                portal.append(portalHrefJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = portals_template.render(portal = portal,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Portals.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Portals Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Portals.json", "w") as fh:
                    json.dump(portal, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(portal)
    except Exception as e:
        logging.exception(e)

def ISE_profiler(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        profilerAll = requests.request("GET", f"{ url }/ers/config/profilerprofile", headers=headers, auth=(username, password), verify=False)
        profilerAllJSON = profilerAll.json()

        # Pass to template 

        if profilerAllJSON is not None:
            profiles_template = env.get_template('ISE_profiler.j2')
            loop_counter = 0
            profiler = []
            for href in profilerAllJSON['SearchResult']['resources']:
                profilerHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                profilerHrefJSON = profilerHref.json()
                profiler.append(profilerHrefJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = profiles_template.render(profiler = profiler,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Profiler Profiles.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Profiler Profiles Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Profiler Profiles.json", "w") as fh:
                    json.dump(profiler, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(profiler)
    except Exception as e:
        logging.exception(e)

def ISE_deployment_info(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        deploymentInfo = requests.request("GET", f"{ url }/ers/config/deploymentinfo/getAllInfo", headers=headers, auth=(username, password), verify=False)
        deploymentInfoJSON = deploymentInfo.json()

        # Pass to template 

        if deploymentInfoJSON is not None:
            deployment_template = env.get_template('ISE_deployment_info.j2')
            ise_cloud_info_template = env.get_template('ISE_deployment_cloud_info.j2')
            kong_info_template = env.get_template('ISE_deployment_kong_info.j2')
            license_info_template = env.get_template('ISE_deployment_license_info.j2')
            mdm_info_template = env.get_template('ISE_deployment_mdm_info.j2')
            nad_info_template = env.get_template('ISE_deployment_nad_info.j2')
            network_access_info_template = env.get_template('ISE_deployment_network_access_info.j2')
            posture_info_template = env.get_template('ISE_deployment_posture_info.j2')
            profiler_info_template = env.get_template('ISE_deployment_profiler_info.j2')
            loop_counter = 0      
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = deployment_template.render(deploymentInfoJSON = deploymentInfoJSON['ERSDeploymentInfo']['deploymentInfo'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

        # -------------------------
        # Save the files
        # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Deployment Info.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Deployment Info Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Deployment Info.json", "w") as fh:
                    json.dump(deploymentInfoJSON['ERSDeploymentInfo']['deploymentInfo'], fh, indent=4, sort_keys=True)
                    fh.close()
         
            loop_counter = 0
            for filetype in filetype_loop:
                parsed_output = ise_cloud_info_template.render(deploymentInfoJSON = deploymentInfoJSON['ERSDeploymentInfo']['iseCloudInfo'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

        # -------------------------
        # Save the files
        # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Deployment ISE Cloud Info.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Deployment ISE Cloud Info Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Deployment ISE Cloud Info.json", "w") as fh:
                    json.dump(deploymentInfoJSON['ERSDeploymentInfo']['iseCloudInfo'], fh, indent=4, sort_keys=True)
                    fh.close()

            loop_counter = 0
            for filetype in filetype_loop:
                parsed_output = kong_info_template.render(deploymentInfoJSON = deploymentInfoJSON['ERSDeploymentInfo']['kongInfo'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

        # -------------------------
        # Save the files
        # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Deployment Kong Info.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Deployment Kong Info Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Deployment Kong Info.json", "w") as fh:
                    json.dump(deploymentInfoJSON['ERSDeploymentInfo']['kongInfo'], fh, indent=4, sort_keys=True)
                    fh.close()

            loop_counter = 0
            for filetype in filetype_loop:
                parsed_output = license_info_template.render(deploymentInfoJSON = deploymentInfoJSON['ERSDeploymentInfo']['licensesInfo'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

        # -------------------------
        # Save the files
        # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Deployment License Info.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Deployment License Info Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Deployment License Info.json", "w") as fh:
                    json.dump(deploymentInfoJSON['ERSDeploymentInfo']['licensesInfo'], fh, indent=4, sort_keys=True)
                    fh.close()

            loop_counter = 0
            for filetype in filetype_loop:
                parsed_output = mdm_info_template.render(deploymentInfoJSON = deploymentInfoJSON['ERSDeploymentInfo']['mdmInfo'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

        # -------------------------
        # Save the files
        # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Deployment MDM Info.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Deployment MDM Info Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Deployment MDM Info.json", "w") as fh:
                    json.dump(deploymentInfoJSON['ERSDeploymentInfo']['mdmInfo'], fh, indent=4, sort_keys=True)
                    fh.close()

            loop_counter = 0
            for filetype in filetype_loop:
                parsed_output = nad_info_template.render(deploymentInfoJSON = deploymentInfoJSON['ERSDeploymentInfo']['nadInfo'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

        # -------------------------
        # Save the files
        # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Deployment NAD Info.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Deployment NAD Info Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Deployment NAD Info.json", "w") as fh:
                    json.dump(deploymentInfoJSON['ERSDeploymentInfo']['nadInfo'], fh, indent=4, sort_keys=True)
                    fh.close()

            loop_counter = 0
            for filetype in filetype_loop:
                parsed_output = network_access_info_template.render(deploymentInfoJSON = deploymentInfoJSON['ERSDeploymentInfo']['networkAccessInfo'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

        # -------------------------
        # Save the files
        # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Deployment Network Access Info.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Deployment Network Access Info Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Deployment Network Access Info.json", "w") as fh:
                    json.dump(deploymentInfoJSON['ERSDeploymentInfo']['networkAccessInfo'], fh, indent=4, sort_keys=True)
                    fh.close()

            loop_counter = 0
            for filetype in filetype_loop:
                parsed_output = posture_info_template.render(deploymentInfoJSON = deploymentInfoJSON['ERSDeploymentInfo']['postureInfo'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

        # -------------------------
        # Save the files
        # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Deployment Posture Info.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Deployment Posture Info Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Deployment Posture Info.json", "w") as fh:
                    json.dump(deploymentInfoJSON['ERSDeploymentInfo']['postureInfo'], fh, indent=4, sort_keys=True)
                    fh.close()

            loop_counter = 0
            for filetype in filetype_loop:
                parsed_output = profiler_info_template.render(deploymentInfoJSON = deploymentInfoJSON['ERSDeploymentInfo']['profilerInfo'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

        # -------------------------
        # Save the files
        # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Deployment Profiler Info.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Deployment Profiler Info Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Deployment Profiler Info.json", "w") as fh:
                    json.dump(deploymentInfoJSON['ERSDeploymentInfo']['profilerInfo'], fh, indent=4, sort_keys=True)
                    fh.close()

        return(deploymentInfoJSON)
    except Exception as e:
        logging.exception(e)

def ISE_sgt(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        sgtAll = requests.request("GET", f"{ url }/ers/config/sgt", headers=headers, auth=(username, password), verify=False)
        sgtAllJSON = sgtAll.json()

        # Pass to template 

        if sgtAllJSON is not None:
            sgt_template = env.get_template('ISE_sgt.j2')
            loop_counter = 0
            sgt = []
            for href in sgtAllJSON['SearchResult']['resources']:
                sgtHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                sgtHrefJSON = sgtHref.json()
                sgt.append(sgtHrefJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = sgt_template.render(sgt = sgt,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Secure Group Tags.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Secure Group Tags Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Secure Group Tags.json", "w") as fh:
                    json.dump(sgt, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(sgt)
    except Exception as e:
        logging.exception(e)

def ISE_sgt_acl(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        sgtACLAll = requests.request("GET", f"{ url }/ers/config/sgacl", headers=headers, auth=(username, password), verify=False)
        sgtACLAllJSON = sgtACLAll.json()

        # Pass to template 

        if sgtACLAllJSON is not None:
            sgtACL_template = env.get_template('ISE_sgt_acls.j2')
            loop_counter = 0
            sgtacl = []
            for href in sgtACLAllJSON['SearchResult']['resources']:
                sgtACLHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                sgtACLHrefJSON = sgtACLHref.json()
                sgtacl.append(sgtACLHrefJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = sgtACL_template.render(sgtacl = sgtacl,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Secure Group Tags Access Control Lists.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Secure Group Tags Access Control Lists Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Secure Group Tags Access Control Lists.json", "w") as fh:
                    json.dump(sgtacl, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(sgtacl)
    except Exception as e:
        logging.exception(e)

def ISE_self_registration_portal(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        selfRegPortalAll = requests.request("GET", f"{ url }/ers/config/selfregportal", headers=headers, auth=(username, password), verify=False)
        selfRegPortalAllJSON = selfRegPortalAll.json()

        # Pass to template 

        if selfRegPortalAllJSON is not None:
            self_reg_portal_template = env.get_template('ISE_self_registration_portal.j2')
            loop_counter = 0
            selfRegPortal = []
            for href in selfRegPortalAllJSON['SearchResult']['resources']:
                selfRegPortalHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                selfRegPortalHrefJSON = selfRegPortalHref.json()
                selfRegPortal.append(selfRegPortalHrefJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = self_reg_portal_template.render(selfRegPortal = selfRegPortal,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Self Registration Portal.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Self Registration Portal Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Self Registration Portal.json", "w") as fh:
                    json.dump(selfRegPortal, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(selfRegPortal)
    except Exception as e:
        logging.exception(e)

def ISE_sponsor_groups(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        sponsorGroupAll = requests.request("GET", f"{ url }/ers/config/sponsorgroup", headers=headers, auth=(username, password), verify=False)
        sponsorGroupAllJSON = sponsorGroupAll.json()

        # Pass to template 

        if sponsorGroupAllJSON is not None:
            sponsorGroups_template = env.get_template('ISE_sponsor_groups.j2')
            loop_counter = 0
            sponsorGroup = []
            for href in sponsorGroupAllJSON['SearchResult']['resources']:
                sponsorGroupHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                sponsorGroupHrefJSON = sponsorGroupHref.json()
                sponsorGroup.append(sponsorGroupHrefJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = sponsorGroups_template.render(sponsorGroup = sponsorGroup,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Sponsor Groups.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Sponsor Groups Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Sponsor Groups.json", "w") as fh:
                    json.dump(sponsorGroup, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(sponsorGroup)
    except Exception as e:
        logging.exception(e)

def ISE_sponsor_portal(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        sponsorPortalAll = requests.request("GET", f"{ url }/ers/config/sponsorportal", headers=headers, auth=(username, password), verify=False)
        sponsorPortalAllJSON = sponsorPortalAll.json()

        # Pass to template 

        if sponsorPortalAllJSON is not None:
            sponsor_portal_template = env.get_template('ISE_sponsor_portal.j2')
            loop_counter = 0
            sponsorPortal = []
            for href in sponsorPortalAllJSON['SearchResult']['resources']:
                sponsorPortalHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                sponsorPortalHrefJSON = sponsorPortalHref.json()
                sponsorPortal.append(sponsorPortalHrefJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = sponsor_portal_template.render(sponsorPortal = sponsorPortal,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Sponsor Portal.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Sponsor Portal Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Sponsor Portal.json", "w") as fh:
                    json.dump(sponsorPortal, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(sponsorPortal)
    except Exception as e:
        logging.exception(e)

def ISE_sponsored_guest_portal(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        sponsorGuestPortalAll = requests.request("GET", f"{ url }/ers/config/sponsoredguestportal", headers=headers, auth=(username, password), verify=False)
        sponsorGuestPortalAllJSON = sponsorGuestPortalAll.json()

        # Pass to template 

        if sponsorGuestPortalAllJSON is not None:
            sponsor_guest_portal_template = env.get_template('ISE_sponsor_guest_portal.j2')
            loop_counter = 0
            sponsorGuestPortal = []
            for href in sponsorGuestPortalAllJSON['SearchResult']['resources']:
                sponsorGuestPortalHref = requests.request("GET", href['link']['href'], headers=headers, auth=(username, password), verify=False)
                sponsorGuestPortalHrefJSON = sponsorGuestPortalHref.json()
                sponsorGuestPortal.append(sponsorGuestPortalHrefJSON)          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = sponsor_guest_portal_template.render(sponsorGuestPortal = sponsorGuestPortal,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Sponsored Guest Portal.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Sponsored Guest Portal Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Sponsored Guest Portal.json", "w") as fh:
                    json.dump(sponsorGuestPortal, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(sponsorGuestPortal)
    except Exception as e:
        logging.exception(e)

# ----------------
# ISE Open APIs
# ----------------

def ISE_last_backup(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        lastBackup = requests.request("GET", f"{ url }/api/v1/backup-restore/config/last-backup-status", headers=headers, auth=(username, password), verify=False)
        lastBackupJSON = lastBackup.json()

        # Pass to template 

        if lastBackupJSON is not None:
            last_backup_template = env.get_template('ISE_last_backup.j2')
            loop_counter = 0          
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = last_backup_template.render(lastBackup = lastBackupJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Last Backup.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Last Backup Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Last Backup.json", "w") as fh:
                    json.dump(lastBackupJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(lastBackupJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_csr(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
    
        csrAll = requests.request("GET", f"{ url }/api/v1/certs/certificate-signing-request", headers=headers, auth=(username, password), verify=False)
        csrAllJSON = csrAll.json()

        # Pass to template 

        if csrAllJSON is not None:
            csr_template = env.get_template('ISE_csr.j2')
            loop_counter = 0
            csr = []
            if csrAllJSON['nextPage'] is not None: 
                for href in csrAllJSON:
                    csrHref = requests.request("GET", href['nextPage']['href'], headers=headers, auth=(username, password), verify=False)
                    csrHrefJSON = csrHref.json()
                    csr.append(csrHrefJSON['response'])          
            else:
                csr.append(csrAllJSON['response'])
        # Render Templates
                for filetype in filetype_loop:
                    parsed_output = csr_template.render(csr = csr,filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                    if loop_counter <= 3:
                        with open(f"ISE Certificate Signing Requests.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    else:
                        with open("ISE Certificate Signing Requests Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"ISE Certificate Signing Requests.json", "w") as fh:
                        json.dump(csr, fh, indent=4, sort_keys=True)
                        fh.close()                            
        return(csr)
    except Exception as e:
        logging.exception(e)

def ISE_system_certificates(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        nohttpurl = url.replace("https://","")
        certsAll = requests.request("GET", f"{ url }/api/v1/certs/system-certificate/{ nohttpurl }", headers=headers, auth=(username, password), verify=False)
        certsAllJSON = certsAll.json()

        # Pass to template 

        if certsAllJSON is not None:
            certs_template = env.get_template('ISE_system_certificates.j2')
            loop_counter = 0
            certs = []
            if certsAllJSON['nextPage'] is not None: 
                for href in certsAllJSON:
                    certsHref = requests.request("GET", href['nextPage']['href'], headers=headers, auth=(username, password), verify=False)
                    certsHrefJSON = certsHref.json()
                    certs.append(certsHrefJSON['response'])          
            else:
                certs.append(certsAllJSON['response'])
        # Render Templates
                for filetype in filetype_loop:
                    parsed_output = certs_template.render(certs = certs,filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                    if loop_counter <= 3:
                        with open(f"ISE System Certificates.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    else:
                        with open("ISE System Certificates Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"ISE System Certificates.json", "w") as fh:
                        json.dump(certs, fh, indent=4, sort_keys=True)
                        fh.close()                            
        return(certs)
    except Exception as e:
        logging.exception(e)

def ISE_trusted_certificates(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        trustedcertsAll = requests.request("GET", f"{ url }/api/v1/certs/trusted-certificate", headers=headers, auth=(username, password), verify=False)
        trustedcertsAllJSON = trustedcertsAll.json()

        # Pass to template 

        if trustedcertsAllJSON is not None:
            trusted_certs_template = env.get_template('ISE_trusted_certificates.j2')
            loop_counter = 0
            trustedcerts = []
            if trustedcertsAllJSON['nextPage'] is not None: 
                for href in certsAllJSON:
                    trustedcertsHref = requests.request("GET", href['nextPage']['href'], headers=headers, auth=(username, password), verify=False)
                    trustedcertsHrefJSON = trustedcertsHref.json()
                    trustedcerts.append(trustedcertsHrefJSON['response'])          
            else:
                trustedcerts.append(trustedcertsAllJSON['response'])
        # Render Templates
                for filetype in filetype_loop:
                    parsed_output = trusted_certs_template.render(trustedcerts = trustedcerts,filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                    if loop_counter <= 3:
                        with open(f"ISE Trusted Certificates.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    else:
                        with open("ISE Trusted Certificates Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"ISE Trusted Certificates.json", "w") as fh:
                        json.dump(trustedcerts, fh, indent=4, sort_keys=True)
                        fh.close()                            
        return(trustedcerts)
    except Exception as e:
        logging.exception(e)

def ISE_deployment_node(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        deploymentNodeAll = requests.request("GET", f"{ url }/api/v1/deployment/node", headers=headers, auth=(username, password), verify=False)
        deploymentNodeAllJSON = deploymentNodeAll.json()

        # Pass to template 

        if deploymentNodeAllJSON is not None:
            deployment_node_template = env.get_template('ISE_deployment_node.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = deployment_node_template.render(nodes = deploymentNodeAllJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Deployment Node.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Deployment Node Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Deployment Node.json", "w") as fh:
                    json.dump(deploymentNodeAllJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(deploymentNodeAllJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_pan_ha(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        panHA = requests.request("GET", f"{ url }/api/v1/deployment/pan-ha", headers=headers, auth=(username, password), verify=False)
        panHAJSON = panHA.json()

        # Pass to template 

        if panHAJSON is not None:
            panha_template = env.get_template('ISE_pan_ha.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = panha_template.render(panha = panHAJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE PAN High Availability.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE PAN High Availability Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE PAN High Availability.json", "w") as fh:
                    json.dump(panHAJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(panHAJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_node_interfaces(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        nohttpurl = url.replace("https://","")
        nodeInterfaces = requests.request("GET", f"{ url }/api/v1/node/{ nohttpurl }/interface", headers=headers, auth=(username, password), verify=False)
        nodeInterfacesJSON = nodeInterfaces.json()

        # Pass to template 

        if nodeInterfacesJSON is not None:
            nodeInterface_template = env.get_template('ISE_node_interfaces.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = nodeInterface_template.render(nodeInterfaces = nodeInterfacesJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Node Interfaces.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Node Interfaces Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Node Interfaces.json", "w") as fh:
                    json.dump(nodeInterfacesJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(nodeInterfacesJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_node_profile(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        nohttpurl = url.replace("https://","")
        nodeProfile = requests.request("GET", f"{ url }/api/v1/profile/{ nohttpurl }", headers=headers, auth=(username, password), verify=False)
        nodeProfileJSON = nodeProfile.json()

        # Pass to template 

        if nodeProfileJSON is not None:
            nodeProfile_template = env.get_template('ISE_node_profile.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = nodeProfile_template.render(nodeProfile = nodeProfileJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Node Profile.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Node Profile Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Node Profile.json", "w") as fh:
                    json.dump(nodeProfileJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(nodeProfileJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_license_connection_type(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        licenseCon = requests.request("GET", f"{ url }/api/v1/license/system/connection-type", headers=headers, auth=(username, password), verify=False)
        licenseConJSON = licenseCon.json()

        # Pass to template 

        if licenseConJSON is not None:
            licenseCon_template = env.get_template('ISE_license_connection_type.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = licenseCon_template.render(licenseCon = licenseConJSON,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE License Connection Type.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE License Connection Type Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE License Connection Type.json", "w") as fh:
                    json.dump(licenseConJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(licenseConJSON)
    except Exception as e:
        logging.exception(e)

def ISE_eval_license(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        evalLic = requests.request("GET", f"{ url }/api/v1/license/system/eval-license", headers=headers, auth=(username, password), verify=False)
        evalLicJSON = evalLic.json()

        # Pass to template 

        if evalLicJSON is not None:
            evalLic_template = env.get_template('ISE_eval_license.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = evalLic_template.render(evalLic = evalLicJSON,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Evaluation License.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Evaluation License Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Evaluation License Type.json", "w") as fh:
                    json.dump(evalLicJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(evalLicJSON)
    except Exception as e:
        logging.exception(e)

def ISE_license_feature_map(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        licFeature = requests.request("GET", f"{ url }/api/v1/license/system/feature-to-tier-mapping", headers=headers, auth=(username, password), verify=False)
        licFeatureJSON = licFeature.json()

        # Pass to template 

        if licFeatureJSON is not None:
            licFeature_template = env.get_template('ISE_license_feature.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = licFeature_template.render(licFeature = licFeatureJSON,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE License Tier Feature Mapping.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE License Tier Feature Mapping Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE License Tier Feature Mapping Type.json", "w") as fh:
                    json.dump(licFeatureJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(licFeatureJSON)
    except Exception as e:
        logging.exception(e)

def ISE_license_register(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        licRegister = requests.request("GET", f"{ url }/api/v1/license/system/register", headers=headers, auth=(username, password), verify=False)
        licRegisterJSON = licRegister.json()

        # Pass to template 

        if licRegisterJSON is not None:
            licRegister_template = env.get_template('ISE_license_register.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = licRegister_template.render(licRegister = licRegisterJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE License Register.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE License Register Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE License Register.json", "w") as fh:
                    json.dump(licRegisterJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(licRegisterJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_license_smart_state(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        licSmart = requests.request("GET", f"{ url }/api/v1/license/system/smart-state", headers=headers, auth=(username, password), verify=False)
        licSmartJSON = licSmart.json()

        # Pass to template 

        if licSmartJSON is not None:
            licSmart_template = env.get_template('ISE_license_smart_state.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = licSmart_template.render(licSmart = licSmartJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE License Smart State.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE License Smart State Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE License Smart State.json", "w") as fh:
                    json.dump(licSmartJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(licSmartJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_license_tier_state(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        licTier = requests.request("GET", f"{ url }/api/v1/license/system/tier-state", headers=headers, auth=(username, password), verify=False)
        licTierJSON = licTier.json()

        # Pass to template 

        if licTierJSON is not None:
            licTier_template = env.get_template('ISE_license_tier_state.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = licTier_template.render(licTier = licTierJSON,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE License Tier State.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE License Tier State Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE License Tier State.json", "w") as fh:
                    json.dump(licTierJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(licTierJSON)
    except Exception as e:
        logging.exception(e)

def ISE_patch(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        patch = requests.request("GET", f"{ url }/api/v1/patch", headers=headers, auth=(username, password), verify=False)
        patchJSON = patch.json()

        # Pass to template 

        if patchJSON is not None:
            patch_template = env.get_template('ISE_patch.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = patch_template.render(patch = patchJSON,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Patches.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Patches Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Patches.json", "w") as fh:
                    json.dump(patchJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(patchJSON)
    except Exception as e:
        logging.exception(e)

def ISE_hot_patch(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        hotPatch = requests.request("GET", f"{ url }/api/v1/hotpatch", headers=headers, auth=(username, password), verify=False)
        hotPatchJSON = hotPatch.json()

        # Pass to template 

        if hotPatchJSON is not None:
            hotPatch_template = env.get_template('ISE_hot_patch.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = hotPatch_template.render(hotPatch = hotPatchJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Hot Patches.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Hot Patches Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Hot Patches.json", "w") as fh:
                    json.dump(hotPatchJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(hotPatchJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_repository(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        repository = requests.request("GET", f"{ url }/api/v1/repository", headers=headers, auth=(username, password), verify=False)
        repositoryJSON = repository.json()

        # Pass to template 

        if repositoryJSON is not None:
            repository_template = env.get_template('ISE_repository.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = repository_template.render(repository = repositoryJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Repositories.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Repositories Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Repositories.json", "w") as fh:
                    json.dump(repositoryJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(repositoryJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_proxy(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        proxy = requests.request("GET", f"{ url }/api/v1/system-settings/proxy", headers=headers, auth=(username, password), verify=False)
        proxyJSON = proxy.json()

        # Pass to template 

        if proxyJSON is not None:
            proxy_template = env.get_template('ISE_proxy.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = proxy_template.render(proxy = proxyJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Proxy.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Proxy Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Proxy.json", "w") as fh:
                    json.dump(proxyJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(proxyJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_transport_gateway(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        transportGateway = requests.request("GET", f"{ url }/api/v1/system-settings/telemetry/transport-gateway", headers=headers, auth=(username, password), verify=False)
        transportGatewayJSON = transportGateway.json()

        # Pass to template 

        if transportGatewayJSON is not None:
            transportGateway_template = env.get_template('ISE_transport_gateway.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = transportGateway_template.render(transportGateway = transportGatewayJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Proxy.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Proxy Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Proxy.json", "w") as fh:
                    json.dump(transportGatewayJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(transportGatewayJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_nbar_app(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        nbarApp = requests.request("GET", f"{ url }/api/v1/trustsec/sgacl/nbarapp/", headers=headers, auth=(username, password), verify=False)
        nbarAppJSON = nbarApp.json()

        # Pass to template 

        if nbarAppJSON is not None:
            nbarApp_template = env.get_template('ISE_nbar_apps.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = nbarApp_template.render(nbarApp = nbarAppJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE NBAR Applications.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE NBAR Applications Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE NBAR Applications.json", "w") as fh:
                    json.dump(nbarAppJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(nbarAppJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_command_set(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        commandSet = requests.request("GET", f"{ url }/api/v1/policy/device-admin/command-sets", headers=headers, auth=(username, password), verify=False)
        commandSetJSON = commandSet.json()

        # Pass to template 

        if commandSetJSON is not None:
            commandSet_template = env.get_template('ISE_command_set.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = commandSet_template.render(commandSet = commandSetJSON,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Command Set.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Command Set Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Command Set.json", "w") as fh:
                    json.dump(commandSetJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(commandSetJSON)
    except Exception as e:
        logging.exception(e)

def ISE_condition(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        condition = requests.request("GET", f"{ url }/api/v1/policy/device-admin/condition", headers=headers, auth=(username, password), verify=False)
        conditionJSON = condition.json()

        # Pass to template 

        if conditionJSON is not None:
            condition_template = env.get_template('ISE_condition.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = condition_template.render(condition = conditionJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Conditions.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Conditions Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Conditions.json", "w") as fh:
                    json.dump(conditionJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(conditionJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_authentication_dictionary(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        authDictionary = requests.request("GET", f"{ url }/api/v1/policy/device-admin/dictionaries/authentication", headers=headers, auth=(username, password), verify=False)
        authDictionaryJSON = authDictionary.json()

        # Pass to template 

        if authDictionaryJSON is not None:
            authDictionary_template = env.get_template('ISE_authentication_dictionary.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = authDictionary_template.render(authDictionary = authDictionaryJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Dictionary Authentication.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Dictionary Authentication Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Dictionary Authentication.json", "w") as fh:
                    json.dump(authDictionaryJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(authDictionaryJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_authorization_dictionary(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        authDictionary = requests.request("GET", f"{ url }/api/v1/policy/device-admin/dictionaries/authorization", headers=headers, auth=(username, password), verify=False)
        authDictionaryJSON = authDictionary.json()

        # Pass to template 

        if authDictionaryJSON is not None:
            authDictionary_template = env.get_template('ISE_authorization_dictionary.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = authDictionary_template.render(authDictionary = authDictionaryJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Dictionary Authorization.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Dictionary Authorization Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Dictionary Authorization.json", "w") as fh:
                    json.dump(authDictionaryJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(authDictionaryJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_policy_set_dictionary(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        authDictionary = requests.request("GET", f"{ url }/api/v1/policy/device-admin/dictionaries/policyset", headers=headers, auth=(username, password), verify=False)
        authDictionaryJSON = authDictionary.json()

        # Pass to template 

        if authDictionaryJSON is not None:
            authDictionary_template = env.get_template('ISE_policy_set_dictionary.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = authDictionary_template.render(authDictionary = authDictionaryJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Dictionary Policy Set.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Dictionary Policy Set Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Dictionary Policy Set.json", "w") as fh:
                    json.dump(authDictionaryJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(authDictionaryJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_identity_stores(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        identityStores = requests.request("GET", f"{ url }/api/v1/policy/device-admin/identity-stores", headers=headers, auth=(username, password), verify=False)
        identityStoresJSON = identityStores.json()

        # Pass to template 

        if identityStoresJSON is not None:
            identityStores_template = env.get_template('ISE_identity_stores.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = identityStores_template.render(identityStores = identityStoresJSON,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Identity Stores.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Identity Stores Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Identity Stores.json", "w") as fh:
                    json.dump(identityStoresJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(identityStoresJSON)
    except Exception as e:
        logging.exception(e)

def ISE_policy_sets(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        policySets = requests.request("GET", f"{ url }/api/v1/policy/device-admin/policy-set", headers=headers, auth=(username, password), verify=False)
        policySetsJSON = policySets.json()

        # Pass to template 

        if policySetsJSON is not None:
            policySets_template = env.get_template('ISE_policy_sets.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = policySets_template.render(policySets = policySetsJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Policy Sets.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Policy Sets Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Policy Sets.json", "w") as fh:
                    json.dump(policySetsJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(policySetsJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_authentication_policy_sets(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        policySets = requests.request("GET", f"{ url }/api/v1/policy/device-admin/policy-set", headers=headers, auth=(username, password), verify=False)
        policySetsJSON = policySets.json()

        # Pass to template 

        if policySetsJSON is not None:
            for policy in policySetsJSON['response']:
                policy = requests.request("GET", f"{ url }/api/v1/policy/device-admin/policy-set/{ policy['id']}/authentication", headers=headers, auth=(username, password), verify=False)
                policyJSON = policy.json()                

                if policySetsJSON is not None:
                    policy_template = env.get_template('ISE_authentication_policy_set.j2')
                    loop_counter = 0

        # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = policy_template.render(policy = policyJSON['response'],filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"ISE Authentication Policy Sets.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open("ISE Authentication Policy Sets Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"ISE Authentication Policy Sets.json", "w") as fh:
                            json.dump(policyJSON['response'], fh, indent=4, sort_keys=True)
                            fh.close()                            
        return(policyJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_authorization_policy_sets(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        policySets = requests.request("GET", f"{ url }/api/v1/policy/device-admin/policy-set", headers=headers, auth=(username, password), verify=False)
        policySetsJSON = policySets.json()

        # Pass to template 

        if policySetsJSON is not None:
            for policy in policySetsJSON['response']:
                policy = requests.request("GET", f"{ url }/api/v1/policy/device-admin/policy-set/{ policy['id']}/authorization", headers=headers, auth=(username, password), verify=False)
                policyJSON = policy.json()                

                if policySetsJSON is not None:
                    policy_template = env.get_template('ISE_authorization_policy_set.j2')
                    loop_counter = 0

        # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = policy_template.render(policy = policyJSON['response'],filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"ISE Authorization Policy Sets.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open("ISE Authorization Policy Sets Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"ISE Authorization Policy Sets.json", "w") as fh:
                            json.dump(policyJSON['response'], fh, indent=4, sort_keys=True)
                            fh.close()                            
        return(policyJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_service_names(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        serviceNames = requests.request("GET", f"{ url }/api/v1/policy/device-admin/service-names", headers=headers, auth=(username, password), verify=False)
        serviceNamesJSON = serviceNames.json()

        # Pass to template 

        if serviceNamesJSON is not None:
            serviceNames_template = env.get_template('ISE_service_names.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = serviceNames_template.render(serviceNames = serviceNamesJSON,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Service Names.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Service Names Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Service Names.json", "w") as fh:
                    json.dump(serviceNamesJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(serviceNamesJSON)
    except Exception as e:
        logging.exception(e)

def ISE_shell_profiles(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        shellProfiles = requests.request("GET", f"{ url }/api/v1/policy/device-admin/shell-profiles", headers=headers, auth=(username, password), verify=False)
        shellProfilesJSON = shellProfiles.json()

        # Pass to template 

        if shellProfilesJSON is not None:
            shellProfiles_template = env.get_template('ISE_shell_profiles.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = shellProfiles_template.render(shellProfiles = shellProfilesJSON,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Shell Profiles.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Shell Profiles Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Shell Profiles.json", "w") as fh:
                    json.dump(shellProfilesJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(shellProfilesJSON)
    except Exception as e:
        logging.exception(e)

def ISE_network_authorization_profiles(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        authProfiles = requests.request("GET", f"{ url }/api/v1/policy/network-access/authorization-profiles", headers=headers, auth=(username, password), verify=False)
        authProfilesJSON = authProfiles.json()

        # Pass to template 

        if authProfilesJSON is not None:
            authProfiles_template = env.get_template('ISE_network_authorization_profiles.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = authProfiles_template.render(authProfiles = authProfilesJSON,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Network Authorization Profiles.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Network Authorization Profiles Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Network Authorization Profiles.json", "w") as fh:
                    json.dump(authProfilesJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(authProfilesJSON)
    except Exception as e:
        logging.exception(e)

def ISE_network_access_condition(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        networkCondition = requests.request("GET", f"{ url }/api/v1/policy/network-access/condition", headers=headers, auth=(username, password), verify=False)
        networkConditionJSON = networkCondition.json()

        # Pass to template 

        if networkConditionJSON is not None:
            networkCondition_template = env.get_template('ISE_network_condition.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = networkCondition_template.render(networkCondition = networkConditionJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Network Access Conditions.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Network Access Conditions Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Network Access Conditions.json", "w") as fh:
                    json.dump(networkConditionJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(networkConditionJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_network_access_condition_authentication(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        networkCondition = requests.request("GET", f"{ url }/api/v1/policy/network-access/condition/authentication", headers=headers, auth=(username, password), verify=False)
        networkConditionJSON = networkCondition.json()

        # Pass to template 

        if networkConditionJSON is not None:
            networkCondition_template = env.get_template('ISE_network_condition.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = networkCondition_template.render(networkCondition = networkConditionJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Network Access Conditions Authentication.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Network Access Conditions Authentication Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Network Access Conditions Authentication.json", "w") as fh:
                    json.dump(networkConditionJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(networkConditionJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_network_access_condition_authorization(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        networkCondition = requests.request("GET", f"{ url }/api/v1/policy/network-access/condition/authorization", headers=headers, auth=(username, password), verify=False)
        networkConditionJSON = networkCondition.json()

        # Pass to template 

        if networkConditionJSON is not None:
            networkCondition_template = env.get_template('ISE_network_condition.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = networkCondition_template.render(networkCondition = networkConditionJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Network Access Conditions Authorization.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Network Access Conditions Authorization Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Network Access Conditions Authorization.json", "w") as fh:
                    json.dump(networkConditionJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(networkConditionJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_network_access_condition_policy_set(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        networkCondition = requests.request("GET", f"{ url }/api/v1/policy/network-access/condition/policyset", headers=headers, auth=(username, password), verify=False)
        networkConditionJSON = networkCondition.json()

        # Pass to template 

        if networkConditionJSON is not None:
            networkCondition_template = env.get_template('ISE_network_condition.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = networkCondition_template.render(networkCondition = networkConditionJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Network Access Conditions Policy Set.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Network Access Conditions Policy Set Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Network Access Conditions Policy Set.json", "w") as fh:
                    json.dump(networkConditionJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(networkConditionJSON['response'])
    except Exception as e:
        logging.exception(e)                

def ISE_network_access_dictionaries(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        networkDictionaries = requests.request("GET", f"{ url }/api/v1/policy/network-access/dictionaries", headers=headers, auth=(username, password), verify=False)
        networkDictionariesJSON = networkDictionaries.json()

        # Pass to template 

        if networkDictionariesJSON is not None:
            networkDictionaries_template = env.get_template('ISE_network_dictionaries.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = networkDictionaries_template.render(networkDictionaries = networkDictionariesJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Network Access Dictionaries.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Network Access Dictionaries Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Network Access Dictionaries.json", "w") as fh:
                    json.dump(networkDictionariesJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(networkDictionariesJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_network_access_dictionaries_authentication(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        networkDictionariesAuthentication = requests.request("GET", f"{ url }/api/v1/policy/network-access/dictionaries/authentication", headers=headers, auth=(username, password), verify=False)
        networkDictionariesAuthenticationJSON = networkDictionariesAuthentication.json()

        # Pass to template 

        if networkDictionariesAuthenticationJSON is not None:
            networkDictionariesAuthentication_template = env.get_template('ISE_network_dictionaries_authentication.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = networkDictionariesAuthentication_template.render(networkDictionaries = networkDictionariesAuthenticationJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Network Access Dictionaries Authentication.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Network Access Dictionaries Authentication Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Network Access Dictionaries Authentication.json", "w") as fh:
                    json.dump(networkDictionariesAuthenticationJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(networkDictionariesAuthenticationJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_network_access_dictionaries_authorization(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        networkDictionariesAuthorization = requests.request("GET", f"{ url }/api/v1/policy/network-access/dictionaries/authorization", headers=headers, auth=(username, password), verify=False)
        networkDictionariesAuthorizationJSON = networkDictionariesAuthorization.json()

        # Pass to template 

        if networkDictionariesAuthorizationJSON is not None:
            networkDictionariesAuthorization_template = env.get_template('ISE_network_dictionaries_authentication.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = networkDictionariesAuthorization_template.render(networkDictionaries = networkDictionariesAuthorizationJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Network Access Dictionaries Authorization.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Network Access Dictionaries Authorization Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Network Access Dictionaries Authorization.json", "w") as fh:
                    json.dump(networkDictionariesAuthorizationJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(networkDictionariesAuthorizationJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_network_access_dictionaries_policy_set(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        networkDictionariesPolicy = requests.request("GET", f"{ url }/api/v1/policy/network-access/dictionaries/policyset", headers=headers, auth=(username, password), verify=False)
        networkDictionariesPolicyJSON = networkDictionariesPolicy.json()

        # Pass to template 

        if networkDictionariesPolicyJSON is not None:
            networkDictionariesPolicy_template = env.get_template('ISE_network_dictionaries_authentication.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = networkDictionariesPolicy_template.render(networkDictionaries = networkDictionariesPolicyJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Network Access Dictionaries Policy Set.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Network Access Dictionaries Policy Set Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Network Access Dictionaries Policy Set.json", "w") as fh:
                    json.dump(networkDictionariesPolicyJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(networkDictionariesPolicyJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_network_access_identity_stores(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        networkIdentity = requests.request("GET", f"{ url }/api/v1/policy/network-access/identity-stores", headers=headers, auth=(username, password), verify=False)
        networkIdentityJSON = networkIdentity.json()

        # Pass to template 

        if networkIdentityJSON is not None:
            networkIdentity_template = env.get_template('ISE_network_identity_stores.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = networkIdentity_template.render(networkIdentity = networkIdentityJSON,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Network Access Identity Stores.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Network Access Identity Stores Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Network Access Identity Stores.json", "w") as fh:
                    json.dump(networkIdentityJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(networkIdentityJSON)
    except Exception as e:
        logging.exception(e)

def ISE_network_access_policy_set(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        networkAccessPolicySet = requests.request("GET", f"{ url }/api/v1/policy/network-access/policy-set", headers=headers, auth=(username, password), verify=False)
        networkAccessPolicySetJSON = networkAccessPolicySet.json()

        # Pass to template 

        if networkAccessPolicySetJSON is not None:
            networkAccessPolicySet_template = env.get_template('ISE_network_access_policy_set.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = networkAccessPolicySet_template.render(networkAccessPolicySet = networkAccessPolicySetJSON['response'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Network Access Policy Sets.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Network Access Policy Sets Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Network Access Policy Sets.json", "w") as fh:
                    json.dump(networkAccessPolicySetJSON['response'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(networkAccessPolicySetJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_network_access_policy_authentication(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        networkAccessPolicySet = requests.request("GET", f"{ url }/api/v1/policy/network-access/policy-set", headers=headers, auth=(username, password), verify=False)
        networkAccessPolicySetJSON = networkAccessPolicySet.json()

        # Pass to template 

        if networkAccessPolicySetJSON is not None:
            for policy in networkAccessPolicySetJSON['response']:
                authPolicy = requests.request("GET", f"{ url }/api/v1/policy/network-access/policy-set/{ policy['id'] }/authentication", headers=headers, auth=(username, password), verify=False)
                authPolicyJSON = authPolicy.json()

                if authPolicyJSON is not None:
                    networkAccessPolicySet_template = env.get_template('ISE_network_access_policy_authentication.j2')
                    loop_counter = 0

        # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = networkAccessPolicySet_template.render(networkAccessPolicySet = authPolicyJSON['response'],filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"ISE Network Access Policy Set Authentication.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open("ISE Network Access Policy Set Authentication Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"ISE Network Access Policy Set Authentication.json", "w") as fh:
                            json.dump(authPolicyJSON['response'], fh, indent=4, sort_keys=True)
                            fh.close()                            
        return(authPolicyJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_network_access_policy_authorization(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        networkAccessPolicySet = requests.request("GET", f"{ url }/api/v1/policy/network-access/policy-set", headers=headers, auth=(username, password), verify=False)
        networkAccessPolicySetJSON = networkAccessPolicySet.json()

        # Pass to template 

        if networkAccessPolicySetJSON is not None:
            for policy in networkAccessPolicySetJSON['response']:
                authPolicy = requests.request("GET", f"{ url }/api/v1/policy/network-access/policy-set/{ policy['id'] }/authorization", headers=headers, auth=(username, password), verify=False)
                authPolicyJSON = authPolicy.json()

                if authPolicyJSON is not None:
                    networkAccessPolicySet_template = env.get_template('ISE_network_access_policy_authorization.j2')
                    loop_counter = 0

        # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = networkAccessPolicySet_template.render(networkAccessPolicySet = authPolicyJSON['response'],filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"ISE Network Access Policy Set Authorization.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open("ISE Network Access Policy Set Authorization Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"ISE Network Access Policy Set Authorization.json", "w") as fh:
                            json.dump(authPolicyJSON['response'], fh, indent=4, sort_keys=True)
                            fh.close()                            
        return(authPolicyJSON['response'])
    except Exception as e:
        logging.exception(e)

def ISE_network_access_security_groups(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        networkAccessSecurityGroup = requests.request("GET", f"{ url }/api/v1/policy/network-access/security-groups", headers=headers, auth=(username, password), verify=False)
        networkAccessSecurityGroupJSON = networkAccessSecurityGroup.json()

        # Pass to template 

        if networkAccessSecurityGroupJSON is not None:
            networkAccessSecurityGroup_template = env.get_template('ISE_network_access_security_groups.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = networkAccessSecurityGroup_template.render(networkAccessSecurityGroup = networkAccessSecurityGroupJSON,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Network Access Security Groups.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Network Access Security Groups Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Network Access Security Groups.json", "w") as fh:
                    json.dump(networkAccessSecurityGroupJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(networkAccessSecurityGroupJSON)
    except Exception as e:
        logging.exception(e)

def ISE_network_access_service_names(url, username, password):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        }
        networkAccessServiceNames = requests.request("GET", f"{ url }/api/v1/policy/network-access/service-names", headers=headers, auth=(username, password), verify=False)
        networkAccessServiceNamesJSON = networkAccessServiceNames.json()

        # Pass to template 

        if networkAccessServiceNamesJSON is not None:
            networkAccessServiceNames_template = env.get_template('ISE_network_access_service_names.j2')
            loop_counter = 0

        # Render Templates
            for filetype in filetype_loop:
                parsed_output = networkAccessServiceNames_template.render(networkAccessServiceNames = networkAccessServiceNamesJSON,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Network Access Security Groups.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Network Access Security Groups Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Network Access Security Groups.json", "w") as fh:
                    json.dump(networkAccessServiceNamesJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(networkAccessServiceNamesJSON)
    except Exception as e:
        logging.exception(e)

# ----------------
# ISE MnT
# ----------------

def ISE_active_sessions(url, username, password):
    try:   
        activeSessionCount = requests.request("GET", f"{ url }/admin/API/mnt/Session/ActiveCount", auth=(username, password), verify=False)
        xmlParse = xmltodict.parse(activeSessionCount.text)
        activeSessionCountJSON = json.loads(json.dumps(xmlParse))

        # Pass to template 

        if activeSessionCountJSON is not None:
            active_session_template = env.get_template('ISE_active_sessions.j2')
            loop_counter = 0      
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = active_session_template.render(activeSessionCount = activeSessionCountJSON,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Active Sessions.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Active Sessions Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Active Sessions.json", "w") as fh:
                    json.dump(activeSessionCountJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(activeSessionCountJSON)
    except Exception as e:
        logging.exception(e)

def ISE_posture_count(url, username, password):
    try:   
        postureCount = requests.request("GET", f"{ url }/admin/API/mnt/Session/PostureCount", auth=(username, password), verify=False)
        xmlParse = xmltodict.parse(postureCount.text)
        postureCountJSON = json.loads(json.dumps(xmlParse))
        # Pass to template 

        if postureCountJSON is not None:
            posture_count_template = env.get_template('ISE_posture_count.j2')
            loop_counter = 0      
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = posture_count_template.render(postureCount = postureCountJSON,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Posture Count.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Posture Count Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Posture Count.json", "w") as fh:
                    json.dump(postureCountJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(postureCountJSON)
    except Exception as e:
        logging.exception(e)

def ISE_profiler_count(url, username, password):
    try:   
        profilerCount = requests.request("GET", f"{ url }/admin/API/mnt/Session/ProfilerCount", auth=(username, password), verify=False)
        xmlParse = xmltodict.parse(profilerCount.text)
        profilerCountJSON = json.loads(json.dumps(xmlParse))
        # Pass to template 

        if profilerCountJSON is not None:
            profiler_count_template = env.get_template('ISE_profiler_count.j2')
            loop_counter = 0      
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = profiler_count_template.render(profilerCount = profilerCountJSON,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Profiler Count.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Profiler Count Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Profiler Count.json", "w") as fh:
                    json.dump(profilerCountJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(profilerCountJSON)
    except Exception as e:
        logging.exception(e)

def ISE_version(url, username, password):
    try:   
        version = requests.request("GET", f"{ url }/admin/API/mnt/Version", auth=(username, password), verify=False)
        xmlParse = xmltodict.parse(version.text)
        versionJSON = json.loads(json.dumps(xmlParse))
        # Pass to template 

        if versionJSON is not None:
            version_template = env.get_template('ISE_version.j2')
            loop_counter = 0      
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = version_template.render(version = versionJSON,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Version.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Version Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Version.json", "w") as fh:
                    json.dump(versionJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(versionJSON)
    except Exception as e:
        logging.exception(e)

def ISE_failure_codes(url, username, password):
    try:   
        failureCodes = requests.request("GET", f"{ url }/admin/API/mnt/FailureReasons", auth=(username, password), verify=False)
        xmlParse = xmltodict.parse(failureCodes.text)
        failureCodesJSON = json.loads(json.dumps(xmlParse))
        # Pass to template 

        if failureCodesJSON is not None:
            failureCodes_template = env.get_template('ISE_failure_codes.j2')
            loop_counter = 0      
            
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = failureCodes_template.render(failureCodes = failureCodesJSON['failureReasonList'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"ISE Failure Codes.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("ISE Failure Codes Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"ISE Failure Codes.json", "w") as fh:
                    json.dump(failureCodesJSON['failureReasonList'], fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(failureCodesJSON['failureReasonList'])
    except Exception as e:
        logging.exception(e)

# -------------------------
# Meraki REST APIs
# -------------------------

# ----------------
# Meraki ALL
# ----------------

def Meraki_all(url, token):
    Meraki_organizations(url, token)
    Meraki_organization_devices(url, token)
    Meraki_organization_licenses(url, token)
    Meraki_organization_adaptive_policies(url, token)
    Meraki_organization_admins(url, token)
    Meraki_organization_alert_profiles(url, token)
    Meraki_organization_branding_policy(url, token)
    Meraki_organization_clients(url, token)
    return("All Meraki APIs Converted to Business Ready Documents")

def Meraki_organizations(url, token):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Cisco-Meraki-API-Key': token,
        }
    
        organizationsRAW = requests.request("GET", f"{ url }/api/v1/organizations", headers=headers)
        organizationsJSON = organizationsRAW.json()

        # Pass to template 

        if organizationsJSON is not None:
            organization_template = env.get_template('Meraki_organizations.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = organization_template.render(organizations = organizationsJSON,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"Meraki Organizations.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open("Meraki Organizations Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"Meraki Organizations.json", "w") as fh:
                    json.dump(organizationsJSON, fh, indent=4, sort_keys=True)
                    fh.close()                            
        return(organizationsJSON)
    except Exception as e:
        logging.exception(e)

def Meraki_organization_licenses(url, token):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Cisco-Meraki-API-Key': token,
        }
    
        organizationsRAW = requests.request("GET", f"{ url }/api/v1/organizations", headers=headers)
        organizationsJSON = organizationsRAW.json()

        # Pass to template 

        if organizationsJSON is not None:
            for org in organizationsJSON:              
                if org['licensing']['model'] == "per-device":
        
        # -------------------------
        # create folders to hold files
        # -------------------------
                    if not os.path.exists(f"{ org['name'] }"):
                        os.mkdir(f"{ org['name'] }")
                    else:
                        print("Directory already exists")                     
        
                    organizationLicensesRAW = requests.request("GET", f"{ url }/api/v1/organizations/{ org['id'] }/licenses", headers=headers)
                    organizationLicensesJSON = organizationLicensesRAW.json()

                    if organizationLicensesJSON is not None:
                        organization_license_template = env.get_template('Meraki_organization_licenses.j2')
                        loop_counter = 0
        # Render Templates
                        for filetype in filetype_loop:
                            parsed_output = organization_license_template.render(license = organizationLicensesJSON,filetype_loop=loop_counter)
                            loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                            if loop_counter <= 3:
                                with open(f"{ org['name'] }/Meraki { org['name'] } Licenses.{ filetype }", "w") as fh:
                                    fh.write(parsed_output)               
                                    fh.close()
                            else:
                                with open(f"{ org['name'] }/Meraki { org['name'] } Licenses Mind Map.md", "w") as fh:
                                    fh.write(parsed_output)               
                                    fh.close()
                            with open(f"{ org['name'] }/Meraki { org['name'] } Licenses.json", "w") as fh:
                                json.dump(organizationLicensesJSON, fh, indent=4, sort_keys=True)
                                fh.close()                            
        return(organizationLicensesJSON)
    except Exception as e:
        logging.exception(e)

def Meraki_organization_adaptive_policies(url, token):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Cisco-Meraki-API-Key': token,
        }
    
        organizationsRAW = requests.request("GET", f"{ url }/api/v1/organizations", headers=headers)
        organizationsJSON = organizationsRAW.json()

        # Pass to template 

        if organizationsJSON is not None:
            for org in organizationsJSON:                     
    
                organizationAdaptivePoliciesRAW = requests.request("GET", f"{ url }/api/v1/organizations/{ org['id'] }/adaptivePolicy/acls", headers=headers)
                organizationAdaptivePoliciesJSON = organizationAdaptivePoliciesRAW.json()

                if organizationAdaptivePoliciesJSON != []:
        # -------------------------
        # create folders to hold files
        # -------------------------
                    if not os.path.exists(f"{ org['name'] }"):
                        os.mkdir(f"{ org['name'] }")
                    else:
                        print("Directory already exists")                      

                    organization_adaptive_policy_template = env.get_template('Meraki_organization_adaptive_policies.j2')
                    loop_counter = 0

        # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = organization_adaptive_policy_template.render(adaptivePolicies = organizationAdaptivePoliciesJSON,filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"{ org['name'] }/Meraki { org['name'] } Adaptive Policy ACLs.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open(f"{ org['name'] }/Meraki { org['name'] } Adaptive Policy ACLs Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"{ org['name'] }/Meraki { org['name'] } Adaptive Policy ACLs.json", "w") as fh:
                            json.dump(organizationAdaptivePoliciesJSON, fh, indent=4, sort_keys=True)
                            fh.close()                            
        return(organizationAdaptivePoliciesJSON)
    except Exception as e:
        logging.exception(e)

def Meraki_organization_admins(url, token):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Cisco-Meraki-API-Key': token,
        }
    
        organizationsRAW = requests.request("GET", f"{ url }/api/v1/organizations", headers=headers)
        organizationsJSON = organizationsRAW.json()

        # Pass to template 

        if organizationsJSON is not None:
            for org in organizationsJSON:                     
    
                organizationAdminsRAW = requests.request("GET", f"{ url }/api/v1/organizations/{ org['id'] }/admins", headers=headers)
                organizationAdminsJSON = organizationAdminsRAW.json()

                if organizationAdminsJSON != []:
        # -------------------------
        # create folders to hold files
        # -------------------------
                    if not os.path.exists(f"{ org['name'] }"):
                        os.mkdir(f"{ org['name'] }")
                    else:
                        print("Directory already exists")                      
                        
                    organization_admins_template = env.get_template('Meraki_organization_admins.j2')
                    loop_counter = 0

        # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = organization_admins_template.render(admins = organizationAdminsJSON,filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"{ org['name'] }/Meraki { org['name'] } Admins.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open(f"{ org['name'] }/Meraki { org['name'] } Admins Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"{ org['name'] }/Meraki { org['name'] } Admins.json", "w") as fh:
                            json.dump(organizationAdminsJSON, fh, indent=4, sort_keys=True)
                            fh.close()                            
        return(organizationAdminsJSON)
    except Exception as e:
        logging.exception(e)

def Meraki_organization_alert_profiles(url, token):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Cisco-Meraki-API-Key': token,
        }
    
        organizationsRAW = requests.request("GET", f"{ url }/api/v1/organizations", headers=headers)
        organizationsJSON = organizationsRAW.json()

        # Pass to template 

        if organizationsJSON is not None:
            for org in organizationsJSON:                     
    
                organizationAlertProfilesRAW = requests.request("GET", f"{ url }/api/v1/organizations/{ org['id'] }/alerts/profiles", headers=headers)
                organizationAlertProfilesJSON = organizationAlertProfilesRAW.json()

                if organizationAlertProfilesJSON != []:
        # -------------------------
        # create folders to hold files
        # -------------------------
                    if not os.path.exists(f"{ org['name'] }"):
                        os.mkdir(f"{ org['name'] }")
                    else:
                        print("Directory already exists")                      
                        
                    organization_alert_profiles_template = env.get_template('Meraki_organization_alert_profiles.j2')
                    loop_counter = 0

        # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = organization_alert_profiles_template.render(alertProfiles = organizationAlertProfilesJSON,filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"{ org['name'] }/Meraki { org['name'] } Alert Profiles.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open(f"{ org['name'] }/Meraki { org['name'] } Alert Profiles Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"{ org['name'] }/Meraki { org['name'] } Alert Profiles.json", "w") as fh:
                            json.dump(organizationAlertProfilesJSON, fh, indent=4, sort_keys=True)
                            fh.close()                            
        return(organizationAlertProfilesJSON)
    except Exception as e:
        logging.exception(e)

def Meraki_organization_branding_policy(url, token):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Cisco-Meraki-API-Key': token,
        }
    
        organizationsRAW = requests.request("GET", f"{ url }/api/v1/organizations", headers=headers)
        organizationsJSON = organizationsRAW.json()

        # Pass to template 

        if organizationsJSON is not None:
            for org in organizationsJSON:                     
    
                organizationBrandingPolicyRAW = requests.request("GET", f"{ url }/api/v1/organizations/{ org['id'] }/brandingPolicies", headers=headers)
                organizationBrandingPolicyJSON = organizationBrandingPolicyRAW.json()
                
                if "errors" not in organizationBrandingPolicyJSON:
                    print(organizationBrandingPolicyJSON)
        # -------------------------
        # create folders to hold files
        # -------------------------
                    if not os.path.exists(f"{ org['name'] }"):
                        os.mkdir(f"{ org['name'] }")
                    else:
                        print("Directory already exists")                      
                        
                    organization_branding_policy_template = env.get_template('Meraki_organization_branding_policy.j2')
                    loop_counter = 0

        # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = organization_branding_policy_template.render(brandingPolicy = organizationBrandingPolicyJSON,filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"{ org['name'] }/Meraki { org['name'] } Branding Policy.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open(f"{ org['name'] }/Meraki { org['name'] } Branding Policy Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"{ org['name'] }/Meraki { org['name'] } Branding Policy.json", "w") as fh:
                            json.dump(organizationBrandingPolicyJSON, fh, indent=4, sort_keys=True)
                            fh.close()                            
        return(organizationBrandingPolicyJSON)
    except Exception as e:
        logging.exception(e)

def Meraki_organization_clients(url, token):
    try:

        headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Cisco-Meraki-API-Key': token,
        }
    
        organizationsRAW = requests.request("GET", f"{ url }/api/v1/organizations", headers=headers)
        organizationsJSON = organizationsRAW.json()

        # Pass to template 

        if organizationsJSON is not None:
            for org in organizationsJSON:                     
    
                organizationClientsRAW = requests.request("GET", f"{ url }/api/v1/organizations/{ org['id'] }/clients/search", headers=headers)
                organizationClientsJSON = organizationClientsRAW.json()

                if organizationClientsJSON != []:
        # -------------------------
        # create folders to hold files
        # -------------------------
                    if not os.path.exists(f"{ org['name'] }"):
                        os.mkdir(f"{ org['name'] }")
                    else:
                        print("Directory already exists")                      
                        
                    organization_clients_template = env.get_template('Meraki_organization_clients.j2')
                    loop_counter = 0

        # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = organization_clients_template.render(clients = organizationClientsJSON,filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"{ org['name'] }/Meraki { org['name'] } Clients.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open(f"{ org['name'] }/Meraki { org['name'] } Clients Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"{ org['name'] }/Meraki { org['name'] } Clients.json", "w") as fh:
                            json.dump(organizationClientsJSON, fh, indent=4, sort_keys=True)
                            fh.close()                            
        return(organizationClientsJSON)
    except Exception as e:
        logging.exception(e)

# ----------------
# IOS ALL
# ----------------

def IOS_all(hostname, username, password, ip):
    IOS_learn_all(hostname, username, password, ip)
    IOS_show_all(hostname, username, password, ip)
    return("All Functions Converted to Business Ready Documents")

# ----------------
# IOS LEARN SECTION
# ----------------

def IOS_learn_all(hostname, username, password, ip):
    IOS_learn_acl(hostname, username, password, ip)
    IOS_learn_arp(hostname, username, password, ip)
    IOS_learn_bgp(hostname, username, password, ip)
    IOS_learn_dot1x(hostname, username, password, ip)
    IOS_learn_hsrp(hostname, username, password, ip)
    IOS_learn_interface(hostname, username, password, ip)
    IOS_learn_lldp(hostname, username, password, ip)
    IOS_learn_ntp(hostname, username, password, ip)
    IOS_learn_ospf(hostname, username, password, ip)  
    IOS_learn_routing(hostname, username, password, ip)
    IOS_learn_stp(hostname, username, password, ip)
    IOS_learn_vlan(hostname, username, password, ip)
    IOS_learn_vrf(hostname, username, password, ip)
    return("learn All Functions")

def IOS_learn_acl(hostname, username, password, ip):
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
            try:
                learn_acl = device.learn("acl").info
            except:
                learn_acl = f"{ hostname } Has NO ACLs to Learn"

        # Pass to template 

        if learn_acl != f"{ hostname } Has NO ACLs to Learn":
            IOS_learn_acl_template = env.get_template('IOS_learn_acl.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learn_acl_template.render(to_parse_access_list=learn_acl['acls'],filetype_loop=loop_counter)
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
                with open(f"{ filename }_Learn ACL.json", "w") as fh:
                    json.dump(learn_acl, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_acl)
    except Exception as e:
        logging.exception(e)

def IOS_learn_arp(hostname, username, password, ip):
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

        # Learn ARP to JSON

            try:
                learn_arp = device.learn("arp").info
            except:
                learn_arp = f"{ hostname } has no ARP to Learn"

        # Pass to template 

        if learn_arp != f"{ hostname } has no ARP to Learn":
            IOS_learn_arp_template = env.get_template('IOS_learn_arp.j2')
            IOS_learn_arp_statistics_template = env.get_template('IOS_learn_arp_statistics.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output_statistics = IOS_learn_arp_statistics_template.render(to_parse_arp=learn_arp['statistics'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1
        # -------------------------
        # Save the files
        # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn ARP Statistics.{ filetype }", "w") as fh:
                        fh.write(parsed_output_statistics)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn ARP Statistics Mind Map.md", "w") as fh:
                        fh.write(parsed_output_statistics)               
                        fh.close()
                with open(f"{ filename }_Learn ARP Statistics.json", "w") as fh:
                    json.dump(learn_arp['statistics'], fh, indent=4, sort_keys=True)
                    fh.close()

        # Render Templates
            loop_counter = 0
            for filetype in filetype_loop:
                parsed_output = IOS_learn_arp_template.render(to_parse_arp=learn_arp['interfaces'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1
        # -------------------------
        # Save the files
        # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn ARP.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn ARP Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn ARP.json", "w") as fh:
                    json.dump(learn_arp, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_arp)
    except Exception as e:
        logging.exception(e)

def IOS_learn_bgp(hostname, username, password, ip):
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

        # Learn BGP to JSON

            try:
                learn_bgp = device.learn("bgp").info
            except:
                learn_bgp = f"{ hostname } has no BGP to Learn"

        # Pass to template 

        if learn_bgp != f"{ hostname } has no BGP to Learn":
            IOS_learn_bgp_template = env.get_template('IOS_learn_bgp.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output_statistics = IOS_learn_bgp_template.render(to_parse_bgp=learn_bgp['instance'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1
        # -------------------------
        # Save the files
        # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn BGP.{ filetype }", "w") as fh:
                        fh.write(parsed_output_statistics)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn BGP Mind Map.md", "w") as fh:
                        fh.write(parsed_output_statistics)               
                        fh.close()
                with open(f"{ filename }_Learn BGP.json", "w") as fh:
                    json.dump(learn_bgp, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_bgp)
    except Exception as e:
        logging.exception(e)

def IOS_learn_dot1x(hostname, username, password, ip):
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

        # Learn dot1x to JSON

            try:
                learn_dot1x = device.learn("dot1x").info
            except:
                learn_dot1x = f"{ hostname } has no dot1x to Learn"
        # Pass to template 

        if learn_dot1x != f"{ hostname } has no dot1x to Learn":
            IOS_learn_dot1x_template = env.get_template('IOS_learn_dot1x.j2')
            IOS_learn_dot1x_sessions_template = env.get_template('IOS_learn_dot1x_sessions.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output_statistics = IOS_learn_dot1x_sessions_template.render(to_parse_dot1x=learn_dot1x,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1
        # -------------------------
        # Save the files
        # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn dot1x Sessions.{ filetype }", "w") as fh:
                        fh.write(parsed_output_statistics)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn dot1x Sessions Mind Map.md", "w") as fh:
                        fh.write(parsed_output_statistics)               
                        fh.close()

        # Render Templates
            loop_counter = 0
            for filetype in filetype_loop:
                parsed_output = IOS_learn_dot1x_template.render(to_parse_dot1x=learn_dot1x,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1
        # -------------------------
        # Save the files
        # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn dot1x.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn dot1x Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn dot1x.json", "w") as fh:
                    json.dump(learn_dot1x, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_dot1x)
    except Exception as e:
        logging.exception(e)

def IOS_learn_hsrp(hostname, username, password, ip):
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

        # Learn HSRP to JSON

            try:
                learn_hsrp = device.learn("hsrp").info
            except:
                learn_hsrp = f"{ hostname } has no HSRP to Learn"

        # Pass to template 

        if learn_hsrp != f"{ hostname } has no Interface to Learn":
            IOS_learn_hsrp_template = env.get_template('IOS_learn_hsrp.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learn_hsrp_template.render(to_parse_hsrp=learn_hsrp,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn Interface.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn Interface Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn Interface.json", "w") as fh:
                    json.dump(learn_hsrp, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_hsrp)
    except Exception as e:
        logging.exception(e)

def IOS_learn_interface(hostname, username, password, ip):
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

        # Learn Interace to JSON

            try:
                learn_interface = device.learn("interface").info
            except:
                learn_interface = f"{ hostname } has no Interface to Learn"

        # Pass to template 

        if learn_interface != f"{ hostname } has no Interface to Learn":
            IOS_learn_interface_template = env.get_template('IOS_learn_interface.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learn_interface_template.render(to_parse_interface=learn_interface,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn Interface.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn Interface Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn Interface.json", "w") as fh:
                    json.dump(learn_interface, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_interface)
    except Exception as e:
        logging.exception(e)

def IOS_learn_lldp(hostname, username, password, ip):
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

        # Learn LLDP to JSON

            try:
                learn_lldp = device.learn("lldp").info
            except:
                learn_lldp = f"{ hostname } has no LLDP to Learn"

        # Pass to template 

        if learn_lldp != f"{ hostname } has no LLDP to Learn":
            IOS_learn_lldp_template = env.get_template('IOS_learn_lldp.j2')
            IOS_learn_lldp_interfaces_template = env.get_template('learn_lldp_interfaces.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learn_lldp_template.render(to_parse_lldp=learn_lldp,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn LLDP.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn LLDP Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn LLDP.json", "w") as fh:
                    json.dump(learn_lldp, fh, indent=4, sort_keys=True)
                    fh.close()

            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learn_lldp_interfaces_template.render(to_parse_lldp=learn_lldp['interfaces'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn LLDP Interface.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn LLDP Interface Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn LLDP Interface.json", "w") as fh:
                    json.dump(learn_lldp, fh, indent=4, sort_keys=True)
                    fh.close()

        return(learn_lldp)
    except Exception as e:
        logging.exception(e)

def IOS_learn_ntp(hostname, username, password, ip):
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

        # Learn NTP to JSON

            try:
                learn_ntp = device.learn("ntp").info
            except:
                learn_ntp = f"{ hostname } has no NTP to Learn"

        # Pass to template 

        if learn_ntp != f"{ hostname } has no NTP to Learn":
            IOS_learn_ntp_template = env.get_template('IOS_learn_ntp.j2')
            IOS_learn_ntp_associations_template = env.get_template('learn_ntp_associations.j2')
            IOS_learn_ntp_unicast_template = env.get_template('learn_ntp_unicast.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learn_lldp_template.render(to_parse_ntp=learn_ntp['clock_state'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn NTP Clock State.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn NTP Clock State Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn NTP.json", "w") as fh:
                    json.dump(learn_ntp, fh, indent=4, sort_keys=True)
                    fh.close()

            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learn_ntp_associations_template.render(to_parse_ntp=learn_ntp['vrf'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn NTP Associations.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn NTP Associations Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn NTP Associations.json", "w") as fh:
                    json.dump(learn_ntp, fh, indent=4, sort_keys=True)
                    fh.close()

            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learn_ntp_unicast_template.render(to_parse_ntp=learn_ntp['vrf'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn NTP Unicast.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn NTP Unicast Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn NTP Unicast.json", "w") as fh:
                    json.dump(learn_ntp, fh, indent=4, sort_keys=True)
                    fh.close()

        return(learn_ntp)
    except Exception as e:
        logging.exception(e)

def IOS_learn_ospf(hostname, username, password, ip):
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

        # Learn OSPF to JSON

            try:
                learn_ospf = device.learn("ospf").info
            except:
                learn_ospf = f"{ hostname } has no OSPF to Learn"

        # Pass to template 

        if learn_ospf != f"{ hostname } has no OSPF to Learn":
            IOS_learn_ospf_template = env.get_template('IOS_learn_ospf.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learn_ospf_template.render(to_parse_ospf=learn_ospf['vrf'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn OSPF.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn OSPF Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn OSPF.json", "w") as fh:
                    json.dump(learn_ospf, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_ospf)
    except Exception as e:
        logging.exception(e)

def IOS_learn_routing(hostname, username, password, ip):
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

        # Learn Routing to JSON

            try:
                learn_routing = device.learn("routing").info
            except:
                learn_routing = f"{ hostname } has no Routing to Learn"

        # Pass to template 

        if learn_routing is not None:
            IOS_learn_routing_template = env.get_template('IOS_learn_routing.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learn_routing_template.render(to_parse_routing=learn_routing['vrf'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn Routing.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn Routing Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn Routing.json", "w") as fh:
                    json.dump(learn_routing, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_routing)
    except Exception as e:
        logging.exception(e)

def IOS_learn_stp(hostname, username, password, ip):
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

        # Learn STP to JSON

            try: 
                learn_stp = device.learn("stp").info
            except:
                learn_stp = f"{ hostname } Has No STP to Learn"

        # Pass to template 

        if learn_stp != f"{ hostname } Has No STP to Learn":
            IOS_learn_stp_template = env.get_template('IOS_learn_stp.j2')
            IOS_learn_stp_rpvst_template = env.get_template('IOS_learn_stp_rpvst.j2')
            IOS_learn_stp_mstp_template = env.get_template('IOS_learn_stp_mstp.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learn_stp_template.render(to_parse_stp=learn_stp['global'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn Spanning Tree Protocol.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn Spanning Tree Protocol Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn Spanning Tree Protocol.json", "w") as fh:
                    json.dump(learn_stp, fh, indent=4, sort_keys=True)
                    fh.close()
            loop_counter = 0

        # Render Templates
            if "rapid_pvst" in learn_stp:
                for filetype in filetype_loop:
                    parsed_output = IOS_learn_stp_template.render(to_parse_stp=learn_stp['rapid_pvst'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ filename }_Learn Rapid Per VLAN Spanning Tree.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    else:
                        with open(f"{ filename }_Learn Rapid Per VLAN Spanning Tree Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"{ filename }_Learn Rapid Per VLAN Spanning Tree.json", "w") as fh:
                        json.dump(learn_stp, fh, indent=4, sort_keys=True)
                        fh.close()

        # Render Templates
            if learn_stp['mstp']: 
                for filetype in filetype_loop:
                    parsed_output = IOS_learn_stp_mstp_template.render(to_parse_stp=learn_stp['mstp'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ filename }_Learn Spanning Tree Multiple.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    else:
                        with open(f"{ filename }_Learn Spanning Multiple Tree Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"{ filename }_Learn Spanning Tree Multiple.json", "w") as fh:
                        json.dump(learn_stp, fh, indent=4, sort_keys=True)
                        fh.close()                        
        return(learn_stp)
    except Exception as e:
        logging.exception(e)

def IOS_learn_vlan(hostname, username, password, ip):
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

        # Learn VLAN to JSON
            try:
                learn_vlan = device.learn("vlan").info
            except:
                learn_vlan = f"{ hostname } Has No VLANs to Learn"
            
        # Pass to template 

        if learn_vlan != f"{ hostname } Has No VLANs to Learn":
            IOS_learn_vlan_template = env.get_template('IOS_learn_vlan.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learn_vlan_template.render(to_parse_vlan=learn_vlan['vlans'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn VLAN.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn VLAN Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn VLAN.json", "w") as fh:
                    json.dump(learn_vlan, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_vlan)
    except Exception as e:
        logging.exception(e)

def IOS_learn_vrf(hostname, username, password, ip):
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

        # Learn VRF to JSON
            try:
                learn_vrf = device.learn("vrf").info
            except:
                learn_vrf = f"{ hostname } Has No VRFs to Learn"
            
        # Pass to template 

        if learn_vrf != f"{ hostname } Has No VRFs to Learn":
            IOS_learn_vrf_template = env.get_template('IOS_learn_vrf.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learn_vrf_template.render(to_parse_vrf=learn_vrf['vrfs'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn VRF.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn VRF Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn VRF.json", "w") as fh:
                    json.dump(learn_vrf, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_vrf)
    except Exception as e:
        logging.exception(e)

# ----------------
# IOS SHOW PARSE SECTION
# ----------------

def IOS_show_all(hostname, username, password, ip):
    IOS_show_access_lists(hostname, username, password, ip)
    IOS_show_cdp_neighbors(hostname, username, password, ip)
    IOS_show_cdp_neighbors_detail(hostname, username, password, ip)
    IOS_show_environment_all(hostname, username, password, ip)
    IOS_show_etherchannel_summary(hostname, username, password, ip)
    IOS_show_interfaces(hostname, username, password, ip)
    IOS_show_interfaces_status(hostname, username, password, ip)
    IOS_show_interfaces_trunk(hostname, username, password, ip)
    IOS_show_inventory_9000(hostname, username, password, ip)
    IOS_show_ip_arp(hostname, username, password, ip)
    IOS_show_ip_interface_brief(hostname, username, password, ip)
    IOS_show_ip_ospf(hostname, username, password, ip)
    IOS_show_ip_ospf_database(hostname, username, password, ip)
    IOS_show_ip_ospf_interface(hostname, username, password, ip)
    IOS_show_ip_ospf_neighbor(hostname, username, password, ip)
    IOS_show_ip_ospf_neighbor_detail(hostname, username, password, ip)
    IOS_show_ip_route(hostname, username, password, ip)
    IOS_show_license_summary(hostname, username, password, ip)
    IOS_show_mac_address_table(hostname, username, password, ip)
    IOS_show_ntp_associations(hostname, username, password, ip)
    IOS_show_wlan_all(hostname, username, password, ip)
    IOS_show_wlan_client_stats(hostname, username, password, ip)
    IOS_show_wlan_summary(hostname, username, password, ip)
    IOS_show_wireless_profile_summary(hostname, username, password, ip)
    IOS_show_wireless_profile_detailed(hostname, username, password, ip)
    IOS_show_version(hostname, username, password, ip)
    IOS_show_vlan(hostname, username, password, ip)
    IOS_show_vrf(hostname, username, password, ip)
    return("Parsed All Show Commands")

def IOS_show_access_lists(hostname, username, password, ip):
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

        # Show Access Lists to JSON

            try:
                show_access_lists = device.parse("show access-lists")
            except:
                show_access_lists = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_access_lists != f"{ hostname } Can't Parse":
            IOS_show_access_lists_template = env.get_template('IOS_learn_acl.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_access_lists_template.render(to_parse_access_list=show_access_lists,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show Access Lists.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show Access Lists Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show Access Lists.json", "w") as fh:
                    json.dump(show_access_lists, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_access_lists)
    except Exception as e:
        logging.exception(e)

def IOS_show_cdp_neighbors(hostname, username, password, ip):
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

        # Show CDP Neighbors to JSON

            try:
                show_cdp_neighbors = device.parse("show cdp neighbors")
            except:
                show_cdp_neighbors = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_cdp_neighbors != f"{ hostname } Can't Parse":
            IOS_show_cdp_neighbors_template = env.get_template('IOS_show_cdp_neighbors.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_cdp_neighbors_template.render(to_parse_cdp_neighbors=show_cdp_neighbors['cdp'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show CDP Neighbors.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show CDP Neighbors Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show CDP Neighbors.json", "w") as fh:
                    json.dump(show_cdp_neighbors, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_cdp_neighbors)
    except Exception as e:
        logging.exception(e)

def IOS_show_cdp_neighbors_detail(hostname, username, password, ip):
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

        # Show CDP Neighbors Detail to JSON

            try:
                show_cdp_neighbors_detail = device.parse("show cdp neighbors detail")
            except:
                show_cdp_neighbors_detail = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_cdp_neighbors_detail != f"{ hostname } Can't Parse":
            IOS_show_cdp_neighbors_detail_template = env.get_template('IOS_show_cdp_neighbors_detail.j2')
            IOS_show_cdp_neighbors_detail_totals_template = env.get_template('IOS_show_cdp_neighbors_detail_totals.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_cdp_neighbors_detail_template.render(to_parse_cdp_neighbors=show_cdp_neighbors_detail['index'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show CDP Neighbors Details.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show CDP Neighbors Details Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show CDP Neighbors Details.json", "w") as fh:
                    json.dump(show_cdp_neighbors_detail, fh, indent=4, sort_keys=True)
                    fh.close()

            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_cdp_neighbors_detail_totals_template.render(to_parse_cdp_neighbors=show_cdp_neighbors_detail,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show CDP Neighbors Details Totals.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show CDP Neighbors Details Totals Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show CDP Neighbors Details Totals.json", "w") as fh:
                    json.dump(show_cdp_neighbors_detail, fh, indent=4, sort_keys=True)
                    fh.close() 

        return(show_cdp_neighbors_detail)
    except Exception as e:
        logging.exception(e)

def IOS_show_environment_all(hostname, username, password, ip):
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

        # Show Environment All to JSON

            try:
                show_environment_all = device.parse("show environment all")
            except:
                show_environment_all = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_environment_all != f"{ hostname } Can't Parse":
            IOS_show_environment_all_template = env.get_template('IOS_show_environment_all.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_environment_all_template.render(to_parse_environment=show_environment_all['switch'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show Environment All.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show Environment All Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show Environment All.json", "w") as fh:
                    json.dump(show_environment_all, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_environment_all)
    except Exception as e:
        logging.exception(e)

def IOS_show_etherchannel_summary(hostname, username, password, ip):
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

        # Show Etherchannel Summary to JSON

            try:
                show_etherchannel_summary = device.parse("show etherchannel summary")
            except:
                show_etherchannel_summary = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_etherchannel_summary != f"{ hostname } Can't Parse":
            IOS_show_etherchannel_summary_template = env.get_template('IOS_show_etherchannel_summary.j2')
            IOS_show_etherchannel_summary_totals_template = env.get_template('IOS_show_etherchannel_summary_totals.j2')
            loop_counter = 0
        # Render Templates
            if "interfaces" in show_etherchannel_summary:
                for filetype in filetype_loop:
                    parsed_output = IOS_show_etherchannel_summary_template.render(to_parse_etherchannel_summary=show_etherchannel_summary['interfaces'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ filename }_Show Etherchannel Summary.{ filetype }", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    else:
                        with open(f"{ filename }_Show Etherchannel Summary Mind Map.md", "w") as fh:
                            fh.write(parsed_output)               
                            fh.close()
                    with open(f"{ filename }_Show Etherchannel Summary.json", "w") as fh:
                        json.dump(show_etherchannel_summary, fh, indent=4, sort_keys=True)
                        fh.close()

            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_etherchannel_summary_totals_template.render(to_parse_etherchannel_summary=show_etherchannel_summary,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show Etherchannel Summary Totals.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show Etherchannel Summary Totals Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()                        
        return(show_etherchannel_summary)
    except Exception as e:
        logging.exception(e)

def IOS_show_interfaces(hostname, username, password, ip):
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

        # Show Interfaces to JSON

            try:
                show_interfaces = device.parse("show interfaces")
            except:
                show_interfaces = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_interfaces != f"{ hostname } Can't Parse":
            IOS_show_interfaces_template = env.get_template('IOS_show_interfaces.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_interfaces_template.render(to_parse_interfaces=show_interfaces,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show Interfaces.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show Interfaces Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show Interfaces.json", "w") as fh:
                    json.dump(show_interfaces, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_interfaces)
    except Exception as e:
        logging.exception(e)

def IOS_show_interfaces_status(hostname, username, password, ip):
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

        # Show Interfaces Status to JSON

            try:
                show_interfaces_status = device.parse("show interfaces status")
            except:
                show_interfaces_status = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_interfaces_status != f"{ hostname } Can't Parse":
            IOS_show_interfaces_status_template = env.get_template('IOS_show_interfaces_status.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_interfaces_status_template.render(to_parse_interfaces=show_interfaces_status['interfaces'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show Interfaces Status.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show Interfaces Status Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show Interfaces Status.json", "w") as fh:
                    json.dump(show_interfaces_status, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_interfaces_status)
    except Exception as e:
        logging.exception(e)

def IOS_show_interfaces_trunk(hostname, username, password, ip):
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

        # Show Interfaces Trunk to JSON

            try:
                show_interfaces_trunk = device.parse("show interfaces trunk")
            except:
                show_interfaces_trunk = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_interfaces_trunk != f"{ hostname } Can't Parse":
            IOS_show_interfaces_trunk_template = env.get_template('IOS_show_interfaces_trunk.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_interfaces_trunk_template.render(to_parse_interfaces_trunk=show_interfaces_trunk['interface'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show Interfaces Trunk.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show Interfaces Trunk Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show Interfaces Trunk.json", "w") as fh:
                    json.dump(show_interfaces_trunk, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_interfaces_trunk)
    except Exception as e:
        logging.exception(e)

def IOS_show_inventory_9000(hostname, username, password, ip):
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

        # Show Inventory 9000 to JSON

            try:
                show_inventory = device.parse("show inventory")
            except:
                show_inventory = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_inventory != f"{ hostname } Can't Parse":
            IOS_show_inventory_template = env.get_template('IOS_show_inventory_9000.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_inventory_template.render(to_parse_inventory=show_inventory['slot'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show Inventory.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show Inventory Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show Inventory.json", "w") as fh:
                    json.dump(show_inventory_trunk, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_inventory_trunk)
    except Exception as e:
        logging.exception(e)

def IOS_show_ip_arp(hostname, username, password, ip):
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

        # Show IP ARP to JSON

            try:
                show_ip_arp = device.parse("show ip arp")
            except:
                show_ip_arp = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_ip_arp != f"{ hostname } Can't Parse":
            IOS_show_ip_arp_template = env.get_template('IOS_show_ip_arp.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_ip_arp_template.render(to_parse_ip_arp=show_ip_arp['interfaces'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show IP ARP.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show IP ARP Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show IP ARP.json", "w") as fh:
                    json.dump(show_ip_arp, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_ip_arp)
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

            try:
                show_ip_interface_brief = device.parse("show ip interface brief")
            except:
                show_ip_interface_brief = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_ip_interface_brief != f"{ hostname } Can't Parse":
            IOS_show_ip_interface_brief_template = env.get_template('IOS_show_ip_interface_brief.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_ip_interface_brief_template.render(to_parse_interfaces=show_ip_interface_brief['interface'],filetype_loop=loop_counter)
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
                with open(f"{ filename }_Show IP Interface Brief.json", "w") as fh:
                    json.dump(show_ip_interface_brief, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_ip_interface_brief)
    except Exception as e:
        logging.exception(e)

def IOS_show_ip_ospf(hostname, username, password, ip):
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

        # Show IP OSPF to JSON

            try:
                show_ip_ospf = device.parse("show ip ospf")
            except:
                show_ip_ospf = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_ip_ospf != f"{ hostname } Can't Parse":
            IOS_show_ip_ospf_template = env.get_template('IOS_show_ip_ospf.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_ip_ospf_template.render(to_parse_ip_ospf=show_ip_ospf['vrf'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show IP OSPF.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show IP OSPF Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show IP OSPF.json", "w") as fh:
                    json.dump(show_ip_ospf, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_ip_ospf)
    except Exception as e:
        logging.exception(e)

def IOS_show_ip_ospf_database(hostname, username, password, ip):
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

        # Show IP OSPF Database to JSON

            try:
                show_ip_ospf_database = device.parse("show ip ospf database")
            except:
                show_ip_ospf_database = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_ip_ospf_database != f"{ hostname } Can't Parse":
            IOS_show_ip_ospf_database_template = env.get_template('IOS_show_ip_ospf_database.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_ip_ospf_database_template.render(to_parse_ip_ospf_database=show_ip_ospf_database['vrf'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show IP OSPF Database.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show IP OSPF Database Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show IP OSPF Database.json", "w") as fh:
                    json.dump(show_ip_ospf_database, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_ip_ospf_database)
    except Exception as e:
        logging.exception(e)

def IOS_show_ip_ospf_interface(hostname, username, password, ip):
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

        # Show IP OSPF Interface to JSON

            try:
                show_ip_ospf_interface = device.parse("show ip ospf interface")
            except:
                show_ip_ospf_interface = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_ip_ospf_interface != f"{ hostname } Can't Parse":
            IOS_show_ip_ospf_interface_template = env.get_template('IOS_show_ip_ospf_interface.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_ip_ospf_interface_template.render(to_parse_ip_ospf_interface=show_ip_ospf_interface['vrf'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show IP OSPF Interface.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show IP OSPF Interface Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show IP OSPF Interface.json", "w") as fh:
                    json.dump(show_ip_ospf_interface, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_ip_ospf_interface)
    except Exception as e:
        logging.exception(e)

def IOS_show_ip_ospf_neighbor(hostname, username, password, ip):
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

        # Show IP OSPF Neighbor to JSON

            try:
                show_ip_ospf_neighbor = device.parse("show ip ospf neighbor")
            except:
                show_ip_ospf_neighbor = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_ip_ospf_neighbor != f"{ hostname } Can't Parse":
            IOS_show_ip_ospf_neighbor_template = env.get_template('IOS_show_ip_ospf_neighbor.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_ip_ospf_neighbor_template.render(to_parse_ip_ospf_neighbor=show_ip_ospf_neighbor['interfaces'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show IP OSPF Neighbor.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show IP OSPF Neighbor Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show IP OSPF Neighbor.json", "w") as fh:
                    json.dump(show_ip_ospf_neighbor, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_ip_ospf_neighbor)
    except Exception as e:
        logging.exception(e)

def IOS_show_ip_ospf_neighbor_detail(hostname, username, password, ip):
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

        # Show IP OSPF Neighbor Detail to JSON

            try:
                show_ip_ospf_neighbor_detail = device.parse("show ip ospf neighbor detail")
            except:
                show_ip_ospf_neighbor_detail = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_ip_ospf_neighbor_detail != f"{ hostname } Can't Parse":
            IOS_show_ip_ospf_neighbor_detail_template = env.get_template('IOS_show_ip_ospf_neighbor_detail.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_ip_ospf_neighbor_detail_template.render(to_parse_ip_ospf_neighbor_detail=show_ip_ospf_neighbor_detail['vrf'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show IP OSPF Neighbor Detail.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show IP OSPF Neighbor Detail Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show IP OSPF Neighbor Detail.json", "w") as fh:
                    json.dump(show_ip_ospf_neighbor_detail, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_ip_ospf_neighbor_detail)
    except Exception as e:
        logging.exception(e)

def IOS_show_ip_route(hostname, username, password, ip):
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

        # Show IP Route to JSON

            try:
                show_ip_route = device.parse("show ip route")
            except:
                show_ip_route = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_ip_route != f"{ hostname } Can't Parse":
            IOS_show_ip_route_template = env.get_template('IOS_show_ip_route.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_ip_route_template.render(to_parse_ip_route=show_ip_route['vrf'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show IP Route.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show IP Route Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show IP Route.json", "w") as fh:
                    json.dump(show_ip_route, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_ip_route)
    except Exception as e:
        logging.exception(e)

def IOS_show_license_summary(hostname, username, password, ip):
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

        # Show License Summary to JSON

            try:
                show_ip_license_summary = device.parse("show license summary")
            except:
                show_ip_license_summary = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_ip_license_summary != f"{ hostname } Can't Parse":
            IOS_show_license_summary_template = env.get_template('IOS_show_license_summary.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_license_summary_template.render(to_parse_license=show_ip_license_summary['license_usage'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show License Summary.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show License Summary Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show License Summary.json", "w") as fh:
                    json.dump(show_ip_license_summary, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_ip_license_summary)
    except Exception as e:
        logging.exception(e)

def IOS_show_mac_address_table(hostname, username, password, ip):
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

        # Show MAC Address Table to JSON

            try:
                show_mac_address_table = device.parse("show mac address-table")
            except:
                show_mac_address_table = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_mac_address_table != f"{ hostname } Can't Parse":
            IOS_show_mac_address_table_template = env.get_template('IOS_show_mac_address_table.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_mac_address_table_template.render(to_parse_mac_address_table=show_mac_address_table['mac_table'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show MAC Address Table.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show MAC Address Table Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show MAC Address Table.json", "w") as fh:
                    json.dump(show_mac_address_table, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_mac_address_table)
    except Exception as e:
        logging.exception(e)

def IOS_show_ntp_associations(hostname, username, password, ip):
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

        # Show NTP Associations to JSON

            try:
                show_ntp_associations = device.parse("show ntp associations")
            except:
                show_ntp_associations = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_ntp_associations != f"{ hostname } Can't Parse":
            IOS_show_ntp_associations_template = env.get_template('IOS_show_ntp_associations.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_ntp_associations_template.render(to_parse_ntp_associations=show_ntp_associations['mac_table'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show NTP Associations.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show NTP Associations Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show NTP Associations.json", "w") as fh:
                    json.dump(show_ntp_associations, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_ntp_associations)
    except Exception as e:
        logging.exception(e)

def IOS_show_wlan_summary(hostname, username, password, ip):
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

        # Show WLAN Summary to JSON

            try:
                show_wlan_summary = device.parse("show wlan summary")
            except:
                show_wlan_summary = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_wlan_summary != f"{ hostname } Can't Parse":
            IOS_show_wlan_summary_template = env.get_template('IOS_show_wlan_summary.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_wlan_summary_template.render(to_parse_wlan=show_wlan_summary['wlan_summary']['wlan_id'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show WLAN Summary.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show WLAN Summary Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show WLAN Summary.json", "w") as fh:
                    json.dump(show_wlan_summary, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_wlan_summary)
    except Exception as e:
        logging.exception(e)

def IOS_show_wlan_all(hostname, username, password, ip):
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

        # Show WLAN all to JSON

            try:
                show_wlan_all = device.parse("show wlan all")
            except:
                show_wlan_all = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_wlan_all != f"{ hostname } Can't Parse":
            IOS_show_wlan_all_template = env.get_template('IOS_show_wlan_all.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_wlan_all_template.render(to_parse_wlan=show_wlan_all['wlan_names'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show WLAN All.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show WLAN All Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show WLAN All.json", "w") as fh:
                    json.dump(show_wlan_all, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_wlan_all)
    except Exception as e:
        logging.exception(e)

def IOS_show_wlan_client_stats(hostname, username, password, ip):
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

        # Show WLAN Summary to JSON

            try:
                show_wlan_summary = device.parse("show wlan summary")
            except:
                show_wlan_summary = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_wlan_summary != f"{ hostname } Can't Parse":
            for wlan in show_wlan_summary['wlan_summary']['wlan_id']:
                try:
                    show_wlan_client_stats = device.parse(f"show wlan id { wlan } client stats")
                except:
                    show_wlan_client_stats = f"{ hostname } Can't Parse"

                if show_wlan_client_stats != f"{ hostname } Can't Parse":
                # -------------------------
                # create folders to hold files
                # -------------------------
                    if not os.path.exists(f"WLAN_ID { wlan }"):
                        os.mkdir(f"WLAN_ID { wlan }")
                    else:
                        print("Directory already exists")                    
                    IOS_show_wlan_client_stats_template = env.get_template('IOS_show_wlan_client_stats.j2')
                    loop_counter = 0
                # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = IOS_show_wlan_client_stats_template.render(to_parse_wlan=show_wlan_client_stats['wlan_id'],filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

                    # -------------------------
                    # Save the files
                    # -------------------------
                        if loop_counter <= 3:
                            with open(f"WLAN_ID { wlan }/{ filename }_Show WLAN { wlan } Client Stats.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open(f"WLAN_ID { wlan }/{ filename }_Show WLAN { wlan } Client Stats Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"WLAN_ID { wlan }/{ filename }_Show WLAN { wlan } Client Stats.json", "w") as fh:
                            json.dump(show_wlan_client_stats, fh, indent=4, sort_keys=True)
                            fh.close()                                 
        return(show_wlan_client_stats)
    except Exception as e:
        logging.exception(e)

def IOS_show_wireless_profile_policy_summary(hostname, username, password, ip):
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

        # Show Wireless Profile Policy Summary to JSON

            try:
                show_wireless_profile_policy_summary = device.parse("show wireless profile policy summary")
            except:
                show_wireless_profile_policy_summary = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_wireless_profile_policy_summary != f"{ hostname } Can't Parse":
            IOS_show_wireless_profile_policy_summary_template = env.get_template('IOS_show_wireless_profile_policy_summary.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_wireless_profile_policy_summary_template.render(to_parse_wireless=show_wireless_profile_policy_summary['policy_name'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show Wireless Profile Policy Summary.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show Wireless Profile Policy Summary Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show Wireless Profile Policy Summary.json", "w") as fh:
                    json.dump(show_wireless_profile_policy_summary, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_wireless_profile_policy_summary)
    except Exception as e:
        logging.exception(e)

# This function is broken I believe the underlying parser is broken
def IOS_show_wireless_profile_policy_detailed(hostname, username, password, ip):
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

        # Show Wireless Profile Policy Summary to JSON

            try:
                show_wireless_profile_policy_summary = device.parse("show wireless profile policy summary")
            except:
                show_wireless_profile_policy_summary = f"{ hostname } Can't Parse"

        # Pass to template 
            
            for policy in show_wireless_profile_policy_summary['policy_name'].keys():
                # Show WLAN all to JSON
                try:
                    print(f"{policy}")
                    show_wireless_profile_policy_detail = device.parse(f"show wireless profile policy detailed { policy }")
                except:
                    show_wireless_profile_policy_detail = f"{ hostname } Can't Parse"

                if show_wireless_profile_policy_detail != f"{ hostname } Can't Parse":
                    # -------------------------
                    # create folders to hold files
                    # -------------------------
                    if not os.path.exists(f"{ policy }"):
                        os.mkdir(f"{ policy }")
                    else:
                        print("Directory already exists")                        
                    IOS_show_wireless_profile_policy_detailed_template = env.get_template('IOS_show_wireless_profile_policy_detailed.j2')
                    loop_counter = 0
                # RenderTemplates
                    for filetype in filetype_loop:
                        parsed_output = IOS_show_wireless_profile_policy_detailed_template.render(to_parse_wireless=show_wireless_profile_policy_detail,filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

                # -------------------------
                # Save the files
                # -------------------------
                        if loop_counter <= 3:
                            with open(f"{ policy }/{ filename }_Show Wireless Profile Policy { policy } Detailed.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open(f"{ policy }/{ filename }_Show Wireless Profile Policy { policy } Detailed Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"{ policy }/{ filename }_Show Wireless Profile Policy { policy } Detailed.json", "w") as fh:
                            json.dump(show_wireless_profile_policy_detail, fh, indent=4, sort_keys=True)
                            fh.close()                                 
        return(show_wireless_profile_policy_detail)
    except Exception as e:
        logging.exception(e)

def IOS_show_version(hostname, username, password, ip):
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

        # Show Version to JSON

            try:
                show_version = device.parse("show version")
            except:
                show_version = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_version != f"{ hostname } Can't Parse":
            IOS_show_version_template = env.get_template('IOS_show_version.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_version_template.render(to_parse_version=show_version['version'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show Version.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show Version Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show Version.json", "w") as fh:
                    json.dump(show_version, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_version)
    except Exception as e:
        logging.exception(e)

def IOS_show_vlan(hostname, username, password, ip):
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

        # Show VLAN to JSON

            try:
                show_vlan = device.parse("show vlan")
            except:
                show_vlan = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_vlan != f"{ hostname } Can't Parse":
            IOS_show_vlan_template = env.get_template('IOS_show_vlan.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_vlan_template.render(to_parse_vlan=show_vlan['vlans'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show VLAN.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show VLAN Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show VLAN.json", "w") as fh:
                    json.dump(show_vlan, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_vlan)
    except Exception as e:
        logging.exception(e)

def IOS_show_vrf(hostname, username, password, ip):
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

        # Show VRF to JSON

            try:
                show_vrf = device.parse("show vrf")
            except:
                show_vrf = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_vrf != f"{ hostname } Can't Parse":
            IOS_show_vrf_template = env.get_template('IOS_show_vrf.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_show_vrf_template.render(to_parse_vrf=show_vrf['vrf'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show VRF.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show VRF Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show VRF.json", "w") as fh:
                    json.dump(show_vrf, fh, indent=4, sort_keys=True)
                    fh.close()
            
            for vrf in show_vrf['vrf']:

            # Show IP ARP VRF <VRF>

                try:
                    show_ip_arp_vrf = device.parse(f"show ip arp vrf { vrf }")
                except:
                    show_ip_arp_vrf = f"{ hostname } Can't Parse"

            # Pass to template 

                if show_ip_arp_vrf != f"{ hostname } Can't Parse":
                    IOS_show_ip_arp_vrf_template = env.get_template('IOS_show_ip_arp.j2')
                    loop_counter = 0
            # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = IOS_show_ip_arp_vrf_template.render(to_parse_ip_arp=show_ip_arp_vrf['interfaces'],filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"{ filename }_Show IP ARP VRF { vrf }.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open(f"{ filename }_Show IP ARP VRF { vrf } Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"{ filename }_Show IP ARP VRF { vrf }.json", "w") as fh:
                            json.dump(show_ip_arp_vrf, fh, indent=4, sort_keys=True)
                            fh.close()

            # Show IP Route VRF <VRF>

                try:
                    show_ip_route_vrf = device.parse(f"show ip route vrf { vrf }")
                except:
                    show_ip_route_vrf = f"{ hostname } Can't Parse"

            # Pass to template 

                if show_ip_route_vrf != f"{ hostname } Can't Parse":
                    IOS_show_ip_route_vrf_template = env.get_template('IOS_show_ip_route.j2')
                    loop_counter = 0
            # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = IOS_show_ip_route_vrf_template.render(to_parse_ip_route=show_ip_route_vrf['vrf'],filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"{ filename }_Show IP Route VRF { vrf }.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open(f"{ filename }_Show IP Route VRF { vrf } Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"{ filename }_Show IP Route VRF { vrf }.json", "w") as fh:
                            json.dump(show_ip_route_vrf, fh, indent=4, sort_keys=True)
                            fh.close()

        return(show_vrf)
    except Exception as e:
        logging.exception(e)

# ----------------
# NXOS ALL
# ----------------

def NXOS_all(hostname, username, password, ip):
    NXOS_learn_all(hostname, username, password, ip)
    NXOS_show_all(hostname, username, password, ip)
    return("All Functions Converted to Business Ready Documents")

# ----------------
# NXOS LEARN SECTION
# ----------------

def NXOS_learn_all(hostname, username, password, ip):
    NXOS_learn_acl(hostname, username, password, ip)
    NXOS_learn_arp(hostname, username, password, ip)
    NXOS_learn_bgp(hostname, username, password, ip)
    NXOS_learn_hsrp(hostname, username, password, ip)
    NXOS_learn_interface(hostname, username, password, ip)
    NXOS_learn_ospf(hostname, username, password, ip)
    NXOS_learn_platform(hostname, username, password, ip)
    NXOS_learn_routing(hostname, username, password, ip)
    NXOS_learn_vlan(hostname, username, password, ip)
    NXOS_learn_vrf(hostname, username, password, ip)
    return("learn All Functions")

def NXOS_learn_acl(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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
            try:
                learn_acl = device.learn("acl").info
            except:
                learn_acl = f"{ hostname } Has NO ACLs to Learn"

        # Pass to template 

        if learn_acl != f"{ hostname } Has NO ACLs to Learn":
            NXOS_learn_acl_template = env.get_template('NXOS_learn_acl.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_learn_acl_template.render(to_parse_access_list=learn_acl['acls'],filetype_loop=loop_counter)
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
                with open(f"{ filename }_Learn ACL.json", "w") as fh:
                    json.dump(learn_acl, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_acl)
    except Exception as e:
        logging.exception(e)

def NXOS_learn_arp(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Learn ARP to JSON

            try:
                learn_arp = device.learn("arp").info
            except:
                learn_arp = f"{ hostname } has no ARP to Learn"

        # Pass to template 

        if learn_arp != f"{ hostname } has no ARP to Learn":
            NXOS_learn_arp_template = env.get_template('NXOS_learn_arp.j2')
            NXOS_learn_arp_statistics_template = env.get_template('NXOS_learn_arp_statistics.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output_statistics = NXOS_learn_arp_statistics_template.render(to_parse_arp=learn_arp['statistics'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1
        # -------------------------
        # Save the files
        # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn ARP Statistics.{ filetype }", "w") as fh:
                        fh.write(parsed_output_statistics)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn ARP Statistics Mind Map.md", "w") as fh:
                        fh.write(parsed_output_statistics)               
                        fh.close()
                with open(f"{ filename }_Learn ARP Statistics.json", "w") as fh:
                    json.dump(learn_arp['statistics'], fh, indent=4, sort_keys=True)
                    fh.close()

        # Render Templates
            loop_counter = 0
            for filetype in filetype_loop:
                parsed_output = NXOS_learn_arp_template.render(to_parse_arp=learn_arp['interfaces'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1
        # -------------------------
        # Save the files
        # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn ARP.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn ARP Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn ARP.json", "w") as fh:
                    json.dump(learn_arp, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_arp)
    except Exception as e:
        logging.exception(e)

def NXOS_learn_bgp(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Learn BGP to JSON

            try:
                learn_bgp = device.learn("bgp").info
            except:
                learn_bgp = f"{ hostname } has no BGP to Learn"

        # Pass to template 

        if learn_bgp != f"{ hostname } has no BGP to Learn":
            if "instance" in learn_bgp:
                NXOS_learn_bgp_template = env.get_template('NXOS_learn_bgp.j2')
                loop_counter = 0
        # Render Templates
                for filetype in filetype_loop:
                    parsed_output_statistics = NXOS_learn_bgp_template.render(to_parse_bgp=learn_bgp['instance'],filetype_loop=loop_counter)
                    loop_counter = loop_counter + 1
        # -------------------------
        # Save the files
        # -------------------------
                    if loop_counter <= 3:
                        with open(f"{ filename }_Learn BGP.{ filetype }", "w") as fh:
                            fh.write(parsed_output_statistics)               
                            fh.close()
                    else:
                        with open(f"{ filename }_Learn BGP Mind Map.md", "w") as fh:
                            fh.write(parsed_output_statistics)               
                            fh.close()
                    with open(f"{ filename }_Learn BGP.json", "w") as fh:
                        json.dump(learn_bgp, fh, indent=4, sort_keys=True)
                        fh.close()
            else:
                learn_bgp = f"{ hostname } has no BGP Instances"
        return(learn_bgp)
    except Exception as e:
        logging.exception(e)

def NXOS_learn_hsrp(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Learn HSRP to JSON

            try:
                learn_hsrp = device.learn("hsrp").info
            except:
                learn_hsrp = f"{ hostname } has no HSRP to Learn"

        # Pass to template 

        if learn_hsrp != f"{ hostname } has no Interface to Learn":
            NXOS_learn_hsrp_template = env.get_template('NXOS_learn_hsrp.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_learn_hsrp_template.render(to_parse_hsrp=learn_hsrp,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn Interface.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn Interface Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn Interface.json", "w") as fh:
                    json.dump(learn_hsrp, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_hsrp)
    except Exception as e:
        logging.exception(e)

def NXOS_learn_interface(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Learn Interace to JSON

            try:
                learn_interface = device.learn("interface").info
            except:
                learn_interface = f"{ hostname } has no Interface to Learn"

        # Pass to template 

        if learn_interface != f"{ hostname } has no Interface to Learn":
            NXOS_learn_interface_template = env.get_template('NXOS_learn_interface.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_learn_interface_template.render(to_parse_interface=learn_interface,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn Interface.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn Interface Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn Interface.json", "w") as fh:
                    json.dump(learn_interface, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_interface)
    except Exception as e:
        logging.exception(e)

def NXOS_learn_ospf(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Learn OSPF to JSON

            try:
                learn_ospf = device.learn("ospf").info
            except:
                learn_ospf = f"{ hostname } has no OSPF to Learn"

        # Pass to template 

        if learn_ospf != f"{ hostname } has no OSPF to Learn":
            NXOS_learn_ospf_template = env.get_template('NXOS_learn_ospf.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_learn_ospf_template.render(to_parse_ospf=learn_ospf,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn OSPF.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn OSPF Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn OSPF.json", "w") as fh:
                    json.dump(learn_ospf, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_ospf)
    except Exception as e:
        logging.exception(e)

def NXOS_learn_platform(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Learn Platform to JSON

            try:
                learn_platform = device.learn("platform").to_dict()
            except:
                learn_platform = f"{ hostname } has no Platform to Learn"

        # Pass to template 

        if learn_platform != f"{ hostname } has no Platform to Learn":
            NXOS_learn_platform_template = env.get_template('NXOS_learn_platform.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_learn_platform_template.render(to_parse_platform=learn_platform,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn Platform.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn Platform Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn Platform.json", "w") as fh:
                    json.dump(learn_platform, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_platform)
    except Exception as e:
        logging.exception(e)

def NXOS_learn_routing(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Learn Routing to JSON

            try:
                learn_routing = device.learn("routing").info
            except:
                learn_routing = f"{ hostname } has no Routing to Learn"

        # Pass to template 

        if learn_routing != f"{ hostname } has no Platform to Learn":
            NXOS_learn_routing_template = env.get_template('NXOS_learn_routing.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_learn_routing_template.render(to_parse_routing=learn_routing['vrf'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn Routing.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn Routing Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn Routing.json", "w") as fh:
                    json.dump(learn_routing, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_routing)
    except Exception as e:
        logging.exception(e)

def NXOS_learn_platform(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Learn Platform to JSON

            try:
                learn_platform = device.learn("platform").to_dict()
            except:
                learn_platform = f"{ hostname } has no Platform to Learn"

        # Pass to template 

        if learn_platform != f"{ hostname } has no Platform to Learn":
            NXOS_learn_platform_template = env.get_template('NXOS_learn_platform.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_learn_platform_template.render(to_parse_platform=learn_platform,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn Platform.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn Platform Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn Platform.json", "w") as fh:
                    json.dump(learn_platform, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_platform)
    except Exception as e:
        logging.exception(e)

def NXOS_learn_vlan(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Learn VLAN to JSON

            try:
                learn_vlan = device.learn("vlan").info
            except:
                learn_vlan = f"{ hostname } has no VLAN to Learn"

        # Pass to template 

        if learn_vlan != f"{ hostname } has no VLAN to Learn":
            NXOS_learn_vlan_template = env.get_template('NXOS_learn_vlan.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_learn_vlan_template.render(to_parse_vlan=learn_vlan['vlans'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn VLAN.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn VLAN Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn VLAN.json", "w") as fh:
                    json.dump(learn_vlan, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_vlan)
    except Exception as e:
        logging.exception(e)

def NXOS_learn_vrf(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Learn VRF to JSON

            try:
                learn_vrf = device.learn("vrf").info
            except:
                learn_vrf = f"{ hostname } has no VRF to Learn"

        # Pass to template 

        if learn_vrf != f"{ hostname } has no VRF to Learn":
            NXOS_learn_vrf_template = env.get_template('NXOS_learn_vrf.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_learn_vrf_template.render(to_parse_vrf=learn_vrf['vrfs'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Learn VRF.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Learn VRF Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Learn VRF.json", "w") as fh:
                    json.dump(learn_vrf, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learn_vrf)
    except Exception as e:
        logging.exception(e)

# ----------------
# NXOS SHOW SECTION
# ----------------       

def NXOS_show_all(hostname, username, password, ip):
    NXOS_show_access_lists(hostname, username, password, ip)
    NXOS_show_bgp_process_vrf_all(hostname, username, password, ip)
    NXOS_show_bgp_sessions(hostname, username, password, ip)
    NXOS_show_cdp_neighbors(hostname, username, password, ip)
    NXOS_show_cdp_neighbors_detail(hostname, username, password, ip)
    NXOS_show_environment(hostname, username, password, ip)
    NXOS_show_interface(hostname, username, password, ip)
    NXOS_show_interface_status(hostname, username, password, ip)
    NXOS_show_interface_transceiver(hostname, username, password, ip)
    NXOS_show_inventory(hostname, username, password, ip)
    NXOS_show_ip_arp_vrf(hostname, username, password, ip)
    NXOS_show_ip_interface_brief(hostname, username, password, ip)
    NXOS_show_ip_ospf(hostname, username, password, ip)
    NXOS_show_ip_ospf_vrf(hostname, username, password, ip)
    NXOS_show_ip_ospf_interface(hostname, username, password, ip)
    NXOS_show_ip_ospf_interface_vrf(hostname, username, password, ip)
    NXOS_show_ip_ospf_neighbors_detail(hostname, username, password, ip)
    NXOS_show_ip_ospf_neighbors_detail_vrf(hostname, username, password, ip)   
    NXOS_show_ip_route(hostname, username, password, ip)
    NXOS_show_ip_route_vrf(hostname, username, password, ip)
    NXOS_show_mac_address_table(hostname, username, password, ip)
    NXOS_show_port_channel_summary(hostname, username, password, ip)
    NXOS_show_version(hostname, username, password, ip)
    NXOS_show_vlan(hostname, username, password, ip)
    NXOS_show_vrf(hostname, username, password, ip)
    NXOS_show_vrf_all_detail(hostname, username, password, ip)
    NXOS_show_vrf_all_interface(hostname, username, password, ip)
    NXOS_show_vrf_detail(hostname, username, password, ip)
    return("Parsed All Show Commands")

def NXOS_show_access_lists(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show Access Lists to JSON

            try:
                show_access_lists = device.parse("show access-lists")
            except:
                show_access_lists = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_access_lists != f"{ hostname } Can't Parse":
            NXOS_show_access_lists_template = env.get_template('NXOS_show_access_lists_acl.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_access_lists_template.render(to_parse_access_list=show_access_lists,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show Access Lists.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show Access Lists Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show Access Lists.json", "w") as fh:
                    json.dump(show_access_lists, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_access_lists)
    except Exception as e:
        logging.exception(e)

def NXOS_show_bgp_process_vrf_all(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show BGP Process VRF All to JSON

            try:
                show_bgp_process_vrf_all = device.parse("show bgp process vrf all")
            except:
                show_bgp_process_vrf_all = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_bgp_process_vrf_all != f"{ hostname } Can't Parse":
            NXOS_show_bgp_process_vrf_all_template = env.get_template('NXOS_show_bgp_process_vrf_all.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_bgp_process_vrf_all_template.render(to_parse_bgp=show_bgp_process_vrf_all,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show BGP Process VRF All.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show BGP Process VRF All Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show BGP Process VRF All.json", "w") as fh:
                    json.dump(show_bgp_process_vrf_all, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_bgp_process_vrf_all)
    except Exception as e:
        logging.exception(e)

def NXOS_show_bgp_sessions(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show BGP Sessions to JSON

            try:
                show_bgp_sessions = device.parse("show bgp sessions")
            except:
                show_bgp_sessions = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_bgp_sessions != f"{ hostname } Can't Parse":
            NXOS_show_bgp_sessions_template = env.get_template('NXOS_show_bgp_sessions.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_bgp_sessions_template.render(to_parse_bgp=show_bgp_sessions,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show BGP Sessions.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show BGP Sessions Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show BGP Sessions.json", "w") as fh:
                    json.dump(show_bgp_sessions, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_bgp_sessions)
    except Exception as e:
        logging.exception(e)

def NXOS_show_cdp_neighbors(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show CDP Neighbors to JSON

            try:
                show_cdp_neighbors = device.parse("show cdp neighbors")
            except:
                show_cdp_neighbors = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_cdp_neighbors != f"{ hostname } Can't Parse":
            NXOS_show_cdp_neighbors_template = env.get_template('NXOS_show_cdp_neighbors.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_cdp_neighbors_template.render(to_parse_cdp_neighbors=show_cdp_neighbors['cdp'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show CDP Neighbors.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show CDP Neighbors Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show CDP Neighbors.json", "w") as fh:
                    json.dump(show_cdp_neighbors, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_cdp_neighbors)
    except Exception as e:
        logging.exception(e)

def NXOS_show_cdp_neighbors_detail(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show CDP Neighbor Details to JSON

            try:
                show_cdp_neighbors_detail = device.parse("show cdp neighbors detail")
            except:
                show_cdp_neighbors_detail = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_cdp_neighbors_detail != f"{ hostname } Can't Parse":
            NXOS_show_cdp_neighbors_detail_template = env.get_template('NXOS_show_cdp_neighbors_detail.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_cdp_neighbors_detail_template.render(to_parse_cdp_neighbors=show_cdp_neighbors_detail['index'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show CDP Neighbor Details.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show CDP Neighbor Details Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show CDP Neighbor Details.json", "w") as fh:
                    json.dump(show_cdp_neighbors_detail, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_cdp_neighbors_detail)
    except Exception as e:
        logging.exception(e)

def NXOS_show_environment(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show Environment to JSON

            try:
                show_environment = device.parse("show environment")
            except:
                show_environment = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_environment != f"{ hostname } Can't Parse":
            NXOS_show_environment_template = env.get_template('NXOS_show_environment.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_environment_template.render(to_parse_environment=show_environment,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show Environment.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show Environment Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show Environment.json", "w") as fh:
                    json.dump(show_environment, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_environment)
    except Exception as e:
        logging.exception(e)

def NXOS_show_interface(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show Interface to JSON

            try:
                show_interface = device.parse("show interface")
            except:
                show_interface = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_interface != f"{ hostname } Can't Parse":
            NXOS_show_interface_template = env.get_template('NXOS_show_interface.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_interface_template.render(to_parse_interface=show_interface,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show Interface.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show Interface Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show Interface.json", "w") as fh:
                    json.dump(show_interface, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_interface)
    except Exception as e:
        logging.exception(e)

def NXOS_show_interface_status(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show Interface Status to JSON

            try:
                show_interface_status = device.parse("show interface status")
            except:
                show_interface_status = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_interface_status != f"{ hostname } Can't Parse":
            NXOS_show_interface_status_template = env.get_template('NXOS_show_interface_status.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_interface_status_template.render(to_parse_interface=show_interface_status,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show Interface Status.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show Interface Status Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show Interface Status.json", "w") as fh:
                    json.dump(show_interface_status, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_interface_status)
    except Exception as e:
        logging.exception(e)

def NXOS_show_interface_transceiver(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show Interface Transceiver to JSON

            try:
                show_interface_transceiver = device.parse("show interface transceiver")
            except:
                show_interface_transceiver = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_interface_transceiver != f"{ hostname } Can't Parse":
            NXOS_show_interface_transceiver_template = env.get_template('NXOS_show_interface_transceiver.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_interface_transceiver_template.render(to_parse_interface=show_interface_transceiver,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show Interface Transceiver.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show Interface Transceiver Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show Interface Transceiver.json", "w") as fh:
                    json.dump(show_interface_transceiver, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_interface_transceiver)
    except Exception as e:
        logging.exception(e)

def NXOS_show_inventory(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show Inventory to JSON

            try:
                show_inventory = device.parse("show inventory")
            except:
                show_inventory = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_inventory != f"{ hostname } Can't Parse":
            NXOS_show_inventory_template = env.get_template('NXOS_show_inventory.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_inventory_template.render(to_parse_inventory=show_inventory['name'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show Inventory.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show Inventory Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show Inventory.json", "w") as fh:
                    json.dump(show_inventory, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_inventory)
    except Exception as e:
        logging.exception(e)

def NXOS_show_ip_arp_vrf(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show VLAN to JSON

            try:
                show_vrf = device.parse("show vrf")
            except:
                show_vrf = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_vrf != f"{ hostname } Can't Parse":
        # For Each VRF
            for vrf in show_vrf['vrfs']:
                if not os.path.exists(f"{ vrf }"):
                    os.mkdir(f"{ vrf }")
                else:
                    print("Directory already exists") 

                try:
                    show_ip_arp_vrf = device.parse(f"show ip arp vrf { vrf} ")
                except:
                    show_ip_arp_vrf = f"{ hostname } Can't Parse"

        # Pass to template 

                if show_ip_arp_vrf != f"{ hostname } Can't Parse":
                    NXOS_show_ip_arp_vrf_template = env.get_template('NXOS_show_ip_arp_vrf.j2')
                    loop_counter = 0
        # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = NXOS_show_ip_arp_vrf_template.render(to_parse_ip_arp=show_ip_arp_vrf['interfaces'],filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"{ vrf }/{ filename }_Show IP ARP VRF {vrf }.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open(f"{ vrf }/{ filename }_Show IP ARP VRF {vrf } Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"{ vrf }/{ filename }_Show IP ARP VRF {vrf }.json", "w") as fh:
                            json.dump(show_ip_arp_vrf, fh, indent=4, sort_keys=True)
                            fh.close()
        return(show_ip_arp_vrf)
    except Exception as e:
        logging.exception(e)

def NXOS_show_ip_interface_brief(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

            try:
                show_ip_interface_brief = device.parse("show ip interface brief vrf all")
            except:
                show_ip_interface_brief = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_ip_interface_brief != f"{ hostname } Can't Parse":
            NXOS_show_ip_interface_brief_template = env.get_template('NXOS_show_ip_interface_brief.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_ip_interface_brief_template.render(to_parse_interfaces=show_ip_interface_brief['interface'],filetype_loop=loop_counter)
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
                with open(f"{ filename }_Show IP Interface Brief.json", "w") as fh:
                    json.dump(show_ip_interface_brief, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_ip_interface_brief)
    except Exception as e:
        logging.exception(e)

def NXOS_show_ip_ospf(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show IP OSPF to JSON

            try:
                show_ip_ospf = device.parse("show ip ospf")
            except:
                show_ip_ospf = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_ip_ospf != f"{ hostname } Can't Parse":
            NXOS_show_ip_ospf_template = env.get_template('NXOS_show_ip_ospf.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_ip_ospf_template.render(to_parse_ip_ospf=show_ip_ospf['vrf'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show IP OSPF.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show IP OSPF Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show IP OSPF.json", "w") as fh:
                    json.dump(show_ip_ospf, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_ip_ospf)
    except Exception as e:
        logging.exception(e)

def NXOS_show_ip_ospf_vrf(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show VLAN to JSON

            try:
                show_vrf = device.parse("show vrf")
            except:
                show_vrf = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_vrf != f"{ hostname } Can't Parse":
        # For Each VRF
            for vrf in show_vrf['vrfs']:
                if not os.path.exists(f"{ vrf }"):
                    os.mkdir(f"{ vrf }")
                else:
                    print("Directory already exists") 

                try:
                    show_ip_ospf_vrf = device.parse(f"show ip ospf vrf { vrf} ")
                except:
                    show_ip_ospf_vrf = f"{ hostname } Can't Parse"

        # Pass to template 

                if show_ip_ospf_vrf != f"{ hostname } Can't Parse":
                    NXOS_show_ip_ospf_vrf_template = env.get_template('NXOS_show_ip_ospf_vrf.j2')
                    loop_counter = 0
        # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = NXOS_show_ip_ospf_vrf_template.render(to_parse_ip_ospf=show_ip_ospf_vrf['vrf'],filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"{ vrf }/{ filename }_Show IP OSPF VRF {vrf }.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open(f"{ vrf }/{ filename }_Show IP OSPF VRF {vrf } Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"{ vrf }/{ filename }_Show IP OSPF VRF {vrf }.json", "w") as fh:
                            json.dump(show_ip_ospf_vrf, fh, indent=4, sort_keys=True)
                            fh.close()
        return(show_ip_ospf_vrf)
    except Exception as e:
        logging.exception(e)

def NXOS_show_ip_ospf_interface(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show IP OSPF Interface to JSON

            try:
                show_ip_ospf_interface = device.parse("show ip ospf interface")
            except:
                show_ip_ospf_interface = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_ip_ospf_interface != f"{ hostname } Can't Parse":
            NXOS_show_ip_ospf_interface_template = env.get_template('NXOS_show_ip_ospf_interface.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_ip_ospf_interface_template.render(to_parse_ip_ospf_interface=show_ip_ospf_interface['vrf'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show IP OSPF Interface.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show IP OSPF Interface Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show IP OSPF Interface.json", "w") as fh:
                    json.dump(show_ip_ospf_interface, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_ip_ospf_interface)
    except Exception as e:
        logging.exception(e)

def NXOS_show_ip_ospf_interface_vrf(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show VLAN to JSON

            try:
                show_vrf = device.parse("show vrf")
            except:
                show_vrf = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_vrf != f"{ hostname } Can't Parse":
        # For Each VRF
            for vrf in show_vrf['vrfs']:
                if not os.path.exists(f"{ vrf }"):
                    os.mkdir(f"{ vrf }")
                else:
                    print("Directory already exists") 

                try:
                    show_ip_ospf_interface_vrf = device.parse(f"show ip ospf interface vrf { vrf} ")
                except:
                    show_ip_ospf_interface_vrf = f"{ hostname } Can't Parse"

        # Pass to template 

                if show_ip_ospf_interface_vrf != f"{ hostname } Can't Parse":
                    NXOS_show_ip_ospf_interface_vrf_template = env.get_template('NXOS_show_ip_ospf_interface_vrf.j2')
                    loop_counter = 0
        # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = NXOS_show_ip_ospf_interface_vrf_template.render(to_parse_ip_ospf_interface=show_ip_ospf_interface_vrf['vrf'],filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"{ vrf }/{ filename }_Show IP OSPF Interface VRF {vrf }.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open(f"{ vrf }/{ filename }_Show IP OSPF Interface VRF {vrf } Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"{ vrf }/{ filename }_Show IP OSPF Interface VRF {vrf }.json", "w") as fh:
                            json.dump(show_ip_ospf_interface_vrf, fh, indent=4, sort_keys=True)
                            fh.close()
        return(show_ip_ospf_interface_vrf)
    except Exception as e:
        logging.exception(e)

def NXOS_show_ip_ospf_neighbors_detail(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show IP OSPF Neighbors Detail to JSON

            try:
                show_ip_ospf_neighbors_detail = device.parse("show ip ospf neighbors detail")
            except:
                show_ip_ospf_neighbors_detail = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_ip_ospf_neighbors_detail != f"{ hostname } Can't Parse":
            NXOS_show_ip_ospf_neighbors_detail_template = env.get_template('NXOS_show_ip_ospf_neighbors_detail.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_ip_ospf_neighbors_detail_template.render(to_parse_ip_ospf_neighbor=show_ip_ospf_neighbors_detail['vrf'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show IP OSPF Neighbors Detail.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show IP OSPF Neighbors Detail Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show IP OSPF Neighbors Detail.json", "w") as fh:
                    json.dump(show_ip_ospf_neighbors_detail, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_ip_ospf_neighbors_detail)
    except Exception as e:
        logging.exception(e)

def NXOS_show_ip_ospf_neighbors_detail_vrf(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show VLAN to JSON

            try:
                show_vrf = device.parse("show vrf")
            except:
                show_vrf = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_vrf != f"{ hostname } Can't Parse":
        # For Each VRF
            for vrf in show_vrf['vrfs']:
                if not os.path.exists(f"{ vrf }"):
                    os.mkdir(f"{ vrf }")
                else:
                    print("Directory already exists") 

                try:
                    show_ip_ospf_neighbors_detail_vrf = device.parse(f"show ip ospf neighbors detail vrf { vrf} ")
                except:
                    show_ip_ospf_neighbors_detail_vrf = f"{ hostname } Can't Parse"

        # Pass to template 

                if show_ip_ospf_neighbors_detail_vrf != f"{ hostname } Can't Parse":
                    NXOS_show_ip_ospf_neighbors_detail_vrf_template = env.get_template('NXOS_show_ip_ospf_neighbors_detail_vrf.j2')
                    loop_counter = 0
        # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = NXOS_show_ip_ospf_neighbors_detail_vrf_template.render(to_parse_ip_ospf_neighbor=show_ip_ospf_neighbors_detail_vrf['vrf'],filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"{ vrf }/{ filename }_Show IP OSPF Neighbors Detail VRF {vrf }.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open(f"{ vrf }/{ filename }_Show IP OSPF Neighbors Detail VRF {vrf } Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"{ vrf }/{ filename }_Show IP OSPF Neighbors Detail VRF {vrf }.json", "w") as fh:
                            json.dump(show_ip_ospf_neighbors_detail_vrf, fh, indent=4, sort_keys=True)
                            fh.close()
        return(show_ip_ospf_neighbors_detail_vrf)
    except Exception as e:
        logging.exception(e)

def NXOS_show_ip_route(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show IP Route to JSON

            try:
                show_ip_route = device.parse("show ip route")
            except:
                show_ip_route = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_ip_route != f"{ hostname } Can't Parse":
            NXOS_show_ip_route_template = env.get_template('NXOS_show_ip_route.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_ip_route_template.render(to_parse_ip_route=show_ip_route['vrf'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show IP Route.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show IP Route Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show IP Route.json", "w") as fh:
                    json.dump(show_ip_route, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_ip_route)
    except Exception as e:
        logging.exception(e)

def NXOS_show_ip_route_vrf(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show VLAN to JSON

            try:
                show_vrf = device.parse("show vrf")
            except:
                show_vrf = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_vrf != f"{ hostname } Can't Parse":
        # For Each VRF
            for vrf in show_vrf['vrfs']:
                if not os.path.exists(f"{ vrf }"):
                    os.mkdir(f"{ vrf }")
                else:
                    print("Directory already exists") 

                try:
                    show_ip_route_vrf = device.parse(f"show ip route vrf { vrf} ")
                except:
                    show_ip_route_vrf = f"{ hostname } Can't Parse"

        # Pass to template 

                if show_ip_route_vrf != f"{ hostname } Can't Parse":
                    NXOS_show_ip_route_vrf_template = env.get_template('NXOS_show_ip_route_vrf.j2')
                    loop_counter = 0
        # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = NXOS_show_ip_route_vrf_template.render(to_parse_ip_route=show_ip_route_vrf['vrf'],filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"{ vrf }/{ filename }_Show IP Route VRF {vrf }.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open(f"{ vrf }/{ filename }_Show IP Route VRF {vrf } Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"{ vrf }/{ filename }_Show IP Route VRF {vrf }.json", "w") as fh:
                            json.dump(show_ip_route_vrf, fh, indent=4, sort_keys=True)
                            fh.close()
        return(show_ip_route_vrf)
    except Exception as e:
        logging.exception(e)

def NXOS_show_mac_address_table(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show MAC Address Table to JSON

            try:
                show_mac_address_table = device.parse("show mac address-table")
            except:
                show_mac_address_table = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_mac_address_table != f"{ hostname } Can't Parse":
            NXOS_show_mac_address_table_template = env.get_template('NXOS_show_mac_address_table.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_mac_address_table_template.render(to_parse_mac_address_table=show_mac_address_table['mac_table'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show MAC Address Table.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show MAC Address Table Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show MAC Address Table.json", "w") as fh:
                    json.dump(show_mac_address_table, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_mac_address_table)
    except Exception as e:
        logging.exception(e)

def NXOS_show_port_channel_summary(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show Port Channel Summary to JSON

            try:
                show_port_channel_summary = device.parse("show port-channel summary")
            except:
                show_port_channel_summary = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_port_channel_summary != f"{ hostname } Can't Parse":
            NXOS_show_port_channel_summary_template = env.get_template('NXOS_show_port_channel_summary.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_port_channel_summary_template.render(to_parse_etherchannel_summary=show_port_channel_summary['interfaces'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show Port Channel Summary.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show Port Channel Summary Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show Port Channel Summary.json", "w") as fh:
                    json.dump(show_port_channel_summary, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_port_channel_summary)
    except Exception as e:
        logging.exception(e)

def NXOS_show_version(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show Version to JSON

            try:
                show_version = device.parse("show version")
            except:
                show_version = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_version != f"{ hostname } Can't Parse":
            NXOS_show_version_template = env.get_template('NXOS_show_version.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_version_template.render(to_parse_version=show_version['platform'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show Version.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show Version Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show Version.json", "w") as fh:
                    json.dump(show_version, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_version)
    except Exception as e:
        logging.exception(e)

def NXOS_show_vlan(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show VLAN to JSON

            try:
                show_vlan = device.parse("show vlan")
            except:
                show_vlan = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_vlan != f"{ hostname } Can't Parse":
            NXOS_show_vlan_template = env.get_template('NXOS_show_vlan.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_vlan_template.render(to_parse_vlan=show_vlan['vlans'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show VLAN.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show VLAN Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show VLAN.json", "w") as fh:
                    json.dump(show_vlan, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_vlan)
    except Exception as e:
        logging.exception(e)

def NXOS_show_vrf(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show VLAN to JSON

            try:
                show_vrf = device.parse("show vrf")
            except:
                show_vrf = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_vrf != f"{ hostname } Can't Parse":
            NXOS_show_vrf_template = env.get_template('NXOS_show_vrf.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_vrf_template.render(to_parse_vrf=show_vrf['vrfs'],filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show VRF All Detail.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show VRF All Detail Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show VRF All Detail.json", "w") as fh:
                    json.dump(show_vrf, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_vrf)
    except Exception as e:
        logging.exception(e)

def NXOS_show_vrf_detail(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show VLAN to JSON

            try:
                show_vrf = device.parse("show vrf")
            except:
                show_vrf = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_vrf != f"{ hostname } Can't Parse":
        # For Each VRF
            for vrf in show_vrf['vrfs']:
                if not os.path.exists(f"{ vrf }"):
                    os.mkdir(f"{ vrf }")
                else:
                    print("Directory already exists") 

                try:
                    show_vrf_detail = device.parse(f"show vrf { vrf } detail")
                except:
                    show_vrf_detail = f"{ hostname } Can't Parse"

        # Pass to template 

                if show_vrf_detail != f"{ hostname } Can't Parse":
                    NXOS_show_vrf_detail_template = env.get_template('NXOS_show_vrf_detail.j2')
                    loop_counter = 0
        # Render Templates
                    for filetype in filetype_loop:
                        parsed_output = NXOS_show_vrf_detail_template.render(to_parse_vrf=show_vrf_detail,filetype_loop=loop_counter)
                        loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                        if loop_counter <= 3:
                            with open(f"{ vrf }/{ filename }_Show VRF { vrf } Detail.{ filetype }", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        else:
                            with open(f"{ vrf }/{ filename }_Show VRF { vrf } Detail Mind Map.md", "w") as fh:
                                fh.write(parsed_output)               
                                fh.close()
                        with open(f"{ vrf }/{ filename }_Show VRF { vrf } Detail.json", "w") as fh:
                            json.dump(show_vrf_detail, fh, indent=4, sort_keys=True)
                            fh.close()
        return(show_vrf_detail)
    except Exception as e:
        logging.exception(e)

def NXOS_show_vrf_all_detail(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show VLAN to JSON

            try:
                show_vrf_all_detail = device.parse("show vrf all detail")
            except:
                show_vrf_all_detail = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_vrf_all_detail != f"{ hostname } Can't Parse":
            NXOS_show_vrf_all_detail_template = env.get_template('NXOS_show_vrf_all_detail.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_vrf_all_detail_template.render(to_parse_vrf=show_vrf_all_detail,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show VRF All Detail.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show VRF All Detail Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show VRF All Detail.json", "w") as fh:
                    json.dump(show_vrf_all_detail, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_vrf_all_detail)
    except Exception as e:
        logging.exception(e)

def NXOS_show_vrf_all_interface(hostname, username, password, ip):
    try:
    # Create Testbed
        filename = hostname
        first_testbed = Testbed('dynamicallyCreatedTestbed')
        testbed_device = Device(hostname,
                    alias = hostname,
                    type = 'switch',
                    os = 'nxos',
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

        # Show VLAN to JSON

            try:
                show_vrf_all_interface = device.parse("show vrf all interface")
            except:
                show_vrf_all_interface = f"{ hostname } Can't Parse"

        # Pass to template 

        if show_vrf_all_interface != f"{ hostname } Can't Parse":
            NXOS_show_vrf_all_interface_template = env.get_template('NXOS_show_vrf_all_interface.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = NXOS_show_vrf_all_interface_template.render(to_parse_vrf=show_vrf_all_interface,filetype_loop=loop_counter)
                loop_counter = loop_counter + 1

    # -------------------------
    # Save the files
    # -------------------------
                if loop_counter <= 3:
                    with open(f"{ filename }_Show VRF All Interface.{ filetype }", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                else:
                    with open(f"{ filename }_Show VRF All Interface Mind Map.md", "w") as fh:
                        fh.write(parsed_output)               
                        fh.close()
                with open(f"{ filename }_Show VRF All Interface.json", "w") as fh:
                    json.dump(show_vrf_all_interface, fh, indent=4, sort_keys=True)
                    fh.close()                                 
        return(show_vrf_all_interface)
    except Exception as e:
        logging.exception(e)        