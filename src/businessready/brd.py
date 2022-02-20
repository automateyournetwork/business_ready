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
    DNAC_devices(url, username, password)
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
                parsed_output = IOS_learn_ospf_template.render(to_parse_routing=learn_ospf['vrf'],filetype_loop=loop_counter)
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