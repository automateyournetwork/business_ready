# ----------------
# Copyright
# ----------------
# Written by John Capobianco, February 2022
# Copyright (c) 2022 John Capobianco

from pathlib import Path
import logging
import requests
import json
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
            try:
                learned_acl = device.learn("acl").info
            except:
                learned_acl = f"{ hostname } Has NO ACLs to Learn"

        # Pass to template 

        if learned_acl != f"{ hostname } Has NO ACLs to Learn":
            IOS_learned_acl_template = env.get_template('IOS_learned_acl.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learned_acl_template.render(to_parse_access_list=learned_acl['acls'],filetype_loop=loop_counter)
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
                    json.dump(learned_acl, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learned_acl)
    except Exception as e:
        logging.exception(e)

def IOS_learned_arp(hostname, username, password, ip):
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
                learned_arp = device.learn("arp").info
            except:
                learned_arp = f"{ hostname } has no ARP to Learn"

        # Pass to template 

        if learned_arp != f"{ hostname } has no ARP to Learn":
            IOS_learned_arp_template = env.get_template('IOS_learned_arp.j2')
            IOS_learned_arp_statistics_template = env.get_template('IOS_learned_arp_statistics.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output_statistics = IOS_learned_arp_statistics_template.render(to_parse_arp=learned_arp['statistics'],filetype_loop=loop_counter)
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
                    json.dump(learned_arp['statistics'], fh, indent=4, sort_keys=True)
                    fh.close()

        # Render Templates
            loop_counter = 0
            for filetype in filetype_loop:
                parsed_output = IOS_learned_arp_template.render(to_parse_arp=learned_arp['interfaces'],filetype_loop=loop_counter)
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
                    json.dump(learned_arp, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learned_arp)
    except Exception as e:
        logging.exception(e)

def IOS_learned_dot1x(hostname, username, password, ip):
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
                learned_dot1x = device.learn("dot1x").info
            except:
                learned_dot1x = f"{ hostname } has no dot1x to Learn"
        # Pass to template 

        if learned_dot1x != f"{ hostname } has no dot1x to Learn":
            IOS_learned_dot1x_template = env.get_template('IOS_learned_dot1x.j2')
            IOS_learned_dot1x_sessions_template = env.get_template('IOS_learned_dot1x_sessions.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output_statistics = IOS_learned_dot1x_sessions_template.render(to_parse_dot1x=learned_dot1x,filetype_loop=loop_counter)
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
                parsed_output = IOS_learned_dot1x_template.render(to_parse_dot1x=self.learned_dot1x,filetype_loop=loop_counter)
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
                    json.dump(learned_dot1x, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learned_dot1x)
    except Exception as e:
        logging.exception(e)

def IOS_learned_interface(hostname, username, password, ip):
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
                learned_interface = device.learn("interface").info
            except:
                learned_interface = f"{ hostname } has no Interface to Learn"

        # Pass to template 

        if learned_interface != f"{ hostname } has no Interface to Learn":
            IOS_learned_interface_template = env.get_template('IOS_learned_interface.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learned_interface_template.render(to_parse_interface=learned_interface,filetype_loop=loop_counter)
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
                    json.dump(learned_interface, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learned_interface)
    except Exception as e:
        logging.exception(e)

def IOS_learned_lldp(hostname, username, password, ip):
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
                learned_lldp = device.learn("lldp").info
            except:
                learned_lldp = f"{ hostname } has no LLDP to Learn"

        # Pass to template 

        if learned_lldp != f"{ hostname } has no LLDP to Learn":
            IOS_learned_lldp_template = env.get_template('IOS_learned_lldp.j2')
            IOS_learned_lldp_interfaces_template = env.get_template('learned_lldp_interfaces.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learned_lldp_template.render(to_parse_lldp=self.learned_lldp,filetype_loop=loop_counter)
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
                    json.dump(learned_lldp, fh, indent=4, sort_keys=True)
                    fh.close()

            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learned_lldp_interfaces_template.render(to_parse_lldp=self.learned_lldp['interfaces'],filetype_loop=loop_counter)
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
                    json.dump(learned_lldp, fh, indent=4, sort_keys=True)
                    fh.close()

        return(learned_lldp)
    except Exception as e:
        logging.exception(e)

def IOS_learned_ntp(hostname, username, password, ip):
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
                learned_ntp = device.learn("ntp").info
            except:
                learned_ntp = f"{ hostname } has no NTP to Learn"

        # Pass to template 

        if learned_ntp != f"{ hostname } has no NTP to Learn":
            IOS_learned_ntp_template = env.get_template('IOS_learned_ntp.j2')
            IOS_learned_ntp_associations_template = env.get_template('learned_ntp_associations.j2')
            IOS_learned_ntp_unicast_template = env.get_template('learned_ntp_unicast.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learned_lldp_template.render(to_parse_ntp=learned_ntp['clock_state'],filetype_loop=loop_counter)
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
                    json.dump(learned_ntp, fh, indent=4, sort_keys=True)
                    fh.close()

            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learned_ntp_associations_template.render(to_parse_ntp=learned_ntp['vrf'],filetype_loop=loop_counter)
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
                    json.dump(learned_ntp, fh, indent=4, sort_keys=True)
                    fh.close()

            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learned_ntp_unicast_template.render(to_parse_ntp=learned_ntp['vrf'],filetype_loop=loop_counter)
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
                    json.dump(learned_ntp, fh, indent=4, sort_keys=True)
                    fh.close()

        return(learned_ntp)
    except Exception as e:
        logging.exception(e)

def IOS_learned_ospf(hostname, username, password, ip):
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
                learned_ospf = device.learn("ospf").info
            except:
                learned_ospf = f"{ hostname } has no OSPF to Learn"

        # Pass to template 

        if learned_ospf != f"{ hostname } has no OSPF to Learn":
            IOS_learned_ospf_template = env.get_template('IOS_learned_ospf.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learned_ospf_template.render(to_parse_routing=learned_ospf['vrf'],filetype_loop=loop_counter)
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
                    json.dump(learned_ospf, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learned_ospf)
    except Exception as e:
        logging.exception(e)

def IOS_learned_routing(hostname, username, password, ip):
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
                learned_routing = device.learn("routing").info
            except:
                learned_routing = f"{ hostname } has no Routing to Learn"

        # Pass to template 

        if learned_routing is not None:
            IOS_learned_routing_template = env.get_template('IOS_learned_routing.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learned_routing_template.render(to_parse_routing=learned_routing['vrf'],filetype_loop=loop_counter)
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
                    json.dump(learned_routing, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learned_routing)
    except Exception as e:
        logging.exception(e)

def IOS_learned_stp(hostname, username, password, ip):
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
                learned_stp = device.learn("stp").info
            except:
                learned_stp = f"{ hostname } Has No STP to Learn"

        # Pass to template 

        if learned_stp != f"{ hostname } Has No STP to Learn":
            IOS_learned_stp_template = env.get_template('IOS_learned_stp.j2')
            IOS_learned_stp_rpvst_template = env.get_template('IOS_learned_stp_rpvst.j2')
            IOS_learned_stp_mstp_template = env.get_template('IOS_learned_stp_mstp.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learned_stp_template.render(to_parse_stp=learned_stp['global'],filetype_loop=loop_counter)
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
                    json.dump(learned_stp, fh, indent=4, sort_keys=True)
                    fh.close()
            loop_counter = 0

        # Render Templates
            if "rapid_pvst" in learned_stp:
                for filetype in filetype_loop:
                    parsed_output = IOS_learned_stp_template.render(to_parse_stp=learned_stp['rapid_pvst'],filetype_loop=loop_counter)
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
                        json.dump(learned_stp, fh, indent=4, sort_keys=True)
                        fh.close()

        # Render Templates
            if learned_stp['mstp']: 
                for filetype in filetype_loop:
                    parsed_output = IOS_learned_stp_mstp_template.render(to_parse_stp=learned_stp['mstp'],filetype_loop=loop_counter)
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
                        json.dump(learned_stp, fh, indent=4, sort_keys=True)
                        fh.close()                        
        return(learned_stp)
    except Exception as e:
        logging.exception(e)

def IOS_learned_vlan(hostname, username, password, ip):
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
                learned_vlan = device.learn("vlan").info
            except:
                learned_vlan = f"{ hostname } Has No VLANs to Learn"
            
        # Pass to template 

        if learned_vlan != f"{ hostname } Has No VLANs to Learn":
            IOS_learned_vlan_template = env.get_template('IOS_learned_vlan.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learned_vlan_template.render(to_parse_vlan=learned_vlan['vlans'],filetype_loop=loop_counter)
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
                    json.dump(learned_vlan, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learned_vlan)
    except Exception as e:
        logging.exception(e)

def IOS_learned_vrf(hostname, username, password, ip):
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
                learned_vrf = device.learn("vrf").info
            except:
                learned_vrf = f"{ hostname } Has No VRFs to Learn"
            
        # Pass to template 

        if learned_vrf != f"{ hostname } Has No VRFs to Learn":
            IOS_learned_vrf_template = env.get_template('IOS_learned_vrf.j2')
            loop_counter = 0
        # Render Templates
            for filetype in filetype_loop:
                parsed_output = IOS_learned_vrf_template.render(to_parse_vrf=learned_vrf['vrfs'],filetype_loop=loop_counter)
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
                    json.dump(learned_vrf, fh, indent=4, sort_keys=True)
                    fh.close()
        return(learned_vrf)
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