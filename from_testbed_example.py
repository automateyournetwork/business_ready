import businessready
import yaml

with open('testbed.yml') as info:
    info_dict = yaml.safe_load(info)

for device in info_dict['devices']:
    if info_dict['devices'][device]['os'] == "iosxe":
        businessready.IOS_learn_all(device,info_dict['devices'][device]['credentials']['default']['username'],info_dict['devices'][device]['credentials']['default']['password'],info_dict['devices'][device]['connections']['cli']['ip'])
    elif info_dict['devices'][device]['os'] == "nxos":
        businessready.NXOS_learn_all(device,info_dict['devices'][device]['credentials']['default']['username'],info_dict['devices'][device]['credentials']['default']['password'],info_dict['devices'][device]['connections']['cli']['ip'])