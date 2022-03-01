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