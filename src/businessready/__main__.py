import sys
from .brd import IOS_show_ip_interface_brief,DNAC_Sites
if __name__ == "__main__":
    print(IOS_show_ip_interface_brief(sys.argv[1]))
    print(DNAC_Sites(sys.argv[1]))