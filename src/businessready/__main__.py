import sys
from .brd import IOS_learned_acl,IOS_learned_arp,IOS_learned_interface,IOS_show_ip_interface_brief,DNAC_Sites
if __name__ == "__main__":
    print(IOS_learned_acl(sys.argv[1]))
    print(IOS_learned_arp(sys.argv[1]))
    print(IOS_learned_arp(sys.argv[1]))
    print(IOS_learned_interface(sys.argv[1]))
    print(DNAC_Sites(sys.argv[1]))