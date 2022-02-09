import sys
from .brd import IOS_learned_arp
def run():
    print(IOS_learned_arp(*sys.argv[1:3]))