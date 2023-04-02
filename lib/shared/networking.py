import re
from netaddr import IPNetwork, IPRange


def processRanges(ranges) -> list:
    """Function will take a string representation of a range for IPv4 or IPv6 in CIDR or Range format and return a list of IPs.

    Args:
        ranges (list): List of strings representing ranges of IPs.

    Returns:
        
    """
    ip_list = []
    for entry in ranges:
        try:
            range_vals = []
            if re.match(r"\S*/\S*", entry):
                ip_list.append(IPNetwork(entry))

            elif re.match(r"\S*-\S*", entry):
                range_vals.extend(entry.split("-"))
                if len(range_vals) == 2:
                    ip_list.append(IPRange(range_vals[0], range_vals[1]))
            else:
                print(f"Range: {entry} provided is not valid")
        except Exception:
            print(Exception)
            print(f"Range: {entry} provided is not valid")

    return ip_list