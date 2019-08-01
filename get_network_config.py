#!/usr/bin/python3
# Author: Scott Chubb scott.chubb@netapp.com
# Written for Python 3.4 and above
# No warranty is offered, use at your own risk.  While these scripts have been
#   tested in lab situations, all use cases cannot be accounted for.
# This script gets the network config from a single node for a node replacment
#
# Example output
# +--------+---------------+---------------+-------------+------+---------------+------------+---------------------------+
# |  Bond  |    Address    |    Netmask    |   Gateway   | MTU  |   Bond-mode   | Link Speed |        DNS servers        |
# +--------+---------------+---------------+-------------+------+---------------+------------+---------------------------+
# | Bond1G | 192.168.1.100 | 255.255.255.0 | 192.168.1.1 | 1500 | ActivePassive |    1000    | 1.1.1.1, 2.2.2.2, 3.3.3.3 |
# +--------+---------------+---------------+-------------+------+---------------+------------+---------------------------+
# +---------------------------------------------------------------------------------+
# | Routing Information                                                             |
# +---------------------------------------------------------------------------------+
# | ip route add 192.168.1.0/24 dev Bond1G src 192.168.1.100 table Bond1G           |
# | ip route add default via 192.168.1.1 dev Bond1G src 192.1688.1.100 table Bond1G |
# | ip rule add from 10.68.225.216 table Bond1G                                     |
# | ip route add default via 10.68.225.1                                            |
# +---------------------------------------------------------------------------------+


# +---------+----------------+---------------+---------------+------+-----------+------------+---------------------------+
# |   Bond  |    Address     |    Netmask    |   Gateway     | MTU  | Bond-mode | Link Speed |        DNS servers        |
# +---------+----------------+---------------+---------------+------+-----------+------------+---------------------------+
# | Bond10G | 169.254.1.100  | 255.255.252.0 | 169.254.1.100 | 9000 |    LACP   |   20000    | 1.1.1.1, 2.2.2.2, 3.3.3.3 |
# +---------+----------------+---------------+---------------+------+-----------+------------+---------------------------+
# +-------------------------------------------------------------------------------------+
# | Routing Information                                                                 |
# +-------------------------------------------------------------------------------------+
# | ip route add 169.254.1.0/22 dev Bond10G src 169.254.1.100 table Bond10G             |
# | ip route add default via 169.254.1.100  dev Bond10G src 169.254.1.100 table Bond10G |
# | ip rule add from 169.254.1.100 table Bond10G                                        |
# +-------------------------------------------------------------------------------------+
import json
import base64
import argparse
import requests
from getpass import getpass
from prettytable import PrettyTable

def get_inputs():
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', type=str,
                        required=True,
                        metavar='mvip',
                        help='MVIP/node name or IP')
    parser.add_argument('-u', type=str,
                        required=True,
                        metavar='username',
                       help='username to connect with')
    parser.add_argument('-p', type=str,
                        required=False,
                        metavar='password',
                        help='password for user')
    parser.add_argument('-i', type=int,
                        required=False,
                        metavar='nodeID',
                        help='nodeID to gather from')
    parser.add_argument('-n', type=str,
                        required=False,
                        metavar='nodeName',
                        help='nodeID to gather from')
    args = parser.parse_args()

    mvip = args.m
    user = args.u
    if args.i != None:
        node_id = args.i
    else:
        node_id = None
    if args.n !=None:
        node_name = args.n
    else:
        node_name = None
    if not args.p:
        user_pass = getpass("Enter password for user {} "
                            "on cluster {}: ".format(user,
                                                     mvip))
    else:
        user_pass = args.p
    return mvip, user, user_pass, node_id, node_name

def build_auth(mvip, user, user_pass):
    auth = (user + ":" + user_pass)
    encodeKey = base64.b64encode(auth.encode('utf-8'))
    basicAuth = bytes.decode(encodeKey)

    # Be certain of your API version path here
    url = "https://" + mvip + "/json-rpc/9.0"
    
    headers = {
        'Content-Type': "application/json",
        'Authorization': "Basic %s" % basicAuth,
        'Cache-Control': "no-cache",
        }

    return headers, url    

def build_payload():
    payload = json.dumps({"method": "GetNetworkConfig","params":{"force": True},"id": 1})
    #payload = json.dumps({"method": "ListReports","params":{},"id": 1})
    return payload
    
def connect_cluster(headers, url, payload):
    response = requests.request("POST", url, data=payload, headers=headers, verify=False)
    response_json = json.loads(response.text)
    print("Status code is: {}".format(response.status_code))
    return response_json

def build_node_name_payload(headers, url, node_id=None, node_name=None):
    """
    ListActiveNodes API call to get node name
    """    
    payload = json.dumps({"method": "ListActiveNodes","params":{},"id": 1})
    active_nodes_json = connect_cluster(headers, url, payload)
    if node_id == None:
        for node in active_nodes_json['result']['nodes']:
            if node['name'] == node_name:
                node_id = node['nodeID']
                node_name = node_name
    if node_name == None:
        for node in active_nodes_json['result']['nodes']:
            if node['nodeID'] == node_id:
                node_name = (node['name'])
                node_id = node_id
    return node_name, node_id

def build_cluster_hardware_payload(headers, url):
    """
    GetClusterHardwareInfo API call to get service tag
    """
    payload = json.dumps({"method": "GetClusterHardwareInfo","params":{},"id": 1})
    cluster_hardware_json = connect_cluster(headers, url, payload)
    return cluster_hardware_json
    
def get_hardware_info(cluster_hardware_json):
    s_tag_dict = {}
    for node in cluster_hardware_json['result']['clusterHardwareInfo']['nodes']:
        node_id = node
        s_tag = cluster_hardware_json['result']['clusterHardwareInfo']['nodes'][str(node)]['chassisSerial']
        s_tag_dict[node_id] = s_tag
    return s_tag_dict

def parse_s_tag_dict(s_tag_dict, node_id):
    print("CSCOTT1: {}".format(s_tag_dict['28']))
    if s_tag_dict[str(key)] == node_id:
        print("CSCOTT2: {}".format(s_tag_dict[str(node_id)]))
    
def build_10g(response_json, node_id):
    for node in response_json['result']['nodes']:
        if node['nodeID'] == node_id:
            bond = "Bond10G"
            addr = node['result']['network']['Bond10G']['address']
            bond_mode = node['result']['network']['Bond10G']['bond-mode']
            dns_servers = node['result']['network']['Bond10G']['dns-nameservers']
            mtu = node['result']['network']['Bond10G']['mtu']
            link_speed = node['result']['network']['Bond10G']['linkSpeed']
            mask = node['result']['network']['Bond10G']['physical']['netmask']
            gateway = node['result']['network']['Bond10G']['gateway']
            routes = node['result']['network']['Bond10G']['symmetricRouteRules']

    return bond, addr, bond_mode, dns_servers, mtu, link_speed, mask, gateway, routes

def build_1g(response_json, node_id):
    for node in response_json['result']['nodes']:
        if node['nodeID'] == node_id:
            bond = "Bond1G"
            addr = node['result']['network']['Bond1G']['address']
            bond_mode = node['result']['network']['Bond1G']['bond-mode']
            dns_servers = node['result']['network']['Bond1G']['dns-nameservers']
            mtu = node['result']['network']['Bond1G']['mtu']
            link_speed = node['result']['network']['Bond1G']['linkSpeed']
            mask = node['result']['network']['Bond1G']['physical']['netmask']
            gateway = node['result']['network']['Bond1G']['gateway']
            routes = node['result']['network']['Bond1G']['symmetricRouteRules']

    return bond, addr, bond_mode, dns_servers, mtu, link_speed, mask, gateway, routes

def build_output_table(bond, addr, bond_mode, dns_servers, mtu, link_speed, mask, gateway, routes):
    network_table = PrettyTable()
    network_table.field_names = ["Bond", "Address", "Netmask", "Gateway", "MTU", "Bond-mode", "Link Speed", "DNS servers"]
    network_table.add_row([bond, addr, mask, gateway, mtu, bond_mode, link_speed, dns_servers])
    print(network_table)
    route_table = PrettyTable()
    route_table.field_names = ["Routing Information"]
    route_table.align["Routing Information"] = "l"
    for route in routes:
        route_table.add_row([route])
    print(route_table)
    print("\n\r")

def main():
    mvip, user, user_pass, node_id, node_name = get_inputs()
    headers, url = build_auth(mvip, user, user_pass)
    payload = build_payload()
    response_json = connect_cluster(headers, url, payload)
    cluster_hardware_json = build_cluster_hardware_payload(headers, url)
    node_name, node_id = build_node_name_payload(headers, url, node_id, node_name)
    s_tag_dict = get_hardware_info(cluster_hardware_json)
    parse_s_tag_dict(s_tag_dict, node_id)
    print("Cluster name: {}\nNode name: {}\nNode ID: {}".format(mvip, node_name, node_id))
    bond, addr, bond_mode, dns_servers, mtu, link_speed, mask, gateway, routes = build_1g(response_json, node_id)
    bond1g_table = build_output_table(bond, addr, bond_mode, dns_servers, mtu, link_speed, mask, gateway, routes)
    bond, addr, bond_mode, dns_servers, mtu, link_speed, mask, gateway, routes = build_10g(response_json, node_id)
    bond10g_table = build_output_table(bond, addr, bond_mode, dns_servers, mtu, link_speed, mask, gateway, routes)
    
if __name__ == "__main__":
    main()
