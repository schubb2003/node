#!/usr/bin/python
# Author: Scott Chubb scott.chubb@netapp.com
# Written for Python 3.4 and above
# No warranty is offered, use at your own risk.  While these scripts have been tested in lab situations, all use cases cannot be accounted for.
# Change sf-mvip.demo.netapp.com to your MVIP name or IP
# Change admin to your user account
# Change Netapp1! to your password
# Updated: 16-Jul
#   removed prettytable module import as it was not needed
#   removed extraneous print statement that doubled output
#   added two new lines to make output move visible

import json
import base64
import argparse
import requests
from getpass import getpass

node_list = ["solidfire-bel-001","solidfire-bel-002","solidfire-bel-004","solidfire-bel-005"]

def get_inputs():
    # parser = argparse.ArgumentParser()
    # parser.add_argument('-m', type=str,
                        # required=True,
                        # metavar='mvip',
                        # help='MVIP/node name or IP')
    parser.add_argument('-u', type=str,
                        required=True,
                        metavar='username',
                        help='username to connect with')
    parser.add_argument('-p', type=str,
                        required=False,
                        metavar='password',
                        help='password for user')
    args = parser.parse_args()

    #mvip = args.m
    user = args.u
    if not args.p:
        user_pass = getpass("Enter password for user: {}".format(user))
    else:
        user_pass = args.p
    
    return user, user_pass

def build_auth(mvip, user, user_pass):
    auth = (user + ":" + user_pass)
    encodeKey = base64.b64encode(auth.encode('utf-8'))
    basicAuth = bytes.decode(encodeKey)

    # Be certain of your API version path here
    url = "https://" + mvip + "/json-rpc/10.0"
    
    headers = {
        'Content-Type': "application/json",
        'Authorization': "Basic %s" % basicAuth,
        'Cache-Control': "no-cache",
        }

    return headers, url    

def build_cluster_hardware_payload(headers, url):
    """
    GetClusterHardwareInfo API call to get service tag
    """
    s_tag_dict = {}
    payload = json.dumps({"method": "GetClusterHardwareInfo","params":{},"id": 1})
    cluster_hardware_json = connect_cluster(headers, url, payload)
    for node in cluster_hardware_json['result']['clusterHardwareInfo']['nodes']:
        node_id = node
        s_tag = cluster_hardware_json['result']['clusterHardwareInfo']['nodes'][str(node)]['chassisSerial']
        s_tag_dict[node_id] = s_tag
    return s_tag_dict

def build_active_nodes_payload(headers, url):
    """
    ListActiveNodes API call to get node name
    """    
    node_dict = {}
    payload = json.dumps({"method": "ListActiveNodes","params":{},"id": 1})
    active_nodes_json = connect_cluster(headers, url, payload)
    for node in active_nodes_json['result']['nodes']:
        node_id = (node['nodeID'])
        node_name = (node['name'])
        node_dict[node_id] = node_name
    return node_dict
    
def connect_cluster(headers, url, payload):
    response = requests.request("POST", url, data=payload, headers=headers, verify=False)
    response_json = json.loads(response.text)
    return response_json

def merge_dictionary(s_tag_dict, node_dict):
    """
    Merge the dictionaries with the entries into a single one
    """
    node_name_s_tag_node_id = {k:v for k in s_tag_dict.keys() for v in zip(s_tag_dict.values(),node_dict.values())}
    return node_name_s_tag_node_id
    
def main(user, user_pass, node_list):
    for node in node_list:
        mvip=node
        headers, url = build_auth(mvip, user, user_pass)
        s_tag_dict = build_cluster_hardware_payload(headers, url)
        node_dict = build_active_nodes_payload(headers, url)
        node_name_s_tag_node_id = merge_dictionary(s_tag_dict, node_dict)
        print("\n\n{}".format(node_name_s_tag_node_id))
    
if __name__ == "__main__":
    user, user_pass = get_inputs()
    main(user, user_pass)
