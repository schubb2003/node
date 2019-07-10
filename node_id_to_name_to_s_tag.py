#!/usr/bin/python
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
    args = parser.parse_args()

    mvip = args.m
    user = args.u
    if not args.p:
        user_pass = getpass("Enter password for user: {} "
                            "on cluster {}: ".format(user,
                                                    mvip))
    else:
        user_pass = args.p
    
    return mvip, user, user_pass

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
    s_tag_dict = {}
    payload = json.dumps({"method": "GetClusterHardwareInfo","params":{},"id": 1})
    cluster_hardware_json = connect_cluster(headers, url, payload)
    for node in cluster_hardware_json['result']['clusterHardwareInfo']['nodes']:
        node_id = node
        s_tag = cluster_hardware_json['result']['clusterHardwareInfo']['nodes'][str(node)]['chassisSerial']
        s_tag_dict[node_id] = s_tag
    print("S_Tag: {}".format(s_tag_dict))
    return s_tag_dict

def build_active_nodes_payload(headers, url):
    node_dict = {}
    payload = json.dumps({"method": "ListActiveNodes","params":{},"id": 1})
    active_nodes_json = connect_cluster(headers, url, payload)
    for node in active_nodes_json['result']['nodes']:
        node_id = (node['nodeID'])
        node_name = (node['name'])
        node_dict[node_id] = node_name
    print("Nodes: {}".format(node_dict))
    return node_dict
    
def connect_cluster(headers, url, payload):
    response = requests.request("POST", url, data=payload, headers=headers, verify=False)
    response_json = json.loads(response.text)
    return response_json

def merge_dictionary(s_tag_dict, node_dict):
    node_name_s_tag_node_id = {k:v for k in s_tag_dict.keys() for v in zip(s_tag_dict.values(),node_dict.values())}
    return node_name_s_tag_node_id
    
def main():
    mvip, user, user_pass = get_inputs()
    headers, url = build_auth(mvip, user, user_pass)
    s_tag_dict = build_cluster_hardware_payload(headers, url)
    node_dict = build_active_nodes_payload(headers, url)
    node_name_s_tag_node_id = merge_dictionary(s_tag_dict, node_dict)
    print(node_name_s_tag_node_id)
    
if __name__ == "__main__":
    main()
