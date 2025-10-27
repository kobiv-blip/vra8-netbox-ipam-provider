"""
Copyright (c) 2020 VMware, Inc.
 
Modified for NetBox by Kobi Vaknin(kobiv@terasky.com)
 
This product is licensed to you under the Apache License, Version 2.0 (the "License").
You may not use this product except in compliance with the License.
 
This product may include a number of subcomponents with separate copyright notices
and license terms. Your use of these subcomponents is subject to the terms and
conditions of the subcomponent's license, as noted in the LICENSE file.
"""
import requests
from vra_ipam_utils.ipam import IPAM
import logging
from requests.packages import urllib3
import ipaddress
 
def handler(context, inputs):
    ipam = IPAM(context, inputs)
    IPAM.do_get_ip_ranges = do_get_ip_ranges
    return ipam.get_ip_ranges()
 
def do_get_ip_ranges(self, auth_credentials, cert):
    try:
        endpoint_props = self.inputs.get("endpoint", {}).get("endpointProperties", {})
        ignore_ssl = str(endpoint_props.get("ignore_ssl", "false"))
        verify = False if ignore_ssl.lower() == "true" else True
        if not verify:
            urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)
    except Exception as e:
        raise Exception("Error handling SSL verification setting: " + str(e))
 
    netbox_object = endpoint_props.get("netboxObject")
    #netbox_tag = endpoint_props.get("netboxTag")
    netbox_url = endpoint_props.get("hostName")
    #netbox_site = endpoint_props.get("netboxSite")
 
    if not all([netbox_object, netbox_url]):
        raise Exception("Missing required NetBox properties: object, URL, or site.")
 
    username = auth_credentials.get("privateKeyId")
    token = auth_credentials.get("privateKey")
    headers = {"Authorization": f"Token {token}"}
 
    logging.info("Collecting ranges")
 
    # Get all results with pagination
    all_results = []
    url = f"{netbox_url}/api/ipam/{netbox_object}/?limit=1000"
    while url:
        response = requests.get(url, verify=verify, headers=headers)
        data = response.json()
        results = data.get("results", [])
        all_results.extend(results)
        # Get the next page URL
        url = data.get("next")
        logging.info(f"Retrieved {len(results)} records, total so far: {len(all_results)}")
 
    result_ranges = []
    print(all_results)
 
    if netbox_object == "prefixes":
        for prefix in all_results:
            try:
                subnet_str = prefix.get("prefix")
                if not subnet_str:
                    continue
                
                # Parse the network and determine IP version
                subnet = ipaddress.ip_network(str(subnet_str))
                
                # Skip IPv6 addresses as they're not supported by the target system
                if subnet.version == 6:
                    logging.info(f"Skipping IPv6 prefix: {subnet_str}")
                    continue
 
                vlan = prefix.get("vlan") or {}
                vlan_name = vlan.get("name", "NA")
                description = prefix.get("description")
                full_name = f"{subnet_str}_{description}"

                # Extract tags from the prefix
                tags = prefix.get("tags", [])
                tag_list = []
                for tag in tags:
                    tag_info = {
                        "name": tag.get("name", ""),
                        "slug": tag.get("slug", ""),
                        "color": tag.get("color", "")
                    }
                    tag_list.append(tag_info)
 
                network_range = {
                    "id": str(prefix.get('id', '')),
 
                    "name": full_name,
 
                    "startIPAddress": str(subnet[2]),
 
                    "endIPAddress": str(subnet[-2]),
 
                    "ipVersion": "IPv4",
 
                    "subnetPrefixLength": str(subnet.prefixlen),
 
                    "gatewayAddress": str(subnet[1])
                    
                }
 
                if "domain" in endpoint_props:
                    network_range["domain"] = endpoint_props["domain"]
                else:
                    logging.info(f"Domain variable not set. Ignoring.")
 
                result_ranges.append(network_range)
 
            except Exception as e:
                logging.warning("Failed to process prefix %s: %s" % (prefix.get("prefix", "unknown"), str(e)))
                continue
 
    else:
        for ip_range in all_results:
            try:
                start_addr = ip_range.get("start_address")
                end_addr = ip_range.get("end_address")
                if not start_addr or not end_addr:
                    continue

                # Check if the IP address is IPv4 before processing
                try:
                    start_ip = ipaddress.ip_address(str(start_addr.split('/')[0]))
                    if start_ip.version == 6:
                        logging.info(f"Skipping IPv6 range: {start_addr} - {end_addr}")
                        continue
                except Exception as ip_parse_error:
                    logging.warning(f"Failed to parse IP address {start_addr}: {str(ip_parse_error)}")
                    continue
 
                subnet = ipaddress.ip_interface(str(start_addr)).network
                family = ip_range.get("family") or {}
                ip_version = family.get("label", "unknown")
 
                network_range = {
                    "id": str(ip_range.get("id", '')),
 
                    "name": str(ip_range.get("display", '')),
 
                    "startIPAddress": str(start_addr.split('/')[0]),
 
                    "endIPAddress": str(end_addr.split('/')[0]),
 
                    "ipVersion": ip_version,
 
                    "subnetPrefixLength": str(subnet.prefixlen),
 
                    "gatewayAddress": str(subnet[1]),
                }
 
                if "domain" in endpoint_props:
                    network_range["domain"] = endpoint_props["domain"]
                else:
                    logging.info(f"Domain variable not set. Ignoring.")
 
                result_ranges.append(network_range)
 
            except Exception as e:
                logging.warning("Failed to process IP range %s: %s" % (ip_range.get("display", "unknown"), str(e)))
                continue
 
    return {
        "ipRanges": result_ranges
    }