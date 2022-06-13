from pydoc import pager
import shodan
import openpyxl
import nvdlib
from termcolor import colored


SHODAN_API_KEY = ''
api = shodan.Shodan(SHODAN_API_KEY)

file_exclusions = ["ips.txt", "ips2.txt"]
ip_exclusions = []
status_exclusions = [400, 404]
MAX_RETRIES = 3
MAX_RESULTS = 100
MAX_VULNS = 10

for file in file_exclusions:
    f = open(file, "r")
    for ip in f.readlines():
        ip_exclusions.append(ip.strip())

data = []
hosts = {}
customer = "sogei"
query = "ssl:{}".format(customer)
subnet = ""
page = 1
row = 2
count = 1
results = ""

# Creazione file Export
export_file = "./{}_Shodan.xlsx".format(customer)
wb = openpyxl.Workbook()
wb.save(export_file)
wb = openpyxl.load_workbook(export_file)
sheet = wb.active
sheet['A1'] = 'IP'
sheet['b1'] = 'Ports'
sheet['C1'] = 'Vulnerabilities'
sheet['D1'] = 'Link'
wb.save(export_file)

while True:
    if count >= MAX_RESULTS:
        print("Reached MAX_RESULTS")
        break
    try:
        # Search Shodan
        results = api.search(query, page=page)

        for result in results['matches']:
            for k in result["ssl"]["cert"]["subject"]:
                if customer.lower() in result["ssl"]["cert"]["subject"][k].lower() and result not in data:
                    data.append(result)

        print(colored("Fetched page {}".format(page), "green"))
        page += 1
    except shodan.APIError as e:
        print('Error: {}'.format(e))
        break
    if len(results["matches"]) == 0:
        print('Finished: {}'.format(page))
        break

    for host in data:
        if count >= MAX_RESULTS:
            print("Reached MAX_RESULTS")
            break

        if subnet == "" or subnet in host["ip_str"]:
            result = ""
            for attempt in range(MAX_RETRIES):
                try:
                    result = api.host(host["ip_str"])
                except:
                    print("Shodan Error, attempt {}".format(attempt))
                else:
                    break
            else:
                print("MAX RETREIS hit, unable to fetch info for IP {}".format(host["ip_str"]))
                if host["ip_str"] in hosts:
                    hosts[host["ip_str"]] = {
                        "ports": "ERROR", 
                        "vulns": "CHECK MANUALLY",
                        "link": "https://shodan.io/host/{}".format(host["ip_str"])
                    }
                    count += 1

            if host["ip_str"] not in ip_exclusions and host["ip_str"] not in hosts:
                ports = []
                for i in range(len(result["data"])):
                    if "port" in result["data"][i]:
                        if "http" in result["data"][i]:
                            if "status" in result["data"][i]["http"] and result["data"][i]["http"]["status"] not in status_exclusions:
                                ports.append("{}/{}".format(result["data"][i]["port"], result["data"][i]["http"]["status"]))
                        else:
                            ports.append(result["data"][i]["port"])


                vulns = {}
                if host["ip_str"] not in hosts:
                    for i in range(len(result["data"])):
                        if "vulns" in result["data"][i]:
                            c = 0
                            for vuln in result["data"][i]["vulns"].keys():
                                r = nvdlib.getCVE(vuln)   
                                c += 1      
                                try:
                                    vulns[vuln] = r.v3score
                                except:
                                    vulns[vuln] = r.v2score
                                if c >= MAX_VULNS:
                                    break
                            
                

                if ports != "": 
                    print("{}) {}".format(count, host["ip_str"]))
                    print("\t-Ports = {}".format(ports))
                    print("\t-Vulns = {}".format(vulns))
                    hosts[host["ip_str"]] = {
                        "ports": ports, 
                        "vulns": vulns,
                        "link": "https://shodan.io/host/{}".format(host["ip_str"])
                    }
                    count += 1


for k in hosts:
    p = ""
    v = ""
    for x in hosts[k]["ports"]:
        p += "{},\015".format(x)
    values = sorted(hosts[k]["vulns"].values(), reverse=True)[:3]
    limited = {}
    for x in hosts[k]["vulns"]:
        if hosts[k]["vulns"][x] in values:
            limited[x] = hosts[k]["vulns"][x]
    
    for x in limited:
        v += "{} CVSS: {}\015".format(x, limited[x]) 
    sheet["A{}".format(row)] = k
    sheet["B{}".format(row)] = p
    sheet["C{}".format(row)] = v
    sheet["D{}".format(row)] = hosts[k]["link"]
    row += 1
wb.save(export_file)
