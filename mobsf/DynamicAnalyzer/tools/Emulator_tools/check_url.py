## This functions has been scrapped, but will just leave it here.
## Scrapped as MobSF already has a malware domain checker.



import requests
import time
import json
import os
import glob

API_KEY = "d3bce791213bf5c2970b32a58a80ba25e328894a8c790218cfd34611e199b928"

# List to store the result dictionaries
results = []

def check_url(url):
    params = {'apikey': API_KEY, 'resource': url}
    result = {'url': url}
    try:
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        response.raise_for_status()  # Raises stored HTTPError, if one occurred.
    except requests.HTTPError as http_err:
        result['error'] = f'HTTP error: {http_err}'
        print(result['error'])
    except Exception as err:
        result['error'] = f'Other error: {err}'
        print(result['error'])
    else:
        if response.text:  # if the response is not empty
            json_response = response.json()
            if json_response['response_code']:
                if json_response['positives']:
                    result['status'] = "malicious"
                else:
                    result['status'] = "safe"
            else:
                result['status'] = "No information"
        else:
            result['error'] = "No response from VirusTotal"
        
        if 'error' in result:
            print(f"URL: {result['url']}, Status: {result.get('status', '')}, Error: {result.get('error', '')}")
        else:
            print(f"URL: {result['url']}, Status: {result.get('status', '')}")
    return result

# Set to keep track of URLs that have been checked
checked_urls = set()

main_dir = os.path.expanduser("~/.MobSF/uploads")
#main_dir = "/path/to/your/main/directory"
directories = glob.glob(f"{main_dir}/*/")  # all directories in main_dir
newest_dir = max(directories, key=os.path.getctime)  # most recently created directory

file_path = os.path.join(newest_dir, "mobsf_frida_out.txt")

if os.path.exists(file_path):
    with open(file_path) as f:
        for line in f:
            if "URL: " in line:
                url = line.replace("URL: ", "").strip()  
                if url not in checked_urls:
                    results.append(check_url(url))
                    checked_urls.add(url)
                    time.sleep(15)

# Check if the 'urlcheck' directory exists, and if not, create it
if not os.path.exists('/urlcheck'):
    os.makedirs('urlcheck')

# Write the results to a JSON file in the 'urlcheck' directory
with open('urlcheck/output.json', 'w') as f:
    json.dump(results, f, indent=4)