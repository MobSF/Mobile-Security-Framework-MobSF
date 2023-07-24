import requests
import time
import os
import glob

API_KEY = "d3bce791213bf5c2970b32a58a80ba25e328894a8c790218cfd34611e199b928"

def check_url(url):
    params = {'apikey': API_KEY, 'resource': url}
    try:
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        response.raise_for_status()  # Raises stored HTTPError, if one occurred.
    except requests.HTTPError as http_err:
        print(f'HTTP error occurred for {url}: {http_err}') 
    except Exception as err:
        print(f'Other error occurred for {url}: {err}')
    else:
        if response.text:  # if the response is not empty
            json_response = response.json()
            if json_response['response_code']:
                if json_response['positives']:
                    print(f"{url} is malicious")
                else:
                    print(f"{url} is safe")
            else:
                print(f"No information about {url}")
        else:
            print(f"No response from VirusTotal for {url}")

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
                # If the URL hasn't been checked before, check it and add it to the set
                if url not in checked_urls:
                    check_url(url)
                    checked_urls.add(url)
                    time.sleep(15)  # wait for 15 seconds before the next request to avoid rate limit
else:
    print(f"The file '{file_path}' does not exist.")