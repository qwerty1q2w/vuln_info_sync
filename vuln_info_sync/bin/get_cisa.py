import requests
import os

SPLUNK_HOME = os.environ.get('SPLUNK_HOME')
LOOKUPS_DIR = os.path.join(SPLUNK_HOME, 'etc', 'apps', 'vuln_info_sync', 'lookups')

filename = 'cisa.csv'
url = 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv'

def download_csv():
    temp_filename = f"{filename}.tmp"

    try:
        response = requests.get(url, stream=True)
        if response.status_code == 200:
            with open(os.path.join(LOOKUPS_DIR, temp_filename), 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            os.replace(os.path.join(LOOKUPS_DIR, temp_filename), os.path.join(LOOKUPS_DIR, filename))
            print(f"Successfully downloaded {filename} from {url}")
        else:
            print(f"Failed to download {filename} from {url}, status code: {response.status_code}")
    except Exception as e:
        print(f"An error occurred while downloading {filename} from {url}: {str(e)}")
        if os.path.exists(os.path.join(LOOKUPS_DIR, temp_filename)):
            os.remove(os.path.join(LOOKUPS_DIR, temp_filename))

if __name__ == '__main__':
    download_csv()
