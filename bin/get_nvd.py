import os
import json
import requests
import csv
import datetime
from zipfile import ZipFile

SPLUNK_HOME = os.environ.get('SPLUNK_HOME')
LOOKUPS_DIR = os.path.join(SPLUNK_HOME, 'etc', 'apps', 'vuln_info_sync', 'lookups')

today = datetime.date.today()
current_year = today.year

def deep_get(d, keys, default='Empty'):
    assert isinstance(keys, list)
    if d is None:
        return default
    if not keys:
        return d
    return deep_get(d.get(keys[0]), keys[1:], default)

def download_and_extract_zip(year):
    try:
        url = f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip'
        response = requests.get(url, stream=True)
        temp_filename = os.path.join(LOOKUPS_DIR, f"{year}.zip.tmp")
        final_filename = os.path.join(LOOKUPS_DIR, f"{year}.zip")

        if response.status_code == 200:
            with open(temp_filename, 'wb') as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
            os.replace(temp_filename, final_filename)

            with ZipFile(final_filename, 'r') as zip_obj:
                zip_obj.extractall(path=LOOKUPS_DIR)
            print(f"Successfully downloaded and extracted data for year {year}")
        else:
            print(f"Failed to download data for year {year}, status code: {response.status_code}")
    except Exception as e:
        print(f"An error occurred while downloading data for year {year}: {str(e)}")
        if os.path.exists(temp_filename):
            os.remove(temp_filename)

def convert_json_to_csv():
    try:
        temp_filename = os.path.join(LOOKUPS_DIR, 'nvd.csv.tmp')
        final_filename = os.path.join(LOOKUPS_DIR, 'nvd.csv')

        with open(temp_filename, 'w', newline='') as file:
            header = [
                'cve_id', 'v2_exploitabilityScore', 'v2_impactScore', 'v2_obtainAllPrivilege',
                'v2_obtainOtherPrivilege', 'v2_obtainUserPrivilege', 'v2_severity',
                'v2_userInteractionRequired', 'v2_cvss2_accessComplexity', 'v2_cvss2_accessVector',
                'v2_cvss2_authentication', 'v2_cvss2_availabilityImpact', 'v2_cvss2_baseScore',
                'v2_cvss2_confidentialityImpact', 'v2_cvss2_integrityImpact', 'v2_cvss2_vectorString',
                'v2_cvss2_version', 'v3_exploitabilityScore', 'v3_impactScore', 'v3_cvss3_attackComplexity',
                'v3_cvss3_attackVector', 'v3_cvss3_availabilityImpact', 'v3_cvss3_baseScore', 'v3_cvss3_baseSeverity',
                'v3_cvss3_confidentialityImpact', 'v3_cvss3_integrityImpact', 'v3_cvss3_privilegesRequired',
                'v3_cvss3_scope', 'v3_cvss3_userInteraction', 'v3_cvss3_vectorString', 'v3_cvss3_version'
            ]
            writer = csv.DictWriter(file, fieldnames=header)
            writer.writeheader()

            for year in range(2017, current_year + 1):
                json_filename = os.path.join(LOOKUPS_DIR, f'nvdcve-1.1-{year}.json')
                with open(json_filename) as json_file:
                    data = json.load(json_file)
                    for item in data['CVE_Items']:
                        if item['impact']:
                            final_dict = {}
                            final_dict['cve_id'] = deep_get(item, ['cve', 'CVE_data_meta', 'ID'])
                            final_dict['v2_exploitabilityScore'] = deep_get(item, ['impact', 'baseMetricV2', 'exploitabilityScore'])
                            final_dict['v2_impactScore'] = deep_get(item, ['impact', 'baseMetricV2', 'impactScore'])
                            final_dict['v2_obtainAllPrivilege'] = deep_get(item, ['impact', 'baseMetricV2', 'obtainAllPrivilege'])
                            final_dict['v2_obtainOtherPrivilege'] = deep_get(item, ['impact', 'baseMetricV2', 'obtainOtherPrivilege'])
                            final_dict['v2_obtainUserPrivilege'] = deep_get(item, ['impact', 'baseMetricV2', 'obtainUserPrivilege'])
                            final_dict['v2_severity'] = deep_get(item, ['impact', 'baseMetricV2', 'severity'])
                            final_dict['v2_userInteractionRequired'] = deep_get(item, ['impact', 'baseMetricV2', 'userInteractionRequired'])
                            final_dict['v2_cvss2_accessComplexity'] = deep_get(item, ['impact', 'baseMetricV2', 'cvssV2', 'accessComplexity'])
                            final_dict['v2_cvss2_accessVector'] = deep_get(item, ['impact', 'baseMetricV2', 'cvssV2', 'accessVector'])
                            final_dict['v2_cvss2_authentication'] = deep_get(item, ['impact','baseMetricV2','cvssV2','authentication'])
                            final_dict['v2_cvss2_availabilityImpact'] = deep_get(item, ['impact','baseMetricV2','cvssV2','availabilityImpact'])
                            final_dict['v2_cvss2_baseScore'] = deep_get(item, ['impact','baseMetricV2','cvssV2','baseScore'])
                            final_dict['v2_cvss2_confidentialityImpact'] = deep_get(item, ['impact','baseMetricV2','cvssV2','confidentialityImpact'])
                            final_dict['v2_cvss2_integrityImpact'] = deep_get(item, ['impact', 'baseMetricV2', 'cvssV2','integrityImpact'])
                            final_dict['v2_cvss2_vectorString'] = deep_get(item, ['impact', 'baseMetricV2','cvssV2', 'vectorString'])
                            final_dict['v2_cvss2_version'] = deep_get(item, ['impact', 'baseMetricV2', 'cvssV2', 'version'])
                            final_dict['v3_exploitabilityScore'] = deep_get(item, ['impact', 'baseMetricV3', 'exploitabilityScore'])
                            final_dict['v3_impactScore'] = deep_get(item, ['impact', 'baseMetricV3', 'impactScore'])
                            final_dict['v3_cvss3_attackComplexity'] = deep_get(item, ['impact', 'baseMetricV3', 'cvssV3', 'attackComplexity'])
                            final_dict['v3_cvss3_attackVector'] = deep_get(item, ['impact', 'baseMetricV3', 'cvssV3', 'attackVector'])
                            final_dict['v3_cvss3_availabilityImpact'] = deep_get(item, ['impact', 'baseMetricV3', 'cvssV3', 'availabilityImpact'])
                            final_dict['v3_cvss3_baseScore'] = deep_get(item, ['impact', 'baseMetricV3', 'cvssV3', 'baseScore'])
                            final_dict['v3_cvss3_baseSeverity'] = deep_get(item, ['impact', 'baseMetricV3', 'cvssV3', 'baseSeverity'])
                            final_dict['v3_cvss3_confidentialityImpact'] = deep_get(item, ['impact', 'baseMetricV3', 'cvssV3', 'confidentialityImpact'])
                            final_dict['v3_cvss3_integrityImpact'] = deep_get(item, ['impact', 'baseMetricV3', 'cvssV3', 'integrityImpact'])
                            final_dict['v3_cvss3_privilegesRequired'] = deep_get(item, ['impact', 'baseMetricV3', 'cvssV3', 'privilegesRequired'])
                            final_dict['v3_cvss3_scope'] = deep_get(item, ['impact', 'baseMetricV3', 'cvssV3', 'scope'])
                            final_dict['v3_cvss3_userInteraction'] = deep_get(item, ['impact', 'baseMetricV3', 'cvssV3', 'userInteraction'])
                            final_dict['v3_cvss3_vectorString'] = deep_get(item, ['impact', 'baseMetricV3', 'cvssV3', 'vectorString'])
                            final_dict['v3_cvss3_version'] = deep_get(item, ['impact', 'baseMetricV3', 'cvssV3', 'version'])
                            writer.writerow(final_dict)

        os.replace(temp_filename, final_filename)
        print(f"Successfully converted JSON files to {final_filename}")
    except Exception as e:
        print(f"An error occurred during the conversion to CSV: {str(e)}")
        if os.path.exists(temp_filename):
            os.remove(temp_filename)

def clean_up_files():
    try:
        for year in range(2017, current_year + 1):
            json_filename = os.path.join(LOOKUPS_DIR, f'nvdcve-1.1-{year}.json')
            zip_filename = os.path.join(LOOKUPS_DIR, f'{year}.zip')

            if os.path.exists(json_filename):
                os.remove(json_filename)
                print(f"Deleted {json_filename}")

            if os.path.exists(zip_filename):
                os.remove(zip_filename)
                print(f"Deleted {zip_filename}")
    except Exception as e:
        print(f"An error occurred during cleanup: {str(e)}")

if __name__ == '__main__':
    for year in range(2017, current_year + 1):
        download_and_extract_zip(year)

    convert_json_to_csv()
    clean_up_files()
