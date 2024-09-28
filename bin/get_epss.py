import requests
import os
import gzip
import shutil

SPLUNK_HOME = os.environ.get('SPLUNK_HOME')
LOOKUPS_DIR = os.path.join(SPLUNK_HOME, 'etc', 'apps', 'vuln_info_sync', 'lookups')

filename = 'epss.csv'
url = 'https://epss.cyentia.com/epss_scores-current.csv.gz'

def download_csv():
    temp_gz_filename = f"{filename}.gz.tmp"  # Temporary name for the archive
    temp_csv_filename = f"{filename}.tmp"    # Temporary name for the extracted file

    try:
        # Download the gzipped file
        response = requests.get(url, stream=True)
        if response.status_code == 200:
            with open(os.path.join(LOOKUPS_DIR, temp_gz_filename), 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            # Extract the file from the archive
            with gzip.open(os.path.join(LOOKUPS_DIR, temp_gz_filename), 'rb') as f_in:
                with open(os.path.join(LOOKUPS_DIR, temp_csv_filename), 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

            # Remove comments from the first line if present
            clean_first_line(os.path.join(LOOKUPS_DIR, temp_csv_filename))

            # Rename the temporary file to the final filename
            os.replace(os.path.join(LOOKUPS_DIR, temp_csv_filename), os.path.join(LOOKUPS_DIR, filename))
            print(f"Successfully downloaded and extracted {filename} from {url}")

            # Remove the temporary gz file
            os.remove(os.path.join(LOOKUPS_DIR, temp_gz_filename))
        else:
            print(f"Failed to download {filename} from {url}, status code: {response.status_code}")
    except Exception as e:
        print(f"An error occurred while downloading {filename} from {url}: {str(e)}")
        # Remove temporary files in case of an error
        if os.path.exists(os.path.join(LOOKUPS_DIR, temp_gz_filename)):
            os.remove(os.path.join(LOOKUPS_DIR, temp_gz_filename))
        if os.path.exists(os.path.join(LOOKUPS_DIR, temp_csv_filename)):
            os.remove(os.path.join(LOOKUPS_DIR, temp_csv_filename))

def clean_first_line(csv_filepath):
    try:
        with open(csv_filepath, 'r') as file:
            lines = file.readlines()

        # Remove comments from the first line if it starts with '#'
        if lines and lines[0].startswith('#'):
            lines[0] = ''  # Remove the first line entirely

        with open(csv_filepath, 'w') as file:
            file.writelines(lines)

        print(f"Successfully cleaned the first line of the CSV file at {csv_filepath}")
    except Exception as e:
        print(f"An error occurred while cleaning the first line of the CSV file at {csv_filepath}: {str(e)}")

if __name__ == '__main__':
    download_csv()
