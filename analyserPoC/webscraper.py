from io import BytesIO
import os
import zipfile
import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

def scrape_extension_ids(url):
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service)
    wait = WebDriverWait(driver, 10)
    ids = set() 
    previous_count = 0  # To keep track of the previous number of IDs
    try:
        driver.get(url)
        while True:
            try:
                load_more_button = wait.until(EC.element_to_be_clickable((By.XPATH, "//button[.//span[text()='Load more']]")))
                driver.execute_script("arguments[0].click();", load_more_button)
                time.sleep(5)  

                # Extract IDs from the current page
                elements = driver.find_elements(By.CLASS_NAME, 'q6LNgd')
                page_ids = {element.get_attribute('href').split('/')[-1] for element in elements}
                ids.update(page_ids)

        
                if len(ids) == previous_count:
                    break  # Break if no new IDs are found
                previous_count = len(ids)  
            except Exception as e:
                print(f"Error while loading more extensions: {e}")
                break  
                
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        driver.quit()
    
    return list(ids)

def download_extension(extension_id, download_dir):
    chrome_version = "124.0.0.0"
    crx_url = f"https://clients2.google.com/service/update2/crx?response=redirect&prodversion={chrome_version}&x=id%3D{extension_id}%26installsource%3Dondemand%26uc&acceptformat=crx2,crx3"

    response = requests.get(crx_url)
    extension_dir = os.path.join(download_dir, extension_id)
    os.makedirs(extension_dir, exist_ok=True)
    if response.status_code != 200:
        print("Failed to download extension:", extension_id)
        return

    try:
        with zipfile.ZipFile(BytesIO(response.content)) as z:
            z.extractall(extension_dir)
    except zipfile.BadZipFile:
        print("Failed to unzip the CRX file. It might not be a valid zip file.")

# Example usage
url = 'https://chromewebstore.google.com/search/extensions'
extension_ids = scrape_extension_ids(url)
print(extension_ids)
for extension_id in extension_ids:
    directory = "extension_data_set"
    download_extension(extension_id, directory)
