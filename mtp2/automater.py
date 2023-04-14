from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
import time




browser = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
browser.get("http://localhost")

import pandas as pd
dataframe = pd.read_csv('data.csv')

# csrf_token = browser.find_element(By.NAME,'csrf_token').get_attribute('value')
# print(csrf_token)

for i in dataframe.index:
    entry = dataframe.iloc[i]

    username_input = browser.find_element(By.NAME,'username')
    username_input.send_keys(entry['username'])

    password_input = browser.find_element(By.NAME,'password')
    password_input.send_keys(entry['password'])

    confirm_pswd_input = browser.find_element(By.NAME,'confirm_pswd')
    confirm_pswd_input.send_keys(entry['confirm_pswd'])
    time.sleep(5)
    submit_btn = browser.find_element(By.CSS_SELECTOR,'input[type="submit"]')
    submit_btn.click()
