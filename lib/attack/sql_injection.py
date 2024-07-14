from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from urllib3.util import parse_url
from selenium.webdriver.edge.service import Service as EdgeService
from webdriver_manager.microsoft import EdgeChromiumDriverManager

from selenium.webdriver.common.by import By

with open('lib/attack/payloads.txt', 'r') as f:
    payloads = f.read().splitlines()


class SQLInjection:
    selectors = {
        'input':
        'input[type="text"], input[type="email"], input[type="password"], input[type="search"], input[type="tel"], input[type="url"], input[type="number"], input[type="range"], input[type="date"], input[type="month"], input[type="week"], input[type="time"], input[type="datetime"], input[type="datetime-local"], input[type="color"], textarea',
        'submit': 'input[type="submit"], button[type="submit"]'
    }

    def __init__(self, website_url: str):
        self.website_url = website_url
        self.driver = webdriver.ChromiumEdge(
            service=EdgeService(EdgeChromiumDriverManager().install()))
        options = webdriver.EdgeOptions()
        options.add_argument('--headless')
        self.driver.get(website_url)
        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, 'html')))
        self.vulnerability_found = False

    def fillInputFields(self, input_fields, payload: str):
        for input_field in input_fields:
            input_field.send_keys(payload)
            yield input_field, payload

    def fillSubmitButtons(self, submit_buttons, payload: str):
        for submit_button in submit_buttons:
            submit_button.send_keys(payload)
            yield submit_button, payload

    def checkVulnerability(self, payload: str):
        try:
            if self.driver.current_url != self.website_url:
                print('SQL injection vulnerability found with payload:',
                      payload)
                self.vulnerability_found = True
                self.driver.back()

            else:
                WebDriverWait(self.driver, 10).until(
                    EC.title_contains('Error')
                    or EC.title_contains('SQL error')
                    or EC.title_contains('Database error'))
                print('SQL injection vulnerability found with payload:',
                      payload)
        except:
            pass

    def run(self):
        # get input fields
        input_fields = self.driver.find_elements(By.CSS_SELECTOR,
                                                 self.selectors['input'])
        submit_buttons = self.driver.find_elements(By.CSS_SELECTOR,
                                                   self.selectors['submit'])

        for payload in payloads:
            if self.vulnerability_found:
                break
            self.fillInputFields(input_fields, payload)
            self.fillSubmitButtons(submit_buttons, payload)
            self.checkVulnerability(payload)

    def __del__(self):
        self.driver.quit()


if __name__ == '__main__':
    # change this to your website url this is just for testing
    url = parse_url('http://localhost')
    sqli = SQLInjection(str(url))
    sqli.run()