from zapv2 import ZAPv2
import time

# Set up the OWASP ZAP API client
zap_api_key = 'your_zap_api_key'  # Set your API key here
zap = ZAPv2(apikey=zap_api_key, proxies={'http': 'http://127.0.0.1:8080', 'https://127.0.0.1:8080'})

# Get target URL from user input
target_url = input("Enter the target URL (e.g., http://example.com): ")

# Start by accessing the target URL to establish a session
print(f'Accessing {target_url}')
zap.urlopen(target_url)
time.sleep(2)

# Start spidering the target website
print(f'Starting spider on {target_url}')
zap.spider.scan(target_url)
time.sleep(5)  # Wait for the spider to kick off

while int(zap.spider.status()) < 100:
    print(f'Spider progress: {zap.spider.status()}%')
    time.sleep(2)
print('Spidering completed!')

# Start active scanning the website (this identifies vulnerabilities)
print(f'Starting active scan on {target_url}')
zap.ascan.scan(target_url)
while int(zap.ascan.status()) < 100:
    print(f'Scan progress: {zap.ascan.status()}%')
    time.sleep(5)
print('Active scan completed!')

# Get the results of the scan
vulnerabilities = zap.core.alerts(baseurl=target_url)
print(f'Found {len(vulnerabilities)} vulnerabilities!')

# Print summary of OWASP Top 10 vulnerabilities found
for alert in vulnerabilities:
    print(f"Alert: {alert['alert']}")
    print(f"Risk: {alert['risk']}")
    print(f"Description: {alert['description']}")
    print(f"URL: {alert['url']}")
    print(f"Solution: {alert['solution']}")
    print('-' * 40)

# Optionally, generate a full HTML report
with open('zap_scan_report.html', 'w') as f:
    f.write(zap.core.htmlreport())

print("Scan report generated: zap_scan_report.html")
