# ext-js-hunter
Series of tools to Hunt for Externally Hosted JS on a website.

1) Uses amass to enumerate subdomains.
2) Validates subdomains for DNS resolution and basic HTTPS reachability.

3) Loads the Website on an instance of Selenium Chromium.
4) Inspect logs from the Browser.
5) Extract all events for type "Script", and prints out externally hosted JS scripts.
