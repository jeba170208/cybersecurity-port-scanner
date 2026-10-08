import requests

url = "https://portal.rathinamtechnicalcampus.com/"

response = requests.get(url, timeout=10)

headers_to_check = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

print("Security Header Check\n")

for header in headers_to_check:
    value = response.headers.get(header)

    if value:
        print(f"[PRESENT] {header}: {value}")
    else:
        print(f"[MISSING] {header}")
