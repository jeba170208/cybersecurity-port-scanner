import requests

url = "https://portal.rathinamtechnicalcampus.com/"

try:
    response = requests.get(url, timeout=10)

    print("Status Code:", response.status_code)
    print("Server:", response.headers.get("Server"))
    print("Content-Type:", response.headers.get("Content-Type"))
    print("Content-Length:", response.headers.get("Content-Length"))

except requests.RequestException as e:
    print("Request failed:", e)
    