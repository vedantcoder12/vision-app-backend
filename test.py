import requests

url = 'http://localhost:5000/api/search_product'
payload = {'product-name': 'Bata Mens MaxUniform Dress Shoe'}
response = requests.post(url, json=payload)

print(response.json())