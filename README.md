# tesla_auth_python
Securely generate API tokens for third-party access to your Tesla. 

This is a Python implementation of the awesome work done by Adrian at [tesla_auth](https://github.com/adriankumpf/tesla_auth).

It generates a Bearer token and Refresh token to be used with the Tesla API. I couldn't seem to make it work with the Fleet API but it seems to work fine with the https://owner-api.teslamotors.com/ base URL.

Unoffical Docs:
https://tesla-api.timdorr.com/

## Usage
Clone repo:

`git clone https://github.com/Hotanya/tesla_auth_python`

Install requirements:

```python
python3 -m venv venv-teslaauth
source venv-teslaauth/bin/activate
pip3 install -r requirements.py
python3 teslaauth.py
```
