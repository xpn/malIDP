# malIDP

A small (and very janky) SAML IDP which will sign SAML responses to authenticate as any user.

Information about this tool can be found in the blog post https://blog.xpnsec.com/identity-providers-redteamers.

## Building

```
python3 -m venv env
source ./env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Usage

### OneLogin

Start with:

```
./main.py --provider onelogin --cert ./example.com.crt --key ./example.com.key --issuer 'www.example.com'
```

And use the following to kick off the flow:

`https://tenant-name.onelogin.com/access/initiate?iss=ISSUER_HERE`

### Okta

Metadata should be downloaded from the added External Identity Provider.

Start with:

```
./main.py --provider okta --cert ./example.com.crt --key ./example.com.key --metadata saml_metadata.xml --issuer 'www.example.com'
```

And use the following to kick off the flow:

`https://tenant-name.okta.com/app/template_saml_2_0/k1k2l3l4l5l6l7l8l9l0/sso/saml?SAMLRequest=REQUEST_HERE`

### Azure

Metadata should be taken from `https://nexus.microsoftonline-p.com/federationmetadata/saml20/federationmetadata.xml`

Start with:

```
./main.py --provider azure --cert ./example.com.crt --key ./example.com.key --metadata federationmetadata.xml --issuer 'www.example.com'
```

And use the following to kick off the flow:

`http://localhost/init`

### Ping Identity

Metadata should be downloaded from the added External Identity Provider.

Start with:

```
./main.py --provider ping --cert ./example.com.crt --key ./example.com.key --metadata saml_metadata.xml --issuer 'www.example.com'
```

