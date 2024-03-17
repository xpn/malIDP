import base64
import io
from lxml import etree
import datetime
from signxml import XMLSigner, XMLVerifier
import string
import random
import re
import zlib

SAMLResponse = """
"""

class SAMLHandler:
    def __init__(self, certificate_file, key_file, metadata_file, issuer, idp_name="okta", entity_id="", acs_url="", sso_entity_id=""):
        self._metadata_file = metadata_file
        self._certificate_file = certificate_file
        self._key_file = key_file
        self._idp_name = idp_name
        self._issuer = issuer
        self._entity_id = entity_id
        self._acs_url = acs_url
        self._sso_entity_id = sso_entity_id

        # Get the certificate
        with open(self._certificate_file, "r") as cert, open(self._key_file, "r") as key:
          self._certificate = cert.read()
          self._key = key.read()

    def parseMetadata(self):
        with open(self._metadata_file, 'r') as f:
            metadata = f.read()

        # Parse XML in metadata
        buf = io.BytesIO(metadata.encode('utf-8'))
        metadataXML = etree.parse(buf)

        # Get the entity ID
        self._entity_id = metadataXML.xpath('//md:EntityDescriptor/@entityID', namespaces={'md': 'urn:oasis:names:tc:SAML:2.0:metadata'})[0]

        # Get the ACS SSO URL
        self._acs_url = metadataXML.xpath('//md:AssertionConsumerService/@Location', namespaces={'md': 'urn:oasis:names:tc:SAML:2.0:metadata'})[0]

    def _generateSamlResponse(self, username, firstname='test', lastname='user', response_to="", immutable_id=""):
        
        current_datetime = datetime.datetime.utcnow()
        future_datetime = current_datetime + datetime.timedelta(hours=2)
        past_datetime = current_datetime - datetime.timedelta(hours=2)

        # Format the date and time in the desired format
        formatted_current_datetime = current_datetime.strftime('%Y-%m-%dT%H:%M:%SZ')
        formatted_past_datetime = past_datetime.strftime('%Y-%m-%dT%H:%M:%SZ')
        formatted_future_datetime = future_datetime.strftime('%Y-%m-%dT%H:%M:%SZ')
        assertion_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(42))

        if self._idp_name == "onelogin":
          with open('data/onelogin_response.xml', 'r') as f:
              response_data = f.read()
        elif self._idp_name == "ping":
          with open('data/ping_response.xml', 'r') as f:
              response_data = f.read()
        elif self._idp_name == "azure":
          with open('data/azure_response.xml', 'r') as f:
              response_data = f.read()
        else:
          with open('data/okta_response.xml', 'r') as f:
              response_data = f.read()

        # Replace the date and time in the response with the formatted date and time
        response_data = response_data.replace('{timenow}', formatted_current_datetime)
        response_data = response_data.replace('{notbefore}', formatted_past_datetime)
        response_data = response_data.replace('{notafter}', formatted_future_datetime)
        response_data = response_data.replace('{issuer}', self._issuer)
        response_data = response_data.replace('{audience}', self._entity_id)
        response_data = response_data.replace('{destination}', self._acs_url)
        response_data = response_data.replace('{recipient}', self._acs_url)
        response_data = response_data.replace('{responseto}', response_to)
        response_data = response_data.replace('{firstname}', firstname)
        response_data = response_data.replace('{lastname}', lastname)
        response_data = response_data.replace('{email}', username)
        response_data = response_data.replace('{assertionid}', assertion_id)
        response_data = response_data.replace('{immutableid}', immutable_id)

        saml_root = etree.fromstring(response_data)
        signed_saml_root = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#").sign(saml_root, key=self._key, cert=self._certificate)
        
        response_data = etree.tostring(signed_saml_root, encoding='unicode')
        return base64.b64encode(response_data.encode('utf-8')).decode('utf-8')
    
    def handleSamlRequest(self, request, username, firstname='test', lastname='user', immutable_id=""):
        
        # Initiated from the SP
        if request == "":
          response = self._generateSamlResponse(username, firstname, lastname, immutable_id=immutable_id)
          return response
        
        # Base64 decode
        samlRequest = base64.b64decode(request)

        if self._idp_name == "onelogin":
          # OneLogin uses zlib compression for the SAMLRequest
          samlRequest = zlib.decompress(samlRequest, -15)

        # Parse XML in samlRequest
        buf = io.BytesIO(samlRequest)
        samlXML = etree.parse(buf)

        # Get the responseTo ID
        response_to = samlXML.xpath('//samlp:AuthnRequest/@ID', namespaces={'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'})
        if len(response_to) > 0:
          response_to = response_to[0]

        acs_url = samlXML.xpath('//samlp:AuthnRequest/@AssertionConsumerServiceURL', namespaces={'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'})
        if len(acs_url) > 0:
          self._acs_url = acs_url[0]

        sso_entity_id = samlXML.xpath('//samlp:AuthnRequest/saml:Issuer/text()', namespaces={'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol', 'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'})
        if len(sso_entity_id) > 0:
          self._sso_entity_id = sso_entity_id[0]
          self._entity_id = sso_entity_id[0]
        
        response = self._generateSamlResponse(username, firstname, lastname, response_to, immutable_id)
        return response
