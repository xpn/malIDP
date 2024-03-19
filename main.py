from flask import Flask, request, render_template
from lib import saml
import argparse

app = Flask(__name__)
samlHandler = None

@app.route('/saml', methods=['GET','POST'])
def handle_saml():
    
    saml_request = ""
    relay_state = ""
    
    if request.method == 'GET':
      saml_request = request.args.get('SAMLRequest')
      relay_state = request.args.get('RelayState')
    else:
      saml_request = request.form['SAMLRequest']
      if 'RelayState' in request.form:
        relay_state = request.form['RelayState']

    return render_template('saml_request.html', saml_request=saml_request, relay_state=relay_state)

@app.route('/redirect', methods=['POST'])
def handle_redirect():
    
    if 'SAMLRequest' in request.form:
      saml_request = request.form['SAMLRequest']
    else:
      saml_request = ''

    username = request.form['username']
    firstname = request.form['firstname']
    lastname = request.form['lastname']
    immutable_id = request.form['immutableid']

    # Parse request and generate SAML response
    decoded = samlHandler.handleSamlRequest(saml_request, username, firstname, lastname, immutable_id = immutable_id)

    return render_template('saml_response.html', saml_response=decoded, redirect_path=samlHandler._acs_url, relay_state=request.form['RelayState'])

@app.route('/', methods=['GET'])
def handle_index():
    return render_template('saml_request.html', saml_request="<?xml version=\"1.0\" encoding=\"UTF-8\"?>")

@app.route('/init', methods=['GET'])
def handle_init():
    
    if samlHandler._idp_name == "azure":
      return render_template('saml_init.html', show_azure=True)
    
    return render_template('saml_init.html')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SAML Response Generator')
    parser.add_argument('--provider', help='Identity Provider', required=True, choices=['azure', 'onelogin', 'okta', 'ping'])
    parser.add_argument('--cert', help='Path to certificate file', required=True)
    parser.add_argument('--key', help='Path to private key file', required=True)
    parser.add_argument('--metadata', help='Path to metadata file', required=True)
    parser.add_argument('--issuer', help='Issuer name', required=True)
    args = parser.parse_args()

    samlHandler = saml.SAMLHandler(args.cert, args.key, args.metadata, args.issuer, idp_name=args.provider)
    samlHandler.parseMetadata()

    app.run(debug=False, port=80)
