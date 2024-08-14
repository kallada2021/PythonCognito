from flask import Flask, redirect, url_for, render_template_string, request, session
import boto3
from botocore.exceptions import ClientError
import secrets
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a secure secret key

# Cognito configuration 
USER_POOL_ID = 'your_cognito_user_pool_id'
APP_CLIENT_ID = 'your_cognito_app_client_id'
IDENTITY_POOL_ID = 'your_cognito_identity_pool_id'
REGION = 'your_aws_region'

# SAML configuration 
SAML_SETTINGS = {
    'sp': {
        'entityId': 'your-sp-entity-id', 
        'assertionConsumerService': {
            'url': 'http://localhost:5000/saml_callback', 
            'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        },
        'privateKey': 'your-sp-private-key',
        'x509cert': 'your-sp-certificate',
    },
    'idp': {
        'entityId': 'your-idp-entity-id', 
        'singleSignOnService': {
            'url': 'your-idp-sso-url', 
            'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        },
        'x509cert': 'your-idp-certificate', 
    },
}

# Initialize Cognito clients
cognito_idp = boto3.client('cognito-idp', region_name=REGION)
cognito_identity = boto3.client('cognito-identity', region_name=REGION)

# login.html template
login_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>

    {% if error %}
        <p style="color: red;">{{ error }}</p>
    {% endif %}

    {% if 'access_token' in session %}
        <p>You are logged in!</p>
        <a href="{{ url_for('logout') }}">Logout</a>
    {% else %}
        <h2>Login</h2>
        <form method="post" action="{{ url_for('login') }}">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required><br><br>

            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required><br><br>

            <input type="submit" value="Login">
        </form>

        <br>

        <h2>Or login with SAML</h2>
        <a href="{{ url_for('saml_login') }}">Login with SAML</a>
    {% endif %}

</body>
</html>
'''


def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, SAML_SETTINGS)
    return auth


def prepare_flask_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    url_data = urlparse(request.url)
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': url_data.port,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }


@app.route('/')
def index():
    if 'access_token' in session:
        return 'You are logged in!'
    else:
        return render_template_string(login_html)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            response = cognito_idp.initiate_auth(
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password
                },
                ClientId=APP_CLIENT_ID
            )

            session['access_token'] = response['AuthenticationResult']['AccessToken']
            session['id_token'] = response['AuthenticationResult']['IdToken']
            session['refresh_token'] = response['AuthenticationResult']['RefreshToken']

            return redirect(url_for('index'))

        except ClientError as e:
            error_message = e.response['Error']['Message']
            return render_template_string(login_html, error=error_message)

    return render_template_string(login_html)


@app.route('/saml_login')
def saml_login():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.login())


@app.route('/saml_callback')
def saml_callback():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()

    if errors:
        return render_template_string(login_html, error=', '.join(errors))

    aws_cognito_domain = f"cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}"

    # Retrieve SAML assertion and attributes (if needed)
    assertion = auth.get_last_assertion()
    attributes = auth.get_attributes()

    # Exchange SAML assertion for Cognito tokens
    try:
        response = cognito_idp.admin_initiate_auth(
            UserPoolId=USER_POOL_ID,
            ClientId=APP_CLIENT_ID,
            AuthFlow='ADMIN_USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'][0],
                'PASSWORD': assertion  # Use the SAML assertion as the password
            }
        )

        # Store tokens in session
        session['access_token'] = response['AuthenticationResult']['AccessToken']
        session['id_token'] = response['AuthenticationResult']['IdToken']
        session['refresh_token'] = response['AuthenticationResult']['RefreshToken']

        # (Optional) Get AWS credentials using Cognito Identity
        identity_id = cognito_identity.get_id(
            AccountId='your_aws_account_id',
            IdentityPoolId=IDENTITY_POOL_ID,
            Logins={
                aws_cognito_domain: session['id_token']
            }
        )['IdentityId']

        credentials = cognito_identity.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins={
                aws_cognito_domain: session['id_token']
            }
        )['Credentials']

        # ... store credentials as needed ...

    except ClientError as e:
        error_message = e.response['Error']['Message']
        return render_template_string(login_html, error=error_message)

    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
