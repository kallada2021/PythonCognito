from flask import Flask, redirect, url_for, render_template_string, request, session
import warrant
import boto3
from botocore.exceptions import ClientError
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a secure secret key

# Cognito configuration (replace with your actual values)
USER_POOL_ID = 'your_cognito_user_pool_id'
APP_CLIENT_ID = 'your_cognito_app_client_id'
IDENTITY_POOL_ID = 'your_cognito_identity_pool_id'   

REGION = 'your_aws_region'

# SAML configuration (replace with your actual SAML provider details)
SAML_PROVIDER_NAME = 'your_saml_provider_name'
SAML_METADATA_URL = 'your_saml_metadata_url'

# Initialize Cognito clients
cognito_idp = boto3.client('cognito-idp', region_name=REGION)
cognito_identity = boto3.client('cognito-identity', region_name=REGION)

# login.html template (embedded within the script)
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
            # Regular Cognito sign-in
            response = cognito_idp.initiate_auth(
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password
                },
                ClientId=APP_CLIENT_ID
            )

            # Store tokens in session
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
    # SAML login initiation
    aws_cognito_domain = f"cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}"
    provider = warrant.SAMLIdP(
        idp_name=SAML_PROVIDER_NAME,
        metadata_url=SAML_METADATA_URL,
        aws_cognito_region=REGION,
        user_pool_id=USER_POOL_ID,
        cognito_idp=cognito_idp
    )

    login_url, _ = provider.get_signin_url(
        relay_state=request.url_root  # Redirect back to the app after login
    )
    return redirect(login_url)


@app.route('/saml_callback')
def saml_callback():
    # SAML callback handling
    provider = warrant.SAMLIdP(
        idp_name=SAML_PROVIDER_NAME,
        metadata_url=SAML_METADATA_URL,
        aws_cognito_region=REGION,
        user_pool_id=USER_POOL_ID,
        cognito_idp=cognito_idp
    )

    try:
        # Parse SAML response and get Cognito tokens
        tokens = provider.process_response(
            http_response=request.form,  # Use 'request.form' for POST data
            aws_cognito_domain=f"cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}"
        )

        # Get identity ID from Cognito
        identity_id = cognito_identity.get_id(
            AccountId='your_aws_account_id',  # Replace with your AWS account ID
            IdentityPoolId=IDENTITY_POOL_ID,
            Logins={
                aws_cognito_domain: tokens['AuthenticationResult']['IdToken']
            }
        )['IdentityId']

        # Get credentials for the identity (if needed)
        credentials = cognito_identity.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins={
                aws_cognito_domain: tokens['AuthenticationResult']['IdToken']
            }
        )['Credentials']

        # Store tokens and credentials in session (optional)
        session['access_token'] = tokens['AuthenticationResult']['AccessToken']
        session['id_token'] = tokens['AuthenticationResult']['IdToken']
        session['refresh_token'] = tokens['AuthenticationResult']['RefreshToken']
        # ... store credentials as needed ...

        return redirect(url_for('index'))

    except warrant.WarrantError as e:
        # Handle SAML errors gracefully
        error_message = str(e) 
        return render_template_string(login_html, error=error_message)


@app.route('/logout')
def logout():
    # Clear session data
    session.clear()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
