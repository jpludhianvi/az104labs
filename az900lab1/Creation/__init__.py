import azure.functions as func
import logging
import random
import string
import requests
import json
import uuid
import os
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.authorization.models import RoleDefinition, Permission, RoleAssignmentCreateParameters
 
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
 
def create_user(tenant_id, client_id, client_secret, scope, subscription_id, resource_group_location, username, password):
    def get_access_token(tenant_id, client_id, client_secret, scope):
        token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
        token_data = {
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
            'scope': scope,
        }
        token_r = requests.post(token_url, data=token_data)
        token_response = token_r.json()
 
        if 'access_token' not in token_response:
            raise Exception(f"Failed to obtain access token: {token_response}")
 
        return token_response['access_token']
 
    def generate_random_string(length):
        letters_and_digits = string.ascii_letters + string.digits
        return ''.join(random.choice(letters_and_digits) for i in range(length))
 
    def generate_random_user_principal_name(username):
        user = username
        username = ''.join(char for char in user if not char.isspace())
        suffix = "@INTERNATIONALKNOWLEDGEACADE.onmicrosoft.com"
        username = username.lower()
        return f"{username}{suffix}"
 
    def generate_unique_serial_number(length=6):
        return ''.join(random.choices(string.digits, k=length))
 
    def generate_custom_role_name():
        prefix = "AZ900LAB1ROLE"
        serial_number = generate_unique_serial_number()
        return f"{prefix}{serial_number}"
 
    def generate_unique_resource_group_name():
        prefix = "AZ900LAB1GROUP"
        serial_number = generate_unique_serial_number()
        return f"{prefix}{serial_number}"
 
    def create_resource_group(credentials, subscription_id, resource_group_name, resource_group_location):
        resource_client = ResourceManagementClient(credentials, subscription_id)
        resource_group_params = {'location': resource_group_location}
        return resource_client.resource_groups.create_or_update(resource_group_name, resource_group_params)
 
    def create_custom_role(auth_client, subscription_id, resource_group_name, permissions):
        role_definition_id = str(uuid.uuid4())
        role_name = generate_custom_role_name()
        role_definition_properties = RoleDefinition(
            role_name=role_name,
            description="Custom role that allows user to explore azure core services.",
            permissions=[permissions],
            assignable_scopes=[f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}"]
        )
        return auth_client.role_definitions.create_or_update(
            scope=f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}",
            role_definition_id=role_definition_id,
            role_definition=role_definition_properties
        )
 
    def assign_custom_role(auth_client, subscription_id, resource_group_name, custom_role, user_info):
        role_assignment_params = RoleAssignmentCreateParameters(
            role_definition_id=custom_role.id,
            principal_id=user_info['id']
        )
        return auth_client.role_assignments.create(
            scope=f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}",
            role_assignment_name=str(uuid.uuid4()),
            parameters=role_assignment_params
        )
 
    def create_user_graph_api(token, user_data):
        graph_url = 'https://graph.microsoft.com/v1.0/users'
        headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
        response = requests.post(graph_url, headers=headers, data=json.dumps(user_data))
 
        if response.status_code == 201:
            return response.json()
        else:
            raise Exception(f"Failed to create user: {response.status_code}, {response.json()}")
 
    # Get access token
    token = get_access_token(tenant_id, client_id, client_secret, scope)
    # Generate random user details
    user_principal_name = generate_random_user_principal_name(username)
    generated_password = password
    user_data = {
        "accountEnabled": True,
        "displayName": "Demo User",
        "mailNickname": "demouser",
        "userPrincipalName": user_principal_name,
        "passwordProfile": {
            "forceChangePasswordNextSignIn": False,
            "password": generated_password
        }
    }
 
    # Initialize the credentials
    credentials = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret
    )
 
    # Generate unique resource group name
    resource_group_name = generate_unique_resource_group_name()
 
    # Create resource group
    resource_client = ResourceManagementClient(credentials, subscription_id)
    resource_group = create_resource_group(credentials, subscription_id, resource_group_name, resource_group_location)
 
    # Define permissions
    permissions = Permission(
        actions=[
                  "Microsoft.Compute/virtualMachines/*",
            "Microsoft.Compute/virtualMachines/extensions/*",
            "Microsoft.Network/networkInterfaces/*",
            "Microsoft.Network/publicIPAddresses/*",
            "Microsoft.Network/virtualNetworks/*",
            "Microsoft.Resources/deployments/*",
            "Microsoft.Resources/subscriptions/resourceGroups/read",
            "Microsoft.Resources/subscriptions/resourceGroups/deployments/*",
            "Microsoft.Storage/storageAccounts/*",
            "Microsoft.Network/networkSecurityGroups/*",
            "Microsoft.Network/routeTables/*"
        ],
        not_actions=[
        ]
    )
    # Initialize the Authorization Management client
    auth_client = AuthorizationManagementClient(credentials, subscription_id)
 
    # Create custom role
    custom_role = create_custom_role(auth_client, subscription_id, resource_group_name, permissions)
 
    # Create user in Graph API and assign custom role
    user_info = create_user_graph_api(token, user_data)
    assign_custom_role(auth_client, subscription_id, resource_group_name, custom_role, user_info)
 
    return user_info['userPrincipalName'], resource_group_name
 
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
 
    # Azure credentials
    client_id = os.getenv("client_id")
    client_secret = os.getenv('client_secret')
    tenant_id = os.getenv("tenant_id")
    subscription = os.getenv("subscription")
    resource_group_location = os.getenv("resource_group_location")
    scope = "https://graph.microsoft.com/.default"
    username = req.params.get('username')
    password = req.params.get('password')
    try:
        user_principal_name, resource_group_name = create_user(tenant_id, client_id, client_secret, scope, subscription, resource_group_location, username, password)
        return func.HttpResponse(json.dumps({
                    "status": "Success",
                    "userPrincipalName": user_principal_name,
                    "resource_group_name": resource_group_name
                }))
    except Exception as e:
        return func.HttpResponse(f"Error in creation: {e}", status_code=500)
    

   
