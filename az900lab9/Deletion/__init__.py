import azure.functions as func
import logging
import requests
import json
import uuid
import os
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
 
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
 
def delete_user(tenant_id, client_id, client_secret, scope, subscription_id, resource_group_name, user_principal_name):
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
 
    def delete_user_graph_api(token, user_principal_name):
        graph_url = f'https://graph.microsoft.com/v1.0/users/{user_principal_name}'
        headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
        response = requests.delete(graph_url, headers=headers)
 
        if response.status_code == 204:
            return True
        else:
            raise Exception(f"Failed to delete user: {response.status_code}, {response.json()}")
 
    def delete_role_assignment(auth_client, subscription_id, resource_group_name, user_principal_name):
        # Find the role assignment for the user
        assignments = auth_client.role_assignments.list_for_scope(f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}")
        for assignment in assignments:
            if assignment.principal_id == user_principal_name:
                auth_client.role_assignments.delete_by_id(assignment.id)
                break
 
    def detach_custom_role(auth_client, subscription_id, resource_group_name, custom_role_name_prefix="azurecoreservices"):
        role_definitions = auth_client.role_definitions.list(f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}")
        for role in role_definitions:
            if role.role_name.startswith(custom_role_name_prefix):
                # Detach role assignments for this custom role
                assignments = auth_client.role_assignments.list_for_scope(f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}")
                for assignment in assignments:
                    if assignment.role_definition_id.split('/')[-1] == role.id.split('/')[-1]:
                        auth_client.role_assignments.delete_by_id(assignment.id)
                # Delete the custom role
                auth_client.role_definitions.delete(
                    scope=f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}",
                    role_definition_id=role.id.split('/')[-1]
                )
                break
 
    def delete_resource_group(resource_client, resource_group_name):
        resource_client.resource_groups.begin_delete(resource_group_name)
 
    # Get access token
    token = get_access_token(tenant_id, client_id, client_secret, scope)
 
    # Initialize the credentials
    credentials = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret
    )
 
    # Initialize the clients
    resource_client = ResourceManagementClient(credentials, subscription_id)
    auth_client = AuthorizationManagementClient(credentials, subscription_id)
 
    # Perform deletion steps
    deletion_status = {
        'user_deletion': False,
        'role_assignment_deletion': False,
        'custom_role_deletion': False,
        'resource_group_deletion': False
    }
 
    try:
        delete_user_graph_api(token, user_principal_name)
        deletion_status['user_deletion'] = True
    except Exception as e:
        logging.error(f"User deletion failed: {e}")
 
    try:
        delete_role_assignment(auth_client, subscription_id, resource_group_name, user_principal_name)
        deletion_status['role_assignment_deletion'] = True
    except Exception as e:
        logging.error(f"Role assignment deletion failed: {e}")
 
    try:
        detach_custom_role(auth_client, subscription_id, resource_group_name)
        deletion_status['custom_role_deletion'] = True
    except Exception as e:
        logging.error(f"Custom role deletion failed: {e}")
 
    try:
        delete_resource_group(resource_client, resource_group_name)
        deletion_status['resource_group_deletion'] = True
    except Exception as e:
        logging.error(f"Resource group deletion failed: {e}")
 
    return deletion_status
 
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
 
    # Azure credentials
    client_id = os.getenv("client_id")
    client_secret = os.getenv('client_secret')
    tenant_id = os.getenv("tenant_id")
    subscription_id = os.getenv("subscription")
    resource_group_name = req.params.get('resource_group_name')
    user_principal_name = req.params.get('user_principal_name')
    scope = "https://graph.microsoft.com/.default"
 
    # Check for missing environment variables
    if not all([client_id, client_secret, tenant_id, subscription_id, resource_group_name, user_principal_name]):
        return func.HttpResponse(
            "Missing one or more required environment variables or parameters.",
            status_code=400
        )
    
    try:
        deletion_status = delete_user(tenant_id, client_id, client_secret, scope, subscription_id, resource_group_name, user_principal_name)
        return func.HttpResponse(f"Deletion Status: {deletion_status}")
    except Exception as e:
        return func.HttpResponse(f"Error in deletion: {e}", status_code=500)
