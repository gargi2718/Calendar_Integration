from django.conf import settings
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseRedirect
from django.urls import reverse
from django.views import View
from google.oauth2 import credentials
from google_auth_oauthlib import flow

'''


def create_oauth_flow(request):
    oauth_flow = flow.Flow.from_client_secrets_file(
        'D:/Django_Calender/venv/Scripts/client_secret.json',
        scopes=['https://www.googleapis.com/auth/calendar.readonly'],
        redirect_uri=request.build_absolute_uri(reverse('calendar-redirect'))
    )
    return oauth_flow



class GoogleCalendarInitView(View):
    def get(self, request):
        flow = create_oauth_flow(request)
        auth_url, _ = flow.authorization_url(prompt='consent')
        return HttpResponseRedirect(auth_url)

class GoogleCalendarRedirectView(View):
    def get(self, request):
        code = request.GET.get('code')
        if not code:
            return HttpResponseBadRequest('Code parameter is missing.')

        flow = create_oauth_flow(request)

        try:
            flow.fetch_token(code=code)
        except Exception as e:
            return HttpResponseBadRequest(f'Error exchanging code for credentials: {e}')

        credentials = flow.credentials
        events = get_events()
        # Now, you can use the obtained `credentials` to make API requests
        # For example, let's fetch a list of events from the user's calendar
        # (Make sure to include the necessary imports and set up the calendar service)

        return JsonResponse({'events': events})
      '''  '''
def create_oauth_flow(request):
    flow = flow.Flow.from_client_secrets_file(
        client_secrets_file=settings.GOOGLE_CLIENT_SECRETS_FILE,
        scopes=['https://www.googleapis.com/auth/calendar.events.readonly'],
        redirect_uri=request.build_absolute_uri(reverse('calendar-redirect'))
    )

    flow.code_verifier = credentials.generate_code_verifier()
    request.session['code_verifier'] = flow.code_verifier

    return flow

# views.py

import json
import requests
from django.http import JsonResponse
from django.views import View


class GoogleCalendarInitView(View):
    def get(self, request):
        # Step 1: Prompt the user for their credentials
        # Redirect the user to the Google OAuth consent screen
        # Include the necessary query parameters for OAuth authorization
        oauth_params = {
            'response_type': 'code',
            'client_id': 'YOUR_CLIENT_ID',
            'redirect_uri': 'YOUR_REDIRECT_URI',
            'scope': 'https://www.googleapis.com/auth/calendar.readonly',
            'access_type': 'offline',
        }
        oauth_url = 'https://accounts.google.com/o/oauth2/auth?' + '&'.join(
            f'{key}={value}' for key, value in oauth_params.items())
        return JsonResponse({'url': oauth_url})


class GoogleCalendarRedirectView(View):
    def get(self, request):
        # Step 2: Handle the redirect request and exchange the authorization code for an access token
        authorization_code = request.GET.get('code')
        token_params = {
            'code': authorization_code,
            'client_id': '243901381939-apllrjpjdurdra354ra2auvpj0vjovqu.apps.googleusercontent.com',
            'client_secret': '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',
            'redirect_uri': 'http://localhost:8000/rest/v1/calendar/redirect/',
            'grant_type': authorization_code,
        }
        token_url = 'https://accounts.google.com/o/oauth2/token'
        response = requests.post(token_url, data=token_params)
        response_data = json.loads(response.text)

        if 'access_token' in response_data:
            access_token = response_data['access_token']
            # Step 3: Use the access token to get a list of events in the user's calendar
            events_url = 'https://www.googleapis.com/calendar/v3/calendars/primary/events'
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json',
            }
            response = requests.get(events_url, headers=headers)
            events_data = json.loads(response.text)
            events = events_data.get('items', [])

            return JsonResponse({'events': events})

        return JsonResponse({'error': 'Failed to obtain access token'})'''
'''

from django.shortcuts import redirect
import requests

def GoogleCalendarInitView(request):
    # Construct the authorization URL
    authorization_url = 'https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=243901381939-apllrjpjdurdra354ra2auvpj0vjovqu.apps.googleusercontent.com&redirect_uri=http://localhost:8000/rest/v1/calendar/redirect/&scope=https://www.googleapis.com/auth/calendar.readonly&access_type=offline'

    # Redirect the user to the authorization URL
    return redirect(authorization_url)

def GoogleCalendarRedirectView(request):
    # Extract the authorization code from the request
    authorization_code = request.GET.get('code')

    # Exchange the authorization code for access token
    token_url = 'https://oauth2.googleapis.com/token'
    client_id = '243901381939-apllrjpjdurdra354ra2auvpj0vjovqu.apps.googleusercontent.com'
    client_secret = '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'
    redirect_uri = 'http://localhost:8000/rest/v1/calendar/redirect/'

    payload = {
        'code': authorization_code,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code'
    }

    response = requests.post(token_url, data=payload)
    access_token = response.json()['access_token']

    # Once you have the access token, you can use it to get the list of events in the user's calendar
    # Implement the logic to retrieve events using the access token

    # Return the events data as a response
    events = ['Event 1', 'Event 2', 'Event 3']
    return JsonResponse({'events': events})

import requests
from django.http import JsonResponse
from django.views import View

class GoogleCalendarRedirectView(View):
    def get(self, request):
        code = request.GET.get('code')
        if code:
            # Exchange authorization code for access token
            token_url = 'https://oauth2.googleapis.com/token'
            data = {
                'code': code,
                'client_id': '243901381939-apllrjpjdurdra354ra2auvpj0vjovqu.apps.googleusercontent.com',
                'client_secret': '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',
                'redirect_uri': 'http://localhost:8000/rest/v1/calendar/redirect/',
                'grant_type': 'https://www.googleapis.com/oauth2/v1/certs',
            }
            response = requests.post(token_url, data=data)
            if response.status_code == 200:
                # Extract access token from response JSON
                access_token = response.json().get('access_token')
                if access_token:
                    # Use the access token to fetch events from the user's calendar
                    events_url = 'https://www.googleapis.com/calendar/v3/calendars/primary/events'
                    headers = {
                        'Authorization': f'Bearer {access_token}',
                    }
                    events_response = requests.get(events_url, headers=headers)
                    if events_response.status_code == 200:
                        events = events_response.json().get('items', [])
                        return JsonResponse({'events': events})
                    else:
                        return JsonResponse({'error': 'Failed to fetch events'}, status=events_response.status_code)
                else:
                    return JsonResponse({'error': 'Access token not found in response'}, status=500)
            else:
                return JsonResponse({'error': 'Failed to exchange authorization code for access token'}, status=response.status_code)
        else:
            return JsonResponse({'error': 'Authorization code not provided'}, status=400)

from django.shortcuts import redirect

from rest_framework.decorators import api_view
from rest_framework.response import Response

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import os

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "D:/Django_Calender/venv/Scripts/client_secret.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection and REDIRECT URL.
SCOPES = ['https://www.googleapis.com/auth/calendar',
          'https://www.googleapis.com/auth/userinfo.email',
          'https://www.googleapis.com/auth/userinfo.profile',
          'openid']
REDIRECT_URL = 'http://127.0.0.1:8000/rest/v1/calendar/redirect'
API_SERVICE_NAME = 'calendar'
API_VERSION = 'v3'


@api_view(['GET'])
def google_calendar_init_view(request):
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    # The URI created here must exactly match one of the authorized redirect URIs
    # for the OAuth 2.0 client, which you configured in the API Console. If this
    # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
    # error.
    flow.redirect_uri = REDIRECT_URL

    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true')

    # Store the state so the callback can verify the auth server response.
    request.session['state'] = state

    return Response({"authorization_url": authorization_url})


@api_view(['GET'])
def google_calendar_redirect_view(request):
    # Specify the state when creating the flow in the callback so that it can
    # verify in the authorization server response.
    state = request.session['state']
    if state is None:
        return Response({"error": "State parameter missing."})

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = REDIRECT_URL

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = request.get_full_path()
    flow.fetch_token(authorization_response=authorization_response)

    # Save credentials back to session in case access token was refreshed.
    # ACTION ITEM: In a production app, you likely want to save these
    # credentials in a persistent database instead.
    credentials = flow.credentials
    request.session['credentials'] = credentials_to_dict(credentials)

    # Check if credentials are in session
    if 'credentials' not in request.session:
        return redirect('v1/calendar/init')

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **request.session['credentials'])

    # Use the Google API Discovery Service to build client libraries, IDE plugins,
    # and other tools that interact with Google APIs.
    # The Discovery API provides a list of Google APIs and a machine-readable "Discovery Document" for each API
    service = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)

    # Returns the calendars on the user's calendar list
    calendar_list = service.calendarList().list().execute()

    # Getting user ID which is his/her email address
    calendar_id = calendar_list['items'][0]['id']

    # Getting all events associated with a user ID (email address)
    events = service.events().list(calendarId=calendar_id).execute()

    events_list_append = []
    if not events['items']:
        print('No data found.')
        return Response({"message": "No data found or user credentials invalid."})
    else:
        for events_list in events['items']:
            events_list_append.append(events_list)

    # return Response({"error": "calendar event aren't here"})
    return Response({"events": events_list_append})


def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

import json
from google.oauth2 import service_account
from googleapiclient.discovery import build
from django.http import JsonResponse
from django.views import View

class GoogleCalendarInitView(View):
    def get(self, request):
        credentials = service_account.Credentials.from_service_account_file(
            'path/to/service-account-key.json',
            scopes=['https://www.googleapis.com/auth/calendar.readonly'],
            redirect_uri='http://localhost:8000/rest/v1/calendar/redirect/'
        )

        auth_url, _ = credentials.authorization_url(
            'https://accounts.google.com/o/oauth2/auth',
            access_type='offline'
        )

        return JsonResponse({'url': auth_url})

class GoogleCalendarRedirectView(View):
    def get(self, request):
        code = request.GET.get('code')
        if code:
            # Exchange authorization code for access token
            credentials = service_account.Credentials.from_service_account_file(
                'D:/Django_Calender/venv/Scripts/client_secret.json',
                scopes=['https://www.googleapis.com/auth/calendar.readonly'],
            )
            credentials.fetch_token(code=code)

            # Build the service using the credentials
            service = build('calendar', 'v3', credentials=credentials)

            # Get the list of events from the user's primary calendar
            events_result = service.events().list(calendarId='primary').execute()
            events = events_result.get('items', [])

            return JsonResponse({'events': events})
        else:
            return JsonResponse({'error': 'Authorization code not provided'}, status=400)
'''
# views.py

import json
import requests

from django.http import JsonResponse
from django.views import View


# Step 1: GoogleCalendarInitView - Prompt user for credentials

class GoogleCalendarInitView(View):
    def get(self, request):
        # Construct the authorization URL
        client_id = '243901381939-apllrjpjdurdra354ra2auvpj0vjovqu.apps.googleusercontent.com'
        redirect_uri = 'http://127.0.0.1:8000/rest/v1/calendar/redirect'
        scope = 'https://www.googleapis.com/auth/calendar.readonly'
        access_type = 'offline'
        auth_url = f'https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&access_type={access_type}'

        # Redirect the user to the authorization URL
        return JsonResponse({'auth_url': auth_url})


# Step 2: GoogleCalendarRedirectView - Handle redirect and obtain access token

class GoogleCalendarRedirectView(View):
    def get(self, request):
        # Get the authorization code from the request URL
        authorization_code = request.GET.get('code')

        if authorization_code:
            # Exchange the authorization code for an access token
            client_id = '243901381939-apllrjpjdurdra354ra2auvpj0vjovqu.apps.googleusercontent.com'
            client_secret = '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'
            redirect_uri = 'http://127.0.0.1:8000/rest/v1/calendar/redirect'
            token_url = 'https://accounts.google.com/o/oauth2/token'
            payload = {
                'code': authorization_code,
                'client_id': client_id,
                'client_secret': client_secret,
                'redirect_uri': redirect_uri,
                'grant_type': 'authorization_code'
            }

            response = requests.post(token_url, data=payload)
            if response.ok:
                # Extract the access token from the response
                access_token = response.json().get('access_token')

                # Step 3: Get list of events using access token
                events = self.get_events(access_token)

                return JsonResponse({'events': events})

        return JsonResponse({'error': 'Authorization code not provided'})

    def get_events(self, access_token):
        # Make API request to get events
        events_url = 'https://www.googleapis.com/calendar/v3/calendars/primary/events'
        headers = {'Authorization': f'Bearer {access_token}'}

        response = requests.get(events_url, headers=headers)
        if response.ok:
            return response.json().get('items', [])

        return []



