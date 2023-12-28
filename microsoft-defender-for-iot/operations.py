"""
Copyright start
MIT License
Copyright (c) 2023 Fortinet Inc
Copyright end
"""

import requests
from datetime import datetime, timezone
from connectors.core.connector import get_logger, ConnectorError
logger = get_logger('microsoft-defender-for-iot')
from .constants import *


class DefenderForIoT:
    def __init__(self, config):
        self.server_url = config.get('server_url').strip('/')
        if not (self.server_url.startswith('https://') or self.server_url.startswith('http://')):
            self.server_url = 'https://' + self.server_url
        self.api_key = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl')

    def make_request(self, endpoint, method='GET', **kwargs):
        try:
            url = self.server_url + endpoint
            logger.info('Executing url {0}'.format(url))
            headers = {'Authorization': self.api_key}
            try:
                headers_copy = headers.copy()
                headers_copy['Authorization'] = "******************************"
                from connectors.debug_utils.curl_script import make_curl
                make_curl(method, url, headers=headers_copy, verify_ssl=self.verify_ssl, **kwargs)
            except Exception as err:
                logger.debug(f"Error in curl utils: {str(err)}")

            response = requests.request(method, url, headers=headers, verify=self.verify_ssl, **kwargs)
            if response.ok:
                logger.info('successfully get response for url {}'.format(url))
                if method.lower() == 'delete':
                    return response
                else:
                    return response.json()
            elif response.status_code == 400:
                error_response = response.json()
                error_description = error_response['message'] if error_response.get('message') else error_response
                raise ConnectorError({'error_description': error_description})
            elif response.status_code == 401:
                error_response = response.json()
                if error_response.get('error'):
                    error_description = error_response['error']
                else:
                    error_description = error_response['message']
                raise ConnectorError({'error_description': error_description})
            elif response.status_code == 404:
                error_response = response.json()
                if error_response.get('message'):
                    error_description = error_response['message']
                    raise ConnectorError({'error_description': error_description})
                raise ConnectorError(error_response)
            else:
                logger.error(response.json())
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            raise ConnectorError(str(err))
        raise ConnectorError(response.text)


def list_alerts(config, params):
    ms = DefenderForIoT(config)
    params['state'] = params.get('state', '').lower()
    params['type'] = params.get('type', '').lower()
    params['fromTime'] = convert_date_to_milliseconds_since_epoch(params.get('fromTime'))
    params['toTime'] = convert_date_to_milliseconds_since_epoch(params.get('toTime'))
    payload = _build_payload(params)
    return ms.make_request(endpoint=ALERTS_ENDPOINT, params=payload)


def list_timeline_events(config, params):
    ms = DefenderForIoT(config)
    if params.get('type'):
        params['type'] = EVENT_TYPE_MAPPING.get(params.get('type'))
    payload = _build_payload(params)
    return ms.make_request(endpoint=EVENTS_ENDPOINT, params=payload)


def list_devices(config, params):
    ms = DefenderForIoT(config)
    payload = _build_payload(params)
    return ms.make_request(endpoint=DEVICES_ENDPOINT, params=payload)


def list_device_cves(config, params):
    ms = DefenderForIoT(config)
    endpoint = IP_ADDRESS_CVE_ENDPOINT.format(params.pop('ipAddress')) if params.get('ipAddress') else DEVICES_CVE_ENDPOINT
    payload = _build_payload(params)
    return ms.make_request(endpoint=endpoint, params=payload)


def get_vulnerability_assessment_report(config, params):
    ms = DefenderForIoT(config)
    return ms.make_request(endpoint=VULNERABILITY_ASSESSMENT_REPORT_ENDPOINT)


def get_device_vulnerability_report(config, params):
    ms = DefenderForIoT(config)
    return ms.make_request(endpoint=DEVICE_VULNERABILITY_REPORT_ENDPOINT)


def get_operational_assessment_report(config, params):
    ms = DefenderForIoT(config)
    return ms.make_request(endpoint=OPERATIONAL_ASSESSMENT_REPORT_ENDPOINT)


def get_mitigation_assessment(config, params):
    ms = DefenderForIoT(config)
    return ms.make_request(endpoint=MITIGATION_ASSESSMENT_REPORT_ENDPOINT)


def _check_health(config):
    try:
        list_alerts(config, params={})
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def _build_payload(params):
    return {key: val for key, val in params.items() if val is not None and val != ''}


def convert_date_to_milliseconds_since_epoch(date_string):
    if date_string:
        dt = datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        milliseconds_since_epoch = int((dt - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds() * 1000)
        return milliseconds_since_epoch


operations = {
    'list_alerts': list_alerts,
    'list_timeline_events': list_timeline_events,
    'list_devices': list_devices,
    'list_device_cves': list_device_cves,
    'get_vulnerability_assessment_report': get_vulnerability_assessment_report,
    'get_device_vulnerability_report': get_device_vulnerability_report,
    'get_operational_assessment_report': get_operational_assessment_report,
    'get_mitigation_assessment': get_mitigation_assessment
}
