"""
Copyright start
MIT License
Copyright (c) 2023 Fortinet Inc
Copyright end
"""

ALERTS_ENDPOINT = '/api/v1/alerts'
EVENTS_ENDPOINT = '/api/v1/events'
DEVICES_ENDPOINT = 'api/v1/devices/'
DEVICES_CVE_ENDPOINT = 'api/v1/devices/cves'
IP_ADDRESS_CVE_ENDPOINT = 'api/v1/devices/{0}/cves'
DEVICE_VULNERABILITY_REPORT_ENDPOINT = '/api/v1/reports/vulnerabilities/devices'
VULNERABILITY_ASSESSMENT_REPORT_ENDPOINT = '/api/v1/reports/vulnerabilities/security'
OPERATIONAL_ASSESSMENT_REPORT_ENDPOINT = '/api/v1/reports/vulnerabilities/operational'
MITIGATION_ASSESSMENT_REPORT_ENDPOINT = '/api/v1/reports/vulnerabilities/mitigation'
EVENT_TYPE_MAPPING = {'Device Detected': 'DEVICE_CREATE', 'Device Updated': 'DEVICE_UNIFICATION',
                      'Alert Detected': 'ALERT_REPORTED', 'Alert Updated': 'ALERT_UPDATED',
                      'Scan Device Detected': 'SCAN',
                      'PLC Programming': 'S7PLUS_PROGRAMMING', 'PLC Program Update': 'MMS_PROGRAM_DEVICE',
                      'SCL Uploaded': 'SCL_UPLOADED', 'Exclusion Rule Created': 'EXCLUSION_RULE_CREATED',
                      'Exclusion Rule Removed': 'EXCLUSION_RULE_REMOVED',
                      'Exclusion Rule Updated': 'EXCLUSION_RULE_UPDATED',
                      'Device Connection Detected': 'DEVICE_CONNECTION_CREATED', 'User Login Attempt': 'USER_LOGIN',
                      'File Transfer Detected': 'FILE_TRANSFER', 'User Defined Event': 'CUSTOM_EVENT',
                      'Remote Access Connection Established': 'REMOTE_ACCESS', 'Back to Normal': 'BACK_TO_NORMAL',
                      'MMS Memory Block Operation': 'MMS_MEMORY_BLOCK_OPERATION',
                      'MMS Program Operation': 'MMS_PROGRAM_OPERATION',
                      'HTTP Basic Authentication': 'HTTP_BASIC_AUTHENTICATION',
                      'Siemens S7 Memory Block Operation': 'SIEMENS_S_7_MEMORY_BLOCK_OPERATION',
                      'Siemens S7 Authentication': 'SIEMENS_S_7_AUTHENTICATION', 'Report Created': 'REPORT_CREATED',
                      'SNMP Trap detected': 'SNMP_TRAP', 'Database Structure Manipulation': 'DATABASE_ACTION',
                      'PLC Module Change': 'PLC_MODULE_CHANGE', 'Firmware Update': 'SRTP_PLC_COPY_FIRMWARE',
                      'PLC Start': 'PLC_START', 'PLC Reset': 'SRTP_PLC_RESET',
                      'PLC Programming Mode Set': 'SRTP_LOGIN_PROGRAMMING',
                      'PLC Password Change': 'SRTP_PLC_CHANGE_PASSWORD',
                      'OPC Data Access Group Management Operation': 'OPC_DATA_ACCESS_GROUP_MANAGEMENT_OPERATION',
                      'OPC Data Access Item Management Operation': 'OPC_DATA_ACCESS_ITEM_MANAGEMENT_OPERATION',
                      'OPC Data Access IO Subscription Management Operation': 'OPC_DATA_ACCESS_IO_SUBSCRIPTION_MANAGEMENT_OPERATION',
                      'OPC AE Event Subscription': 'OPC_AE_EVENT_SUBSCRIPTION',
                      'OPC AE Event Condition Management Operation': 'OPC_AE_EVENT_CONDITION_MANAGEMENT_OPERATION',
                      'OPC AE Event': 'OPC_AE_EVENT', 'PLC Change access level': 'SRTP_CHANGE_PRIVILEGE',
                      'PLC Change access level failed': 'SRTP_CHANGE_LEVEL_FAILED',
                      'Wonderware session initialized': 'SUITELINK_INIT_CONNECTION', 'User Operation': 'USER_OPERATION',
                      'Data Intelligence Package Uploaded': 'DIP_UPLOADED',
                      'FTP Authentication Failure': 'FTP_AUTHENTICATION_FAILURE',
                      'Profinet SET operation': 'PROFINET_DPC_VALUE_SET', 'PLC Mode Change': 'S7_PLC_MODE_CHANGE',
                      'Device Deleted': 'DELETE_DEVICE', 'PLC Firmware Changed': 'FIRMWARE_CHANGED',
                      'DeltaV Install Script': 'DELTAV_PROGRAMMING',
                      'User Defined Rule Created': 'USER_DEFINED_RULE_CREATED',
                      'User Defined Rule Edited': 'USER_DEFINED_RULE_EDITED',
                      'User Defined Rule Deleted': 'USER_DEFINED_RULE_DELETED',
                      'User Defined Rule Operation': 'USER_DEFINED_RULE_OPERATION',
                      'Remote Process Execution': 'REMOTE_PROCESS_EXECUTION',
                      'Notification was resolved manually': 'NOTIFICATION',
                      'Controller Program Delete': 'ENIP_CONTROLLER_PROGRAM_DELETE',
                      'Controller Program Reset': 'ENIP_CONTROLLER_PROGRAM_RESET',
                      'Controller Reset': 'ENIP_CONTROLLER_GENERIC_RESET',
                      'Controller Stop': 'ENIP_CONTROLLER_GENERIC_STOP',
                      'Controller Start': 'ENIP_CONTROLLER_GENERIC_START',
                      'Telnet Authentication Failure': 'TELNET_AUTHENTICATION_FAILURE',
                      'Configuration Of Cleartext Password': 'CONFIGURATION_OF_CLEARTEXT_PASSWORD',
                      'Cleartext Authentication': 'CLEARTEXT_AUTHENTICATION',
                      'PLC Program Upload': 'PROGRAM_UPLOAD_DEVICE',
                      'PLC Configuration Write': 'CONFIGURATION_CHANGE', 'PLC Configuration Read': 'CONFIGURATION_READ',
                      'Syslog Message': 'SYSLOG_MSG', 'Internet Access': 'INTERNET_ACCESS',
                      'Common ASCII Message Protocol Memory Write Operation': 'CAMP_MEMORY_WRITE_OPERATION',
                      'Event Detected and Muted': 'MUTED_ALERT', 'Address Update': 'HARDWARE_UPDATE_BY_IDENTIFIER',
                      'Data Intelligence Package Installation Failure': 'DIP_FAILURE',
                      'Inactive Devices Scheduled for deletion': 'DELETE_DEVICE_SCHEDULE',
                      'PLC Operating Mode Change Detected': 'PLC_OPERATING_MODE_CHANGED'}
