import requests
import json
from requests.exceptions import HTTPError
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class FortiGateAPI:
    """FortiGate API client for handling FortiGate operations.

    Attributes:
        fgt_ip (str): IP address of the FortiGate.
        admin_user (str, optional): Admin username.
        admin_pass (str, optional): Admin password.
        api_user (str, optional): API username.
        api_key (str, optional): API key.
        session (requests.Session): Session object for API interactions.
    """
    
    def __init__(self,
                 fgt_ip: str,
                 admin_user: str = None,
                 admin_pass: str = None,
                 api_user: str = None,
                 api_key: str = None
    ):
        """Initialize the FortiGate API client.

        Args:
            fgt_ip (str): IP address of the FortiGate.
            admin_user (str, optional): Admin username.
            admin_pass (str, optional): Admin password.
            api_user (str, optional): API username.
            api_key (str, optional): API key.
        """
        self.fgt_ip = fgt_ip
        self.admin_user = admin_user
        self.admin_pass = admin_pass
        self.api_user = api_user
        self.api_key = api_key
        self.session = requests.Session()
        self.fgt_session_object_with_auth_cookie = None
        self.fgt_session_object_with_api_key_token = None
        
    def open_fgt_session(self):
        """Opens a session with FortiGate to get an API cookie.
        Required is API key is not provided.

        Raises:
            ConnectionError: If connection to FortiGate fails.
        """
        if not self.fgt_session_object_with_auth_cookie:
            try:
                r = self.session.post(
                    'https://' + self.fgt_ip + '/logincheck',
                    data={'username': self.admin_user, 'secretkey': self.admin_pass},
                    verify=False, timeout=20
                )
                for cookie in self.session.cookies:
                    # TODO: this needs to be change to find both versions 
                    # TODO: of the cookie name
                    # if cookie.name == 'ccsrftoken_443':  # this was added after 7.2
                    if cookie.name == 'ccsrftoken':  # this was working until 7.2
                        self.session.headers.update({'X-CSRFTOKEN': cookie.value[1:-1]})
                self.fgt_session_object_with_auth_cookie = self.session
            except Exception as e:
                raise ConnectionError('Unable to connect to FGT to get API cookie. '
                                      'This can be caused by interface, IP, DNS, path, \
                                      or firewall issues, etc.')

    def close_fgt_session(self):
        """Closes the session with FortiGate."""
        if self.fgt_session_object_with_auth_cookie:
            self.session.post(
                'https://' + self.fgt_ip + '/logout', verify=False, timeout=20
            )
        self.session.close()
        self.fgt_session_object_with_auth_cookie = None
        self.fgt_session_object_with_api_key_token = None
    
    def value_from_key_path(self, working_dictionary, key_path):
        """Extracts the value from a nested dictionary by following the key path.

        Args:
            working_dictionary (dict): The dictionary to search.
            key_path (list): List of keys defining the path to the target value.

        Returns:
            The value found at the key path within the dictionary.

        Raises:
            KeyError: If a key in the key path is not found.
            ValueError: If a list is encountered during traversal.
        """
        value = None
        for key in key_path:
            
            if key_path.index(key) == 0:
                try:
                    value = working_dictionary[key]
                except KeyError as e:
                    raise KeyError(
                        f'value_from_key_path error: The supplied key path contains a '
                        f'key ({e}), which was not found.'
                    )
            else:
                try:
                    value = value[key]
                except KeyError as e:
                    raise KeyError(e)
                except TypeError as e:
                    raise ValueError(
                        f'The supplied dictionary contains a list,'
                        f' which cannot be indexed by the string in the supplied path.'
                    )
        return value

    def get_fgt_api_key_token(self):
        """Obtain an API key token for FortiGate.

        The key is persistent and survives a device reboot.

        Raises:
            KeyError: If incorrect API User.
            ConnectionError: If connection fails.
        """
        if not self.fgt_session_object_with_auth_cookie and not self.api_key:
            self.open_fgt_session()
        if not self.fgt_session_object_with_api_key_token:
            if self.api_key:
                self.fgt_session_object_with_auth_cookie = self.session
                self.fgt_session_object_with_auth_cookie.headers.update(
                    {'Authorization': 'Bearer ' + self.api_key, 'Content-Type': 'application/x-www-form-urlencoded'}
                    )
                self.fgt_session_object_with_api_key_token = self.fgt_session_object_with_auth_cookie
            else:
                body = {'api-user': self.api_user}
                try:
                    response = self.fgt_session_object_with_auth_cookie.post(
                        'https://' + self.fgt_ip + '/api/v2/monitor/system/api-user/generate-key',
                        json=body,
                        verify=False,
                        timeout=20
                    )
                    token = response.json()['results']['access_token']
                    self.fgt_session_object_with_auth_cookie.headers.update({'Authorization': 'Bearer ' + token, 'Content-Type': 'application/x-www-form-urlencoded'})
                    self.fgt_session_object_with_api_key_token = self.fgt_session_object_with_auth_cookie
                except KeyError:
                    raise KeyError(
                        'Connect failure generating API key. Possible Incorrect API User'
                    )
                except Exception as e:
                    raise ConnectionError('Connect failure generating API key.')
        
    def get_response_from_fgt_command(
        self,
        cmd_url,
        cmd_method,
        cmd_parameters=None,
        cmd_data=None,
        cmd_result_key_path=None
    ):
        """Executes a FortiGate API command and returns the result.

        Args:
            cmd_url (str): The URL endpoint for the command.
            cmd_method (str): HTTP method (e.g., 'GET', 'POST').
            cmd_parameters (dict, optional): Query parameters for the command.
            cmd_data (dict, optional): Data payload for the command.
            cmd_result_key_path (list, optional): Key path to extract specific data from the API response.

        Returns:
            JSON response or specific value if cmd_result_key_path is given.

        Raises:
            HTTPError: If HTTP request fails.
            ConnectionError: If connection fails.
        """
        if not self.fgt_session_object_with_api_key_token:
            self.get_fgt_api_key_token()
        try:
            response = self.fgt_session_object_with_api_key_token.request(
                cmd_method,
                'https://' + self.fgt_ip + cmd_url,
                params=cmd_parameters,
                json=cmd_data,
                verify=False,
                timeout=30
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            raise HTTPError(e)
        except Exception as e:
            raise ConnectionError('Connect failure getting response from FGT.')

        if cmd_result_key_path:
            try:
                result = self.value_from_key_path(
                    response.json(), 
                    cmd_result_key_path
                )
                return result
            except ValueError as e:
                return f'ValueError Parsing Key Path: {e}'
            except IndexError as e:
                return f'Error Parsing API Response (IndexError)'
            except KeyError as e:
                return f'Error Parsing API Response ({e})'
            except Exception as e:
                raise ValueError(f'There was an undefined error: {e}')
        else:
            return response


class FortiGateAPICommands(FortiGateAPI):
    """FortiGate API Commands: Derived class for specific FortiGate functionalities."""

    def set_interface_down_6_4(self, interface):
        """Set a FortiGate interface to the down state.

        Args:
            interface (str): The name of the interface.

        Returns:
            str: The new state of the interface ('down').
        """
        kwargs = {"cmd_url": f"/api/v2/cmdb//system/interface/{interface}",
                  "cmd_method": "put",
                  "cmd_data": {"status": "down"},
                  "cmd_result_key_path": ['status']
                  }
        return self.get_response_from_fgt_command(**kwargs)

    def set_interface_up_6_4(self, interface):
        """Set a FortiGate interface to the up state.

        Args:
            interface (str): The name of the interface.

        Returns:
            str: The new state of the interface ('up').
        """
        kwargs = {"cmd_url": f"/api/v2/cmdb//system/interface/{interface}",
                  "cmd_method": "put",
                  "cmd_data": {"status": "up"},
                  "cmd_result_key_path": ['status']
                  }
        return self.get_response_from_fgt_command(**kwargs)

    def get_system_status(self):
        """Retrieve the system status.
        this is almost like a loopback test. should always work.
        a copy of it should be in every testing class for diagnostics
 
        Returns:
            str: Serial number of the device.
        """
        kwargs = {"cmd_url": "/api/v2/monitor/system/status",
                  "cmd_method": "get",
                  "cmd_data": None,
                  "cmd_result_key_path": ['serial']
                  }
        return self.get_response_from_fgt_command(**kwargs)
    
    def get_fortios_version(self):
        """Retrieve the FortiOS version.

        Returns:
            str: The version of FortiOS running on the device.
        """
        kwargs = {"cmd_url": "/api/v2/monitor/system/status",
                  "cmd_method": "get",
                  "cmd_data": None,
                  "cmd_result_key_path": ['version']
                  }
        return self.get_response_from_fgt_command(**kwargs)

    def get_interface_link(self, interface):
        """Retrieve the link status of a given interface.

        Args:
            interface (str): The name of the interface.

        Returns:
            str: The link status ('up' or 'down').
        """
        kwargs = {"cmd_url": "/api/v2/monitor/system/interface",
                  "cmd_method": "get",
                  "cmd_parameters": {"interface_name": f"{interface}"},
                  "cmd_result_key_path": ['results', f'{interface}', 'link']
                  }
        return self.get_response_from_fgt_command(**kwargs)

    def get_fortiview_by_source(self, source_ip):
        """Retrieve FortiView statistics by source IP.

        Args:
            source_ip (str): The source IP address to filter by.

        Returns:
            dict: FortiView statistics for the given source IP.
        """
        kwargs = {"cmd_url": "/api/v2/monitor/fortiview/statistics",
                  "cmd_method": "get",
                  "cmd_parameters": {
                      # "filter": "{'source': '172.16.23.17'}",  # example syntax
                      "filter": json.dumps({"source": source_ip}),
                      "report_by": "destination",
                      "realtime": True,
                      },
                  "cmd_result_key_path": ['results']
                  }
        return self.get_response_from_fgt_command(**kwargs)
