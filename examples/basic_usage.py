import fortios_api.fortios_api as fos

# replace the values below with your own
FGT_IP = None
ADMIN_USER = None
ADMIN_PASS = None
API_USER = None
API_KEY = None 

# create a FortiGateAPICommands object
fgt = fos.FortiGateAPICommands(
    fgt_ip=FGT_IP,
    admin_user=ADMIN_USER,
    admin_pass=ADMIN_PASS,
    api_user=API_USER,
    api_key=API_KEY
)

SOURCE_IP = '192.168.121.12'
# some test commands
fv = fgt.get_fortiview_by_source(SOURCE_IP)
gs = fgt.get_system_status()
il = fgt.get_interface_link('wan1')
