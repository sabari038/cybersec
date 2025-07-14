# config.py

SNMPV3 = {
    'user': 'snmpuser',
    'authKey': 'authpassword',
    'privKey': 'privpassword',
    'target': '192.168.1.1'
}

SSH_DEVICES = [
    {
        'device_type': 'cisco_ios',
        'host': '192.168.1.1',
        'username': 'admin',
        'password': 'admin123'
    }
]

WHITELIST_DEVICES = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
