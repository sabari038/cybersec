from netmiko import ConnectHandler
from config import SSH_DEVICES

def get_eigrp_neighbors():
    neighbors = []
    for device in SSH_DEVICES:
        try:
            connection = ConnectHandler(**device)
            output = connection.send_command("show ip eigrp neighbors")
            neighbors.append(output)
            connection.disconnect()
        except Exception as e:
            print(f"SSH connection failed for {device['host']}: {e}")
    return neighbors

if __name__ == '__main__':
    neighbors = get_eigrp_neighbors()
    print(neighbors)
