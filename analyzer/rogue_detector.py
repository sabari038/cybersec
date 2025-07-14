from config import WHITELIST_DEVICES

def detect_rogue_devices(discovered_devices):
    rogue = []
    for device in discovered_devices:
        if device not in WHITELIST_DEVICES:
            rogue.append(device)
    return rogue
