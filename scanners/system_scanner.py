import wmi
import subprocess
import platform
import winreg

def get_basic_info():
    c = wmi.WMI()
    os_info = c.Win32_OperatingSystem()[0]
    return {
        'OS': os_info.Caption,
        'OS Version': os_info.Version,
        'Architecture': platform.machine(),
    }

def get_dotnet_versions():
    versions = []
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\NET Framework Setup\NDP')
        for i in range(0, winreg.QueryInfoKey(key)[0]):
            subkey_name = winreg.EnumKey(key, i)
            if subkey_name.startswith('v'):
                versions.append(subkey_name)
    except Exception as e:
        versions.append(str(e))
    return versions

def get_installed_hotfixes():
    c = wmi.WMI()
    return [hotfix.HotFixID for hotfix in c.Win32_QuickFixEngineering()]

def get_registered_antivirus():
    cmd = 'powershell Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct | Select displayName'
    result = subprocess.getoutput(cmd)
    return result.strip()

def scan_system():
    return {
        'Basic Info': get_basic_info(),
        '.NET Versions': get_dotnet_versions(),
        'Hotfixes': get_installed_hotfixes(),
        'Registered AV': get_registered_antivirus(),
    }

if __name__ == "__main__":
    import pprint
    pprint.pprint(scan_system())
