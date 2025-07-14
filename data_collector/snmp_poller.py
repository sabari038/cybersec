from pysnmp.hlapi import (
    nextCmd,
    SnmpEngine,
    UsmUserData,
    usmHMACSHAAuthProtocol,
    usmAesCfb128Protocol,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity
)

from config import SNMPV3

def snmpv3_walk(oid):
    results = []
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
            SnmpEngine(),
            UsmUserData(SNMPV3['user'], SNMPV3['authKey'], SNMPV3['privKey'],
                        authProtocol=usmHMACSHAAuthProtocol,
                        privProtocol=usmAesCfb128Protocol),
            UdpTransportTarget((SNMPV3['target'], 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False):

        if errorIndication or errorStatus:
            print("SNMP error:", errorIndication or errorStatus)
            break
        for varBind in varBinds:
            results.append(varBind)
    return results

if __name__ == '__main__':
    arp_oid = '1.3.6.1.2.1.4.22.1.2'
    data = snmpv3_walk(arp_oid)
    for entry in data:
        print(entry)
