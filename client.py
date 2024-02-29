# CODE USES PYTHON 3
from socket import *
import sys
import secrets
import time

# helper functions

# get int value from bytes
def get_int(remaining_bytes, bytes_to_parse):
    return int.from_bytes(remaining_bytes[:bytes_to_parse], 'big'), remaining_bytes[bytes_to_parse:] # returns int result, and remaining bytes left after parsing that result

# get name string from bytes
def get_name(remaining_bytes, total_bytes):
    name_parts = []
    while True:
        if (remaining_bytes[0] & (1 << 6)) and (remaining_bytes[0] & (1 << 7)):  # if label byte begins ones as the first two bits, it is a pointer
            offset, remaining_bytes = get_int(remaining_bytes, 2)
            label_loc = offset - (3 << 14)  # remove the first two one bits from the beginning to get location of label
            label, _ = get_name(total_bytes[label_loc:], total_bytes) # call function again from label location
            name_parts.append(label)
            break
        else:  # otherwise, label is a normal qname
            ln, remaining_bytes = get_int(remaining_bytes, 1)
            label, remaining_bytes = remaining_bytes[:ln], remaining_bytes[ln:]
            if len(label) == 0:
                break
            name_parts.append(label.decode())
    return '.'.join(name_parts), remaining_bytes # returns string result, and remaining bytes left after parsing that result


# Main
try:
    resolver_ip = sys.argv[1]
    resolver_port = int(sys.argv[2])
    name = sys.argv[3]
    time_out = int(sys.argv[4])
except:
    print('Error: invalid arguments\nUsage: client resolver_ip resolver_port name timeout')
    sys.exit(1)

start = time.time()
dns_types = {1: 'A', 2: 'NS', 5: 'CNAME'}
dns_classes = {1: 'IN', 2: 'CS', 3: 'ch', 4: 'HS'}

client_socket = socket(AF_INET, SOCK_DGRAM)

# create query
if resolver_ip == '127.0.0.1': # no recursion (localhost)
    header = secrets.token_bytes(2) + b'\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
else: # recursion desired (public server)
    header = secrets.token_bytes(2) + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
qname = b''.join(bytes([len(part)]) + part.encode() for part in name.split('.'))
qtype = int.to_bytes(1, length = 2, byteorder = 'big')
qclass = b'\x00\x01'
query = header + qname + b'\x00' + qtype + qclass
client_socket.sendto(query, (resolver_ip, resolver_port))

client_socket.settimeout(time_out)
try:
    response, server_address = client_socket.recvfrom(2048)
    query_time = round((time.time() - start) * 1000)
except:
    print('Error: request timed out')
    sys.exit(1)

# get time taken for response to arrive
query_time = round((time.time() - start) * 1000)

# get bits for error code from header
error = response[3]
bit1, bit2, bit3, bit4 = '0', '0', '0', '0'
if (error) & 1:
    bit4 = '1'
if (error >> 1) & 1:
    bit3 = '1'
if (error >> 2) & 1:
    bit2 = '1'
if (error >> 3) & 1:
    bit1 = '1'

# if valid error code, print error
error_code = bit1 + bit2 + bit3 + bit4
#print(error_code)
if error_code == '0011':
    print(f'Error: server can\'t find {name}')
    sys.exit(1)
if error_code == '0001':
    print('Error: formatting error - name server was unable to interpret the query')
    sys.exit(1)
if error_code == '0010':
    print('Error: query could not be processed due to problem with name server')
    sys.exit(1)
if error_code == '0100':
    print('Error: code 4 - name server does not support the requested query type')
    sys.exit(1)
if error_code == '0101':
    print('Error: code 5 - Refused')
    sys.exit(1)

# get counts
res_header = response[:12]
qdcount = int.from_bytes(res_header[4:6], 'big')
ancount = int.from_bytes(res_header[6:8], 'big')
nscount = int.from_bytes(res_header[8:10], 'big')
arcount = int.from_bytes(res_header[10:12], 'big')
print(f'\nResponse ID: {response[0:2]}\nQuestion count: {qdcount}\nAnswer count: {ancount}\nAuthority count: {nscount}\nAdditional count: {arcount}')

# get aa/tc flags
flags = res_header[2]
tc = ''
aa = ''
if (flags >> 1) & 1:
    tc = ' tc'
if (flags >> 2) & 1:
    aa = ' aa'
print('Flags:' + tc + aa)

remaining_bytes = response[12:]

# get question section
qd_records = []
for res in range(qdcount):
    qname, remaining_bytes = get_name(remaining_bytes, response)
    qtype, remaining_bytes = get_int(remaining_bytes, 2)
    qclass, remaining_bytes = get_int(remaining_bytes, 2)

    record = (qtype, qname)
    qd_records.append(record)

print('\nQUESTION SECTION:')
print(f'{name}          IN      A')

# get answer section
an_records = []
for res in range(ancount):
    domain, remaining_bytes = get_name(remaining_bytes, response)
    qtype, remaining_bytes = get_int(remaining_bytes, 2)
    qclass, remaining_bytes = get_int(remaining_bytes, 2)
    ttl, remaining_bytes = get_int(remaining_bytes, 4)
    rdlength, remaining_bytes = get_int(remaining_bytes, 2)
    rdata, remaining_bytes = remaining_bytes[:rdlength], remaining_bytes[rdlength:]

    if qtype == 1:  # 'A' record
        rdata = '.'.join(str(x) for x in rdata)
    if qtype == 5:  # 'CNAME' record
        rdata, _ = get_name(rdata, response)

    record = (dns_types[qtype], dns_classes[qclass], domain, ttl, rdata)
    an_records.append(record)

print('\nANSWER SECTION:')
for record in an_records:
    print(record)

# get authority section
ns_records = []
for res in range(nscount):
    domain, remaining_bytes = get_name(remaining_bytes, response)
    qtype, remaining_bytes = get_int(remaining_bytes, 2)
    qclass, remaining_bytes = get_int(remaining_bytes, 2)
    ttl, remaining_bytes = get_int(remaining_bytes, 4)
    rdlength, remaining_bytes = get_int(remaining_bytes, 2)
    rdata, remaining_bytes = remaining_bytes[:rdlength], remaining_bytes[rdlength:]

    if qtype == 2:  # NS record
        rdata, _ = get_name(rdata, response)

    record = (dns_types[qtype], dns_classes[qclass], domain, ttl, rdata)
    ns_records.append(record)

print('\nAUTHORITY SECTION:')
for record in ns_records:
    print(record)

# get additional section
ar_records = []
for res in range(arcount):
    domain, remaining_bytes = get_name(remaining_bytes, response)
    qtype, remaining_bytes = get_int(remaining_bytes, 2)
    qclass, remaining_bytes = get_int(remaining_bytes, 2)
    ttl, remaining_bytes = get_int(remaining_bytes, 4)
    rdlength, remaining_bytes = get_int(remaining_bytes, 2)
    rdata, remaining_bytes = remaining_bytes[:rdlength], remaining_bytes[rdlength:]

    if qtype == 1:  # A record
        rdata = '.'.join(str(x) for x in rdata)
    if qtype == 28:  # skip any AAAA records
        continue

    record = (dns_types[qtype], dns_classes[qclass], domain, ttl, rdata)
    ar_records.append(record)

print('\nADDITIONAL SECTION:')
for record in ar_records:
    print(record)

print(f'\nQuery time: {query_time} ms')

# Uncomment code below for performance reporting
'''
if resolver_ip == '127.0.0.1':
    res_file = open('results_local.txt', 'a')
    res_file.write(str(query_time) + '\n')
    res_file.close()
if resolver_ip == '1.1.1.1':
    res_file = open('results_cloudflare.txt', 'a')
    res_file.write(str(query_time) + '\n')
    res_file.close()
if resolver_ip == '8.8.8.8':
    res_file = open('results_google.txt', 'a')
    res_file.write(str(query_time) + '\n')
    res_file.close()
'''

client_socket.close()
