# CODE USES PYTHON 3
from socket import *
import sys
import _thread

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
        else:  # otherwise, label is a normal name (no pointer)
            ln, remaining_bytes = get_int(remaining_bytes, 1)
            label, remaining_bytes = remaining_bytes[:ln], remaining_bytes[ln:]
            if len(label) == 0:
                break
            name_parts.append(label.decode())
    return '.'.join(name_parts), remaining_bytes # returns string result, and remaining bytes left after parsing that result

# create a new query (used when answer only includes CNAME)
def create_query(domain_name, query_id):
    header = query_id + b'\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    qname = b''.join(bytes([len(part)]) + part.encode() for part in domain_name.split('.'))
    qtype = int.to_bytes(1, length = 2, byteorder = 'big')
    qclass = b'\x00\x01'
    query = header + qname + b'\x00' + qtype + qclass
    return query

# get answer for query, and send back to client
def get_answer(client_query, client_address):
        question_bytes = client_query[12:]
        name, question_bytes = get_name(question_bytes, client_query)

        query_socket = socket(AF_INET, SOCK_DGRAM)
        query = client_query
        next_query = root_a[0]

        while True:
            query_socket.sendto(query, (next_query, 53))

            query_socket.settimeout(time_out)
            try:
                response, server_address = query_socket.recvfrom(2048)
            except:
                print(f'{name} - Error: request timed out')
                sys.exit(1)

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

            # get error code
            error_code = bit1 + bit2 + bit3 + bit4
            if error_code != '0000':
                print(f'{name} - Error code found: forwarding to client')
                server_socket.sendto(response, client_address)
                break

            res_header = response[:12]
            qdcount = int.from_bytes(res_header[4:6], 'big')
            ancount = int.from_bytes(res_header[6:8], 'big')
            nscount = int.from_bytes(res_header[8:10], 'big')
            arcount = int.from_bytes(res_header[10:12], 'big')

            remaining_bytes = response[12:]


            # get question section
            qd_records = []
            for res in range(qdcount):
                qname, remaining_bytes = get_name(remaining_bytes, response)
                qtype, remaining_bytes = get_int(remaining_bytes, 2)
                qclass, remaining_bytes = get_int(remaining_bytes, 2)

                record = (qtype, qname)
                qd_records.append(record)


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

                record = (qtype, domain, ttl, rdata)
                an_records.append(record)


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

                record = (qtype, domain, ttl, rdata)
                ns_records.append(record)


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

                record = (qtype, domain, ttl, rdata)
                ar_records.append(record)


            # decide what to do for next query
            if query == client_query: # querying for original domain name
                if ancount != 0: # if answer section has results
                    exit_flag = False
                    for record in an_records:
                        if record[0] == 1:
                            print(f'{name} - ANSWER FOUND!')
                            server_socket.sendto(response, client_address)
                            exit_flag = True
                            break
                    if exit_flag: # found an 'A' answer, so exit loop
                        break
                    else: # answer section only had 'CNAME' answer, so query that instead
                        client_query = create_query(an_records[0][3], client_query[:2])
                        query = client_query
                        next_query = root_a[0]
                        continue
                elif arcount == 0: # if additional section is empty
                    query = create_query(ns_records[0][3], client_query[:2])
                    continue
                elif arcount != 0: # if additional section has results
                    next_query = ar_records[0][3]

            if query != client_query: # querying a different domain from the one sent by the client
                next_query = ar_records[0][3]
                query = client_query



if __name__ == "__main__":
    try:
        port = int(sys.argv[1])
        time_out = int(sys.argv[2])
    except:
        print('Error: invalid arguments\nUsage: resolver port timeout')
        sys.exit(1)

    root_ns = [] #root nameservers
    root_a = []  #root ip addresses
    with open('named.root') as file:
        for line in file:
            if line[0] == ';' or line[38:42] == 'AAAA':
                continue
            if line[38:40] == 'NS':
                root_ns.append(line[44:].strip())
            if line[38] == 'A':
                root_a.append(line[44:].strip())


    server_socket = socket(AF_INET, SOCK_DGRAM)
    server_socket.bind(('localhost', port))
    print('The server is ready to receive')

    while True:
        client_query, client_address = server_socket.recvfrom(2048)
        _thread.start_new_thread(get_answer, (client_query, client_address))
