#! /lusr/bin/python

# ap45485
# CS 356 - Lam
# Lab 1 - Exercise 0 - Client interaction with Normal Server

import sys
import socket
import struct
import array
import random
import datetime

# Ones complement addition
def onesCompAddition(n1, n2):
    result = n1 + n2
    return result if result < (1 << 16) else (result + 1) % (1 << 16)

# Ones complement of a 16-bit value
def onesComp16bit(num):
    return num ^ 0xFFFF

# Server socket information
server_ip = "128.83.144.56"
server_port = 35605

# Create client socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Initial message information
req_header = 0b00000001011001000000000100000111
client_cookie = random.randint(0, 0xFFFF)
print ""
while True:
    req_data = input("Please enter a valid Social Security Number (9-digits): ")
    if len(str(req_data)) != 9:
        print "\nERROR: Not a valid Social Security Number\n"
    else:
        print "\nSUCCESS: Social Security Number is " + str(req_data) + ", retrieving P.O. box number...\n"
        break
req_checksum = 0
req_result = 0

# Calculate Checksum
msg_check = bytearray()
msg_check.extend(struct.pack("!IIIHH", req_header, client_cookie, req_data, req_checksum, req_result))
for i in range(0, 16, 2):
    e = (msg_check[i] << 8) + msg_check[i + 1]
    req_checksum = onesCompAddition(req_checksum, e)
req_checksum = onesComp16bit(req_checksum)

# Construct request message
req_msg = bytearray()
req_msg.extend(struct.pack("!IIIHH", req_header, client_cookie, req_data, req_checksum, req_result))

# Set timeout of 10 seconds then send message and receive response, 5 attempts
attempt = 1
while attempt <= 5:
    response = bytearray()
    sock.settimeout(5.0)
    try:
        send_time = datetime.datetime.now()
        sock.sendto(req_msg, (server_ip, server_port))
        recv_time = datetime.datetime.now()
        resp_msg, server_addr = sock.recvfrom(128)
        response.extend(resp_msg)
        if (len(response) == 16):
            break
    except socket.timeout:
        if attempt == 5:
            sys.exit("ERROR: 5 timeouts, exiting...\n")
        print "Attempt " + str(attempt) + " unsuccessful, reattempting to retrieve P.O. box number...\n"
    attempt += 1
print "Attempt " + str(attempt) + " successful\n"

# Output request data
print "[Client -> CS356 Server] Request - " + str(send_time) + " UTC"
for i in range(0, 16, 4):
    print "[" + str(i) + "-" + str(i+3) + "]\t" + format(req_msg[i], "02x") + "\t" + format(req_msg[i + 1], "02x") + "\t" + format(req_msg[i + 2], "02x") + "\t" + format(req_msg[i + 3], "02x")

# Parse information from server response
resp_msg_type = response[0] >> 7
resp_flag = (response[0] & 0b01000000) >> 6
resp_low14 = ((response[0] << 8) + response[1]) & 0b0011111111111111
resp_lab_num = response[2]
resp_ver = response[3]
resp_cookie = (response[4] << 24) + (response[5] << 16) + (response[6] << 8) + response[7]
resp_data = (response[8] << 24) + (response[9] << 16) + (response[10] << 8) + response[11]
resp_result = (response[14] << 8) + response[15]
outcome_bit = resp_result >> 15
outcome_data = resp_result & 0b0111111111111111

# Output response data
print "\n[CS356 -> Client] Type " + str(resp_msg_type) + " Response - " + str(recv_time) + " UTC"
for i in range(0, 16, 4):
    print "[" + str(i) + "-" + str(i+3) + "]\t" + format(response[i], "02x") + "\t" + format(response[i + 1], "02x") + "\t" + format(response[i + 2], "02x") + "\t" + format(response[i + 3], "02x")
print ""

# Calculate Checksum
resp_checksum = 0
for i in range(0, 16, 2):
    e = (response[i] << 8) + response[i + 1]
    resp_checksum = onesCompAddition(resp_checksum, e)

# Close socket
sock.close()

# Check for errors
if outcome_bit == 1:
    if outcome_data == 1 or resp_checksum != 0xFFFF:
        sys.exit("CHECKSUM ERROR: exiting...\n")
    if outcome_data == 2:
        if resp_msg_type != 0:
            sys.exit("SYNTAX ERROR: Incorrect message type, exiting...\n")
        if resp_flag != 1:
            sys.exit("SYNTAX ERROR: Incorrect response/request flag, exiting...\n")
        if resp_low14 != 356:
            sys.exit("SYNTAX ERROR: Low-order 14 bits of first two bytes has incorrect value, exiting...\n")
        if resp_lab_num != 1:
            sys.exit("SYNTAX ERROR: Incorrect lab number, exiting...\n")
        if resp_ver != 7:
            sys.exit("SYNTAX ERROR: Incorrect version number, exiting...\n")
        if resp_cookie != client_cookie:
            sys.exit("SYNTAX ERROR: Incorrect cookie value, exiting...\n")
        if resp_data != req_data:
            sys.exit("SYNTAX ERROR: SSN does not match SSN in request, exiting...\n")
    if outcome_data == 4:
        sys.exit("ERROR: Unknown Social Security Number (" + str(resp_data) + "), exiting...\n")
    if outcome_data == 5:
        sys.exit("SERVER ERROR: exiting...\n")
else:
    print "P.O. Box Number: " + str(outcome_data) + "\n"
