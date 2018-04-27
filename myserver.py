#! /lusr/bin/python

# ap45485
# CS 356 - Lam
# Lab 1 - Exercise 1 - Server

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

# Database
with open("db.txt") as f:
    db = f.readlines()
db = [x.strip().split("\t") for x in db]
db = [(eval(x[0]), eval(x[1])) for x in db]
db_dict = dict(db)

# SUT server socket information
SUT_ip = socket.gethostbyname(socket.gethostname())
SUT_port = 13579
SUT_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
SUT_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
SUT_sock.bind(("", SUT_port))

# Listen for messages
print ""
while True:
    print "\nServer (" + SUT_ip + "-" + str(SUT_port) + ") ready to listen...\n"
    request = bytearray()
    recv_time = datetime.datetime.now()
    server_msg, server_addr = SUT_sock.recvfrom(128)
    request.extend(server_msg)
    if len(request) == 16:
        # Parse information from request
        req_msg_type = request[0] >> 7
        req_flag = (request[0] & 0b01000000) >> 6
        req_low14 = ((request[0] << 8) + request[1]) & 0b0011111111111111
        req_lab_num = request[2]
        req_ver = request[3]
        req_cookie = (request[4] << 24) + (request[5] << 16) + (request[6] << 8) + request[7]
        req_data = (request[8] << 24) + (request[9] << 16) + (request[10] << 8) + request[11]
        req_result = (request[14] << 8) + request[15]
        invalid_flag = 0
        print "\n[CS356 Server -> SUT] Type " + str(req_msg_type) + " Request - " + str(recv_time) + " UTC"
        for i in range(0, 16, 4):
            print "[" + str(i) + "-" + str(i+3) + "]\t" + format(request[i], "02x") + "\t" + format(request[i + 1], "02x") + "\t" + format(request[i + 2], "02x") + "\t" + format(request[i + 3], "02x")
        print ""
        try:
            resp_result = db_dict[req_data]
        except KeyError:
            invalid_flag = 1
        # Calculate checksum
        req_checksum = 0
        for i in range(0, 16, 2):
            e = (request[i] << 8) + request[i + 1]
            req_checksum = onesCompAddition(req_checksum, e)
        # Check for errors
        if req_checksum != 0xFFFF:
            resp_result = (1 << 15) + 1
        elif req_msg_type != 0 or req_flag != 0 or req_low14 != 356 or req_lab_num != 1 or req_ver != 7:
            resp_result = (1 << 15) + 2
        elif invalid_flag == 1:
            resp_result = (1 << 15) + 4
        # Construct response with new checksum
        msg_check = bytearray()
        response = bytearray()
        resp_checksum = 0
        msg_check.extend(struct.pack("!IIIHH", 0b01000001011001000000000100000111, req_cookie, req_data, 0, resp_result))
        for i in range(0, 16, 2):
            e = (msg_check[i] << 8) + msg_check[i + 1]
            resp_checksum = onesCompAddition(resp_checksum, e)
        resp_checksum = onesComp16bit(resp_checksum)
        response.extend(struct.pack("!IIIHH", 0b01000001011001000000000100000111, req_cookie, req_data, resp_checksum, resp_result))
        # Send message
        SUT_sock.sendto(response, server_addr)
        send_time = datetime.datetime.now()
        print "\n[SUT -> CS356 Server] Type " + str(req_msg_type) + " Response - " + str(send_time) + " UTC"
        for i in range(0, 16, 4):
            print "[" + str(i) + "-" + str(i+3) + "]\t" + format(response[i], "02x") + "\t" + format(response[i + 1], "02x") + "\t" + format(response[i + 2], "02x") + "\t" + format(response[i + 3], "02x")
        print ""
