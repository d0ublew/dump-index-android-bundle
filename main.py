#!/usr/bin/env python3
# Copyright (c) 2024 d0ublew
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# SPDX-License-Identifier: MIT


import sys
import frida
import time


def message_handler(message, data):
    print(message)
    if message["type"] == "error":
        print(message['stack'])
        return
    if message["type"] == "send":
        payload = message["payload"]
        if payload == "hbc" and data is not None:
            print("[*] saving index.android.bundle")
            with open("index.android.bundle", "wb") as f:
                f.write(data)


if len(sys.argv) != 2:
    print("Missing process name")
    quit()

with open("./dump-on-client.js") as f:
    jscode = f.read()

print("[*] Getting device")
device = frida.get_usb_device(timeout=1)
# device = frida.get_device_manager().add_remote_device("192.168.100.62:31337")

while True:
    try:
        process = device.get_process(sys.argv[1])
        break
    except KeyboardInterrupt:
        quit()
    except frida.ProcessNotFoundError:
        continue
    except frida.ServerNotRunningError as e:
        print(e)
        quit()
 
time.sleep(0.1)
session = device.attach(process.pid)
script = session.create_script(jscode)
script.on("message", message_handler)
script.load()
print("[*] Attached")

try:
    sys.stdin.read()
except BaseException:
    session.detach()
    print("\n[*] Detached successfully")
