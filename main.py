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
            filename = f"index.android.bundle_{int(time.time())}"
            print(f"[*] Saving index.android.bundle to {filename}")
            with open(filename, "wb") as f:
                f.write(data)
            print("[*] index.android.bundle is successfully saved")


def usage():
    print(f"Usage: {sys.argv[0]} spawn  <package name>")
    print(f"       {sys.argv[0]} attach <process name>")
    quit()


if len(sys.argv) != 3 or sys.argv[1] not in ["spawn", "attach"]:
    usage()

with open("./dump-on-client.js") as f:
    jscode = f.read()

print("[*] Getting the android device")
# device = frida.get_usb_device(timeout=1)
device = frida.get_device_manager().add_remote_device("192.168.0.100:31337")

session = None

if sys.argv[1] == "attach":
    print(f"[*] Waiting for the process `{sys.argv[2]}` to be spawned by the user manually")

    while True:
        try:
            process = device.get_process(sys.argv[2])
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
    print("[*] Script loaded successfully")

elif sys.argv[1] == "spawn":
    print(f"[*] Spawning {sys.argv[2]} application")
    pid = device.spawn([sys.argv[2]])
    print(f"[*] Application spawned successfully (pid={pid})")
    session = device.attach(pid)
    print(f"[*] Attached to process (pid={pid})")
    script = session.create_script(jscode)
    script.on("message", message_handler)
    script.load()
    print("[*] Script loaded successfully")
    device.resume(pid)

try:
    sys.stdin.read()
except BaseException:
    session.detach()
    print("\n[*] Detached successfully")
