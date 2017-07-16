#!/usr/bin/env python

import json
import traceback

import websocket

SERVER = 'ws://127.0.0.1:8642'
AGENT = 'py-websockets-client'


ws = websocket.create_connection(SERVER + "/getCaseCount")
count = json.loads(ws.recv())
ws.close()


for case in range(1, count+1):
    url = SERVER + '/runCase?case={0}&agent={1}'.format(case, AGENT)
    status = websocket.STATUS_NORMAL
    try:
        ws = websocket.create_connection(url)
        while True:
            opcode, msg = ws.recv_data()
            if opcode == websocket.ABNF.OPCODE_TEXT:
                msg.decode("utf-8")
            if opcode  in (websocket.ABNF.OPCODE_TEXT, websocket.ABNF.OPCODE_BINARY):
                ws.send(msg, opcode)
    except UnicodeDecodeError:
        # this case is ok.
        status = websocket.STATUS_PROTOCOL_ERROR
    except websocket.WebSocketProtocolException:
        status = websocket.STATUS_PROTOCOL_ERROR
    except websocket.WebSocketPayloadException:
        status = websocket.STATUS_INVALID_PAYLOAD
    except Exception as e:
        # status = websocket.STATUS_PROTOCOL_ERROR
        print(traceback.format_exc())
    finally:
        ws.close(status)

print("Ran {} test cases.".format(case))
url = SERVER + '/updateReports?agent={0}'.format(AGENT)
ws = websocket.create_connection(url)
