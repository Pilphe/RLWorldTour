import hmac
import hashlib
import base64
import json
import re
import time
from mitmproxy import ctx

class PsyNet:
    def __init__(self):
        self.ws_req_secret = b"<removed>"
        self.ws_res_secret = b"<removed>"
        self.cfg_res_secret = b"<removed>"
        self.cfg_host = "config.psynet.gg"
        self.cfg = None
        self.should_load_cfg = True

        self.regions = ["USE","EU","USW","ASC","ASM","JPN","ME","OCE","SAF","SAM"]
        self.nregions = len(self.regions)

        self.schedules_set = set()
        self.schedules_msg_id = None
        self.schedules_count = self.nregions
        
        self.test_id = None

    def gen_sig(self, key, msg):
        sig = base64.b64encode(hmac.new(key, msg, hashlib.sha256).digest())
        return sig

    def gen_cfg_res_sig(self, flow):
        sig = self.gen_sig(self.cfg_res_secret, flow.response.content)
        return sig

    def gen_ws_res_sig(self, ts, body):
        sig = self.gen_sig(self.ws_res_secret, ts.encode() + b"-" + body.encode())
        return sig
    
    def gen_ws_req_sig(self, body):
        sig = self.gen_sig(self.ws_req_secret, b"-" + body.encode())
        return sig

    def get_ws_msg_id(self, headers):
        id = None
        match = re.search(r"PsyNetMessage_X_(\d+)", headers)
        if match:
            id = int(match.group(1))
        return id
        
    def get_ws_res_ts(self, headers):
        ts = None
        match = re.search(r"PsyTime: (\d+)", headers)
        if match:
            ts = match.group(1)
        return ts
    
    def replace_ws_msg_sig(self, headers, sig):
        new_headers = re.sub("PsySig: .{44}", f"PsySig: {sig.decode()}", headers, 1)
        return new_headers
        
    def replace_ws_msg_id(self, headers, id):
        new_headers = re.sub(r"PsyNetMessage_X_\d+", f"PsyNetMessage_X_{id}", headers, 1)
        return new_headers
    
    def replace_ws_res_sig(self, ts, headers, body):
        sig = self.gen_ws_res_sig(ts, body)
        new_headers = self.replace_ws_msg_sig(headers, sig)
        return new_headers
        
    def replace_ws_req_sig(self, headers, body):
        sig = self.gen_ws_req_sig(body)
        new_headers = self.replace_ws_msg_sig(headers, sig)
        return new_headers
    
    def build_schedules_res(self, headers, ts, json_body):
        schedules_res = {
            "Result": {
                "Schedules": []
            }
        }
        '''
        now = int(time.time())
        for schedule in (json.loads(s) for s in self.schedules_set):
            diff = schedule["Time"] - now
            if diff < 0 or diff > self.schedules_max_time_diff:
                continue
            for tour in schedule["Tournaments"]:
                diff = tour["StartTime"] - now
                if diff > 0 and diff < self.schedules_max_time_diff:
                    new_title = f'[{tour["Region"]}] {tour["Title"]}'
                    tour["Title"] = new_title
                else:
                    del tour
            schedules_res["Responses"][0]["Result"]["Schedules"].append(schedule)
        '''
        for schedule in (json.loads(s) for s in self.schedules_set):
            for tour in schedule["Tournaments"]:
                new_title = f'[{tour["Region"]}] {tour["Title"]}'
                tour["Title"] = new_title
            schedules_res["Result"]["Schedules"].append(schedule)

        body = json.dumps(schedules_res, separators=(',', ':'))
        new_headers = self.replace_ws_res_sig(ts, headers, body)
        msg = f"{new_headers}\r\n\r\n{body}"
        return msg
    
    def retrieve_all_schedules(self, flow, headers, json_body):
        regions = [region for region in self.regions if region != json_body["Region"]]
        for region in regions:
            json_body["Region"] = region
            new_body = json.dumps(json_body, separators=(',', ':'))
            new_headers = self.replace_ws_req_sig(headers, new_body)
            msg = f"{new_headers}\r\n\r\n{new_body}"
            ctx.master.commands.call("inject.websocket", flow, False, msg.encode())
    
    def handle_schedules_res(self, message, id, headers, ts, json_body, flow):
        print(f"Got schedules response, id: {id}")
        message.drop()
        for schedule in json_body["Result"]["Schedules"]:
            self.schedules_set.add(json.dumps(schedule, separators=(',', ':')))
        self.schedules_count = self.schedules_count - 1
        if self.schedules_count == 0:
            msg = self.build_schedules_res(headers, ts, json_body)
            ctx.master.commands.call("inject.websocket", flow, True, msg.encode())
            self.schedules_set.clear()
            self.schedules_msg_id = None
            self.schedules_count = self.nregions
    
    def handle_schedules_req(self, message, flow, id, headers, json_body):
        if self.schedules_msg_id is None:
            print(f"Got schedules request, id: {id}")
            self.schedules_msg_id = id
            self.schedules_count = self.nregions
            self.retrieve_all_schedules(flow, headers, json_body)
        elif id != self.schedules_msg_id:
            message.drop()
            print(f"WARNING got another schedules request during retrieving, id: {id}, dropped.")
    
    def edit_cfg_res(self, flow):
        self.cfg["RetryConfig"]["RetryDelays"][0]["DelaySeconds"] = [5]
        flow.response.text = json.dumps(self.cfg)
        flow.response.headers["Psysignature"] = self.gen_cfg_res_sig(flow)
    
    def handle_cfg_req(self, flow):
        if self.should_load_cfg:
            if "If-None-Match" in flow.request.headers:
                del flow.request.headers["If-None-Match"]
            self.should_load_cfg = False

    def handle_cfg_res(self, flow):
        if flow.response.status_code == 200:
            self.cfg = flow.response.json()
            self.edit_cfg_res(flow)
            print("Remote configuration file loaded.")
        elif flow.response.status_code == 304:
            print("Remote configuration file unmodified, using cache.")
        else:
            print(f"Error while retrieving remote configuration file (HTTP status code: {flow.response.status_code}).")
    
    def request(self, flow):
        if flow.request.headers["Host"] == self.cfg_host:
            self.handle_cfg_req(flow)

    def response(self, flow):
        if flow.request.headers["Host"] == self.cfg_host:
            self.handle_cfg_res(flow)

    def decode_party_message(self, msg):
        pmsg = base64.b64decode(msg)
        classname_len = int.from_bytes(pmsg[:4], "big")
        classname = pmsg[4:(4 + classname_len)].decode()
        payload = pmsg[(4 + classname_len + 1):].decode()
        return pmsg, classname_len, classname, payload

    def websocket_message(self, flow):
        assert flow.websocket is not None
        message = flow.websocket.messages[-1]
        try:
            headers, body = message.text.split("\r\n\r\n", 1)
        except ValueError:
            print("MESSAGE ERROR: DROP")
            message.drop()
            return
        id = self.get_ws_msg_id(headers)
        if not message.from_client:
            ts = self.get_ws_res_ts(headers)

        if id is not None:
            json_body = json.loads(body)

            if message.from_client and "PsyService" in headers:
                if "Tournaments/Search/GetSchedule v1" in headers:
                    self.handle_schedules_req(message, flow, id, headers, json_body)
                elif "Metrics" in headers:
                    message.drop()
            
            elif not message.from_client and "Result" in json_body:
                if id == self.schedules_msg_id:
                    self.handle_schedules_res(message, id, headers, ts, json_body, flow)

addons = [
    PsyNet()
]

