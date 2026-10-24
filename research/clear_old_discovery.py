"""Clear stale retained Home Assistant MQTT discovery messages for the old
channel slugs (renamed to impuls/partial/open/close/ventilation). Publishing
an empty retained payload to a discovery config topic removes that entity
from Home Assistant.
Reads broker host/user/password from the local-only wifi_mqtt.txt file
without printing them.
"""
import paho.mqtt.client as mqtt

WIFI_FILE = r"C:\Users\serge\HoermannBLE\secret\wifi_mqtt.txt"

kv = {}
with open(WIFI_FILE, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        kv[k.strip()] = v.strip()

host = kv["MQTT_HOST"]
port = int(kv.get("MQTT_PORT") or 1883)
user = kv.get("MQTT_USER") or None
password = kv.get("MQTT_PASSWORD") or None

old_slugs = ["channel1", "channel3", "channel4", "channel5", "channel6"]
topics = [f"homeassistant/button/hoermann_gate_{slug}/config" for slug in old_slugs]

client = mqtt.Client()
if user:
    client.username_pw_set(user, password)
client.connect(host, port, keepalive=10)
client.loop_start()

for t in topics:
    client.publish(t, payload=b"", qos=1, retain=True)
    print(f"cleared: {t}")

import time
time.sleep(1)
client.loop_stop()
client.disconnect()
print("done")
