#!/usr/bin/python3
import os
import random
os.system("cp Client.py Temp.txt")
with open("Temp.txt", "r") as in_file:
    buf = in_file.readlines()

with open("Temp.txt", "w") as out_file:
    for line in buf:
        if line == "import os\n":
            line = line + "\nimport random\n"
        if line == "                SPN190_value.append(spn190)\n":
            #print(line)
            line = line + "\n                zulu = random.uniform(0,1)\n                titter = random.uniform(0,1)\n                if zulu > 0.96:\n                    if titter > 0.3:\n                        spn190 = spn190 - (zulu-0.3) * 100\n                    else:\n                        spn190 = spn190 + (zulu-0.3) * 100\n"
        out_file.write(line)
os.system("mv Temp.txt Client.py")