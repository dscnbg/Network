import json

f = open('C:/Temp/Git/Forcepoint/barracuda-large.txt', 'r')

content = f.read()
content = content.replace("\t", "")
content = content.replace("\n", "")

data = json.dumps(content)
print(data)
f.close()