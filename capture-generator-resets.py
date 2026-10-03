"""Export TCP reset metadata only; never save packets, payloads or raw addresses."""
import hashlib, ipaddress, json, pathlib, re, shutil, signal, subprocess, sys, threading, time

def parse_reset(line, local, run):
    match=re.search(r'^(\d+\.\d+)\s+.*?\s(\S+) > (\S+):',line)
    if not match:return None
    try:
        source,source_port=match[2].rsplit('.',1);destination,destination_port=match[3].rsplit('.',1)
        ipaddress.ip_address(source);ipaddress.ip_address(destination)
        source_port=int(source_port);destination_port=int(destination_port)
        if not all(0<n<=65535 for n in [source_port,destination_port]):return None
    except ValueError:return None
    if source in local and destination_port==443:direction='sent';peer=destination;port=source_port
    elif destination in local and source_port==443:direction='received';peer=source;port=destination_port
    else:return None
    return {'kind':'tcp_reset','epoch_seconds':float(match[1]),'direction':direction,
        'peer_ip_fingerprint':hashlib.sha256((run+'|'+peer).encode()).hexdigest(),'client_port':port}

def capture(target, run):
    if not re.fullmatch(r'\d{1,20}-\d{1,3}',run):raise ValueError('Invalid run identity')
    running=True
    def stop(*args):
        nonlocal running
        running=False
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    available=shutil.which('tcpdump') is not None;local=set()
    if available:
        for interface in json.loads(subprocess.check_output(['ip','-json','address','show'])):
            for address in interface.get('addr_info',[]):local.add(address['local'])
    with target.open('w') as output:
        output.write(json.dumps({'kind':'capture_status','available':available})+'\n');output.flush()
        if not available:return
        process=subprocess.Popen(['tcpdump','-n','-l','-tt','-q','-s','96','-i','any','tcp port 443 and (tcp[tcpflags] & tcp-rst != 0)'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        count=0
        def read():
            nonlocal count
            for line in process.stdout:
                record=parse_reset(line,local,run)
                if record is None:continue
                count+=1
                if count<=1000:output.write(json.dumps(record)+'\n');output.flush()
        thread=threading.Thread(target=read,daemon=True);thread.start()
        try:
            deadline=time.monotonic()+660
            while running and process.poll() is None and time.monotonic()<deadline:time.sleep(.2)
        finally:
            if process.poll() is None:process.terminate()
            process.wait(timeout=3);thread.join(timeout=3)
            output.write(json.dumps({'kind':'capture_final','reset_records':min(count,1000),'omitted_records':max(0,count-1000),'exit_code':process.returncode})+'\n');output.flush()

if __name__=='__main__':capture(pathlib.Path(sys.argv[1]),sys.argv[2])
