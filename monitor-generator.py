import datetime, json, os, pathlib, signal, sys, time

running = True
def stop(*args):
    global running
    running = False
signal.signal(signal.SIGTERM, stop)
target = pathlib.Path(sys.argv[1])
with target.open('w') as output:
    while running:
        processes = []
        for proc in pathlib.Path('/proc').iterdir():
            if not proc.name.isdigit(): continue
            try:
                if (proc / 'comm').read_text().strip() != 'k6': continue
                fields = (proc / 'stat').read_text().split()
                status = (proc / 'status').read_text().splitlines()
                rss = next(int(s.split()[1]) for s in status if s.startswith('VmRSS:'))
                processes.append({'pid': int(proc.name), 'cpu_ticks': int(fields[13]) + int(fields[14]),
                    'rss_kib': rss, 'open_fds': len(list((proc / 'fd').iterdir()))})
            except (OSError, ValueError, StopIteration): continue
        tcp = {}
        for file in ['/proc/net/tcp', '/proc/net/tcp6']:
            for line in pathlib.Path(file).read_text().splitlines()[1:]:
                state = line.split()[3]; tcp[state] = tcp.get(state, 0) + 1
        row = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'cpu_count': os.cpu_count(),
            'clock_ticks': os.sysconf('SC_CLK_TCK'), 'load': os.getloadavg(), 'k6': processes, 'tcp_states': tcp}
        output.write(json.dumps(row) + '\n'); output.flush()
        for _ in range(15):
            if not running: break
            time.sleep(1)
