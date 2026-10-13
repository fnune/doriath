#!/bin/sh
# threat: run threads, subprocesses and /tmp files
# expect: works

echo ok > /tmp/control && [ "$(cat /tmp/control)" = ok ] || exit 1
python3 -c 'import threading, subprocess; t = threading.Thread(target=lambda: None); t.start(); t.join(); subprocess.run(["true"], check=True)' || exit 1
