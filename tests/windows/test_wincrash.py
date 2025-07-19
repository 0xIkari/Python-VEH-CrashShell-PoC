import subprocess
import os
import time
import sys

def test_crashhandler_wipes_memory():
    log_path = "crashhandler.log"
    dump_path = "dump.bin"
    real_path = "real.bin"
    for path in [log_path, dump_path, real_path]:
        if os.path.exists(path):
            os.remove(path)

    result = subprocess.run(
        [sys.executable, "tests/windows/crasher.py"], 
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    print("STDOUT:", result.stdout.decode())
    print("STDERR:", result.stderr.decode())

    assert result.returncode != 0, "Expected crash did not occur"

    # Give time for flush
    time.sleep(0.5)
    assert os.path.exists(log_path), "Crashhandler log not found"
    with open(log_path, "r") as f:
        contents = f.read()
    assert "MEMORY WIPED" in contents, "Crashhandler did not wipe memory"
