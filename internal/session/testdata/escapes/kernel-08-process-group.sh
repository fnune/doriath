#!/bin/sh
# threat: signal doriath's own processes through the process group that the jail shares with them (kill 0)
# expect: held

pgrp=$(awk '{print $5}' /proc/self/stat)
[ "$pgrp" = 0 ] && { echo "ESCAPED: the agent's process group lies outside the jail, so kill 0 reaches doriath"; exit 1; }
exit 0
