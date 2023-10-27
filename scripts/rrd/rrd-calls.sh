#!/bin/bash

# Nový název RRD souboru
RRD_FILE="/var/spool/voipmonitor/rrd/3db-callscounter.rrd"
DATA_FILE="/tmp/rrd_calls_data.txt"

# Časový rozsah zůstává stejný
START_TIME="now-2days"
END_TIME="now"

# Získání dat z RRD s použitím datasourci "inv"
rrdtool fetch $RRD_FILE MAX --start "$START_TIME" --end "$END_TIME" | awk '/:/ { gsub(":", "", $1); if ($2 != "-nan") print $1, $2 }' > $DATA_FILE

WIDTH=$(tput cols)
HEIGHT=$(tput lines)

# Vypočet rozsahu dat pro y-osu
max_y=$(awk 'NR>1 {if ($2>maxval) maxval=$2} END {print maxval}' $DATA_FILE)

# Získejte seznam všech dnů v souboru $DATA_FILE
DAYS=$(awk '{print strftime("%Y-%m-%d", $1)}' $DATA_FILE | sort -u | tr '\n' ' ')

gnuplot <<EOF
set ytics 50000
set terminal dumb size $WIDTH,25
set terminal dumb $WIDTH,$HEIGHT
set title "Max values from RRD for callscounter"

# Nastavení ytics pro zobrazení oddělovačů tisíců
set ytics nomirror scale 0,0.5
do for [i=0:$max_y/6:$max_y] {
    set ytics add (sprintf("%'.0f", i) i)
}

# Nastavení xtics pro zobrazení data a času
set xdata time
set timefmt "%s"
set format x "%Y-%m-%d %H:%M"
set xtics rotate by -45

# Vykreslení vertikálních čar pro každý den
days_list = "$DAYS"
do for [i=1:words(days_list)] {
    day = word(days_list, i)
    day_start = strptime("%Y-%m-%d", day)
    set arrow from day_start, graph 0 to day_start, graph 1 nohead linetype -1
}

plot "$DATA_FILE" using 1:2 with lines title "inv"
EOF

