#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022-2023 ImmortalWrt.org

NAME="homeproxy"

log_max_size="50" #KB
main_log_file="/var/run/$NAME/$NAME.log"
hiddifyc_log_file="/var/run/$NAME/hiddify-c.log"

while true; do
	sleep 180
	for i in "$main_log_file" "$hiddifyc_log_file"; do
		[ -s "$i" ] || continue
		# F10.2: keep the newest tail instead of wiping the file — diagnostics
		# must survive exactly on a busy box, where the cap is hit most often.
		[ "$(( $(ls -l "$i" | awk -F ' ' '{print $5}') / 1024 >= log_max_size))" -eq "0" ] || { tail -n 100 "$i" > "$i.t" 2>/dev/null && mv -f "$i.t" "$i"; }
	done
done
