#!/bin/bash

runner=$HOME/git/testing/build.sh

for a in arm64 x86; do
	for c in allnoconfig defconfig; do
		$runner -a $a -c $c -f
	done
done
