#!/bin/bash
set -e
export UCT=/home/ubuntu-security/git-pulls/cve-tracker
REVIEWED=/home/ubuntu-security/reviewed

cd /home/ubuntu-security/graphing

# Affected software counts
export NAMED=10
echo '<html><head><title>CVE counts per release per package</title></head><body>' > ~/public_html/graphs/pkgs-report.html.new
for REL in $(./supported-list.py | tac) ; do
	export REL

	SPECIFIC=$( (cd "$REVIEWED" && ./scripts/report-packages.py --action plot $REL) | sort -n -k 8 | awk '{print $1 " " $8}' | tail -n $NAMED)
	if [ -n "$SPECIFIC" ]; then
		OTHERS=$( (cd "$REVIEWED" && ./scripts/report-packages.py --action plot $REL) | sort -n -k 8 | head -n -$NAMED | awk '{ sum+=$8 }END{print sum}' )
		export SPECIFIC
		export OTHERS

		(
		echo "$SPECIFIC"
		if [ -n "$OTHERS" ]; then
			echo "others $OTHERS"
		fi
		) | "$REVIEWED"/scripts/pie-chart.py pkgs-$REL.png "$REL CVE fixes published per package"

		echo '<img src="'pkgs-$REL.png'" /><hr />' >> ~/public_html/graphs/pkgs-report.html.new
		cp pkgs-$REL.png ~/public_html/graphs/
	fi
done
echo '</body></html>' >> ~/public_html/graphs/pkgs-report.html.new
mv ~/public_html/graphs/pkgs-report.html.new ~/public_html/graphs/pkgs-report.html
