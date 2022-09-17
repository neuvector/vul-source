#!/bin/bash
set -e
GRAPHING=/home/ubuntu-security/graphing
HTML=/home/ubuntu-security/public_html
ARCHIVE=/srv/archive.ubuntu.com/ubuntu
REVIEWED=/home/ubuntu-security/reviewed
export UCT=/home/ubuntu-security/git-pulls/cve-tracker

REL=cosmic  # set to last column in templates (ie, the devel release)
RELTAG="18.10"  # set to version of $REL, e.g. 18.10
INDEX=28

cd $GRAPHING

# Update CSS
ln -sf $HTML/cve/toplevel.css $HTML/graphs/toplevel.css

# Generate supported binary package counts data for the devel release
COUNT=$(zgrep ^Package: $ARCHIVE/dists/$REL/{main,restricted}/binary-i386/Packages.gz | wc -l)
echo "$REL $INDEX $COUNT" > $REL.data

cat supported.data.template > supported.data
LAST=$(tail -n1 supported.data.template | cut -c2-)
echo $LAST $COUNT >> supported.data

# Generate supported source package counts data for the devel release
COUNT=$(zgrep ^Package: $ARCHIVE/dists/$REL/{main,restricted}/source/Sources.gz | wc -l)
echo "$REL $INDEX $COUNT" > ${REL}-src.data

cat supported-src.data.template > supported-src.data
LAST=$(tail -n1 supported-src.data.template | cut -c2-)
echo $LAST $COUNT >> supported-src.data

# Plot historical package counts
./plot.py | gnuplot

# Plot supported packages
PLOTLINE=$(echo -n " '' using 3"
for i in $(seq 4 $(( $INDEX + 2 )) ); do
	echo -n ", '' using $i"
done)
perl -pe 's/^(plot .*)/$1 '"$PLOTLINE"'/g' < supported.plot.template | gnuplot

# Publish!
cp packages.png sources.png supported.png supported-src.png $HTML/graphs/


# Open CVEs
NOW=$(date +'%Y-%m-%d')
CURRENT=$(echo -n "$NOW "; cd $REVIEWED; ./scripts/report-todo-plot -S)
cp CVE.data.template CVE.data
if [ $(date +%a) = "Sun" ] && ! grep -q ^"$NOW" CVE.data.template; then
    # Save weekly information as a snapshot
    echo "$CURRENT" >> CVE.data.template
fi
echo "$CURRENT" >> CVE.data
gnuplot < open-cves.plot
gnuplot < open-cves-all.plot

XSTART=$(date -d "6 months ago" +%Y-%m-%d)
perl -p -e "s/^set xrange.*/set xrange [\"$XSTART\":]/;" open-cves-6mon.plot.template > open-cves-6mon.plot
perl -p -e "s/^set xrange.*/set xrange [\"$XSTART\":]/;" open-cves-all-6mon.plot.template > open-cves-all-6mon.plot
gnuplot < open-cves-6mon.plot
gnuplot < open-cves-all-6mon.plot

# Publish!
cp open-cves*.png $HTML/cve/


# Raw published USN counts
XSTART=$(date -d "6 months ago" +%Y-%m)
perl -p -e "s/^set xrange.*/set xrange [\"$XSTART\":]/;" usns-6mon.plot.template > usns-6mon.plot
~/bin/usn.sh --db $HTML/usn/database.pickle --list-graph > USN.data
head -n -1 USN.data > USN.data.truncated
gnuplot < usns.plot
gnuplot < usns-6mon.plot
# Publish!
cp usns.png usns-6mon.png $HTML/graphs/
USNCOUNT=$(tail -n 1 USN.data| cut -f2 -d" ")


# Published CVE counts/priorities
perl -p -e "s/^set xrange.*/set xrange [\"$XSTART\":]/;" cve-updates-6mon.plot.template > cve-updates-6mon.plot
(cd $REVIEWED && ./scripts/plot-usns.py --target cve) > cve-updates.data
head -n -1 cve-updates.data > cve-updates.data.truncated
gnuplot < cve-updates.plot
gnuplot < cve-updates-6mon.plot
# Publish!
cp cve-updates.png cve-updates-6mon.png $HTML/graphs/


# Published USN counts with release multiplier
# http://latex.codecogs.com/gif.latex?\sum_{u=firstUSNofMonth}^{lastUSNofMonth}releases%28u%29*cves%28u%29
perl -p -e "s/^set xrange.*/set xrange [\"$XSTART\":]/;" usn-updates-6mon.plot.template > usn-updates-6mon.plot
(cd $REVIEWED && ./scripts/plot-usns.py --target usn --cve-multiply --release-multiply) > usn-updates.data
head -n -1 usn-updates.data > usn-updates.data.truncated
gnuplot < usn-updates.plot
gnuplot < usn-updates-6mon.plot
# Publish!
cp usn-updates.png usn-updates-6mon.png $HTML/graphs/


# Exposure calculations
for REL in $(./supported-list.py)
do
	perl -p -e "s/^set title.*/set title \"Exposure to Open CVEs ($REL)\"/" exposure.plot.template > exposure.plot
	(cd $REVIEWED; ./scripts/report-cve-age.py --action plot --priority critical,high,medium --buckets 0,1,2,3,4,5,6,7,14,30,60,-1 --html $GRAPHING/exposure-$REL.html $REL) > exposure-$REL.data
	cp exposure-$REL.data exposure.data
    # new release outputs this error, so suppress it
    tmp=`mktemp -t ubuntu-security-XXXXXX`
	if ! gnuplot > "$tmp" 2>&1 < exposure.plot ; then
        cat "$tmp"
    fi
    rm -f "$tmp"
	cp exposure.png $HTML/graphs/exposure-$REL.png
	cp exposure-$REL.html $HTML/graphs/exposure-$REL.html
done
perl -p -e "s/^set title.*/set title \"Exposure to Open CVEs (all)\"/" exposure.plot.template > exposure.plot
(cd $REVIEWED; ./scripts/report-cve-age.py --action plot --priority critical,high,medium --buckets 0,1,2,3,4,5,6,7,14,30,60,-1 --html $GRAPHING/exposure-all.html ) > exposure.data
gnuplot < exposure.plot
cp exposure.png $HTML/graphs/exposure-all.png
cp exposure-all.html $HTML/graphs/exposure-all.html


# Affected software counts
./pkgs-update.sh

