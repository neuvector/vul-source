# These utility functions are useful functions for dealing with the
# ubuntu-cve-tracker.

# To use this from dash or bash, do '. dot.usn-functions.sh' or copy it
# to your home directory as ~/.usn-functions.sh and add
# '.  .usn-functions.sh' to your .bashrc

# These functions should work regardless if your shell is dash or bash.


# This function generates a commit message suitable for use when
# committing the result of a cve triage run. It assumes that all the
# triage changes have been added to the git index already. Can be used
# directly or as part of a commit command like
# 'git commit _em $(uct_process_cves_commit_message)'
#
# It can also be passed a specific git commit hash, like so:
#
#   $ uct_process_cves_commit_message db3a2d63e6
#   Process cves run: triaged 3 CVEs, 9 Ignored, 3 Packages
#
#   Packages with new cves:
#     dwarfutils(1) mgetty(1) nasm(1)
#

uct_process_cves_commit_message ()
{
    local _GIT_COMMAND="git diff --cached HEAD"
    if [ -n "$1" ]; then
        _GIT_COMMAND="git show $1"
    fi;
    ${_GIT_COMMAND} | gawk '
        BEGIN { cve = ignored = 0 }
	/^\+Candidate:/ { cve++ }
	/^\+Patches_linux:/ { packages["linux"]++ }
	/^\+Patches_/ { name=substr($1, 10, length($1)-10) ;
	    if (name !~ /linux/) { packages[name]++ } }
	/^\+CVE/ { ignored++ }
	END {
	      print "Process cves run: triaged", cve, "CVEs,", ignored, "Ignored,", length(packages), "Packages" ;
	      printf("\nPackages with new cves:\n  ");
	      n = asorti(packages, sorted_packages)
	      for (i = 1; i <= n; i++) {
	        printf("%s(%d) ", sorted_packages[i], packages[sorted_packages[i]])
	      }
	      print "";
	 } ' | fmt -w78
}

# Simple helper function to setup a remote for the kernel team's UCT
# triage tree.
uct_kernel_tree_setup_remote ()
{
    local _URL_PREFIX="https://git.launchpad.net/"
    if (git config --get-regexp 'url\.git\+ssh://.*@git.launchpad.net/?.insteadof$'  | grep -q " lp:$") ; then
        _URL_PREFIX="lp:"
    fi

    if ! (git remote  | grep -q '^kernel-team$') ; then
        git remote add kernel-team "${_URL_PREFIX}~canonical-kernel-team/ubuntu-cve-tracker"
	git fetch -v -t kernel-team
    fi
}

# Simple helper function to merge UCT kernel changes from the kernel
# team. Assumes uct_kernel_tree_setup_remote has already been run
uct_kernel_merge_commit ()
{
    merge_branch="${1:-kernel-team/master}"

    git merge --no-ff --signoff -m 'merge cve updates from kernel team' "$merge_branch"
}
