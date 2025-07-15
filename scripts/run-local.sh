#!/usr/bin/bash
#
# script to run a locally built stalld for testing/debugging
#

OPTIONS="--foreground --verbose"
BACKEND="queue_track"

run ()
{
    cmd=$1
    echo ${cmd}
    eval ${cmd}
}

parse_args()
{
    args=$(getopt -o b: --long backend: -- "$@")
    # Check for parsing errors.
    if [ $? -ne 0 ]; then
	echo "Error: Failed to parse options." >&2
	exit 1
    fi
    eval set -- "$args"
    while true; do
	case "$1" in
	    -b|--backend)
		BACKEND=$2
		shift 2
		;;
	    --)
		shift
		break
		;;
	    *)
		echo "Internal Error: unexpected option: $1" >&2
		exit 1
		;;
	esac
    done
}

#
# script start
#

if [[ ! -x ./stalld ]] then
   echo "No stalld executable in the current directory!"
   exit 1
fi

parse_args $@

run "./stalld ${OPTIONS} --backend=${BACKEND}"
