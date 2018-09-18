#!/bin/bash

#
# Include this script using:
#
# source /scripts/utils.sh
#

#---------------------------------------
# return the folder of executing script
#
# usage sample:
# echo "running from [`executing_dir`]"
executing_dir()
{
	dirname `readlink -f "$0"`
}

#-----------------------------------------
# if press y it will continue, otherwise
# it will exit calling script
proceed()
{
        if [ "$1" != "" ]; then
                read -p "$1 " -n 1 -r
        else
                read -p "proceed ? " -n 1 -r
        fi
        echo
        if ! [[ $REPLY =~ ^[Yy]$ ]]; then exit 0; fi
}
