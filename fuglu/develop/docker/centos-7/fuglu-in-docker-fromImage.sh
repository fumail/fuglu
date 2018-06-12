#!/bin/bash

#---------
# The yes no functions have been copied from: 
# https://www.linuxjournal.com/content/asking-yesno-question-bash-script
#---------

#####################################################################
# Print warning message.

function warning()
{
    echo "$*" >&2
}

#####################################################################
# Print error message and exit.

function error()
{
    echo "$*" >&2
    exit 1
}


#####################################################################
# Ask yesno question.
#
# Usage: yesno OPTIONS QUESTION
#
#   Options:
#     --timeout N    Timeout if no input seen in N seconds.
#     --default ANS  Use ANS as the default answer on timeout or
#                    if an empty answer is provided.
#
# Exit status is the answer.

function yesno()
{
    local ans
    local ok=0
    local timeout=0
    local default
    local t

    while [[ "$1" ]]
    do
        case "$1" in
        --default)
            shift
            default=$1
            if [[ ! "$default" ]]; then error "Missing default value"; fi
            t=$(tr '[:upper:]' '[:lower:]' <<<$default)

            if [[ "$t" != 'y'  &&  "$t" != 'yes'  &&  "$t" != 'n'  &&  "$t" != 'no' ]]; then
                error "Illegal default answer: $default"
            fi
            default=$t
            shift
            ;;

        --timeout)
            shift
            timeout=$1
            if [[ ! "$timeout" ]]; then error "Missing timeout value"; fi
            if [[ ! "$timeout" =~ ^[0-9][0-9]*$ ]]; then error "Illegal timeout value: $timeout"; fi
            shift
            ;;

        -*)
            error "Unrecognized option: $1"
            ;;

        *)
            break
            ;;
        esac
    done

    if [[ $timeout -ne 0  &&  ! "$default" ]]; then
        error "Non-zero timeout requires a default answer"
    fi

    if [[ ! "$*" ]]; then error "Missing question"; fi

    while [[ $ok -eq 0 ]]
    do
        if [[ $timeout -ne 0 ]]; then
            if ! read -t $timeout -p "$*" ans; then
                ans=$default
            else
                # Turn off timeout if answer entered.
                timeout=0
                if [[ ! "$ans" ]]; then ans=$default; fi
            fi
        else
            read -p "$*" ans
            if [[ ! "$ans" ]]; then
                ans=$default
            else
                ans=$(tr '[:upper:]' '[:lower:]' <<<$ans)
            fi 
        fi

        if [[ "$ans" == 'y'  ||  "$ans" == 'yes'  ||  "$ans" == 'n'  ||  "$ans" == 'no' ]]; then
            ok=1
        fi

        if [[ $ok -eq 0 ]]; then warning "Valid answers are: yes y no n"; fi
    done
    [[ "$ans" = "y" || "$ans" == "yes" ]]
}

# run current fuglu source in a docker environment
srcdir=$(cd "$(dirname "$0")/../../../"; pwd)
folder="centos-7"

if [ "$1" == "py2" ]; then
   alljobs=(py2) 
elif [ "$1" == "py3" ]; then
   alljobs=(py3) 
elif [ "$1" == "all" ]; then
   alljobs=(py2 py3) 
else
   echo "Usage: fuglu-in-docker-build-fromImage.sh OPTION"
   echo "       where OPTION is (py2/p3/all)"
   exit 0
fi

for job in "${alljobs[@]}"
do
   echo ""
   echo "***************************************************************"
   echo "* Running fuglu in docker instance for $folder for Python $job"
   echo "***************************************************************"
   image="danbla/fuglutestenv"

   did=$(docker create -w /fuglu-src -v $srcdir:/fuglu-src -t -i $image /bin/bash)
   echo "Starting docker instance ID: $did"
   docker start $did
   echo "Starting services (clamav, SA)..."
   docker exec -i $did chmod u=rwx /usr/local/bin/start-services.sh
   docker exec -i $did /bin/bash -c "/usr/local/bin/start-services.sh"
   docker exec -i $did /bin/bash -c "clamscan -V"

   echo ""
   echo "-----------------------------------"
   echo "- Installing current fuglu source -"
   echo "-----------------------------------"
   if [ $job == "py2" ]; then
      docker exec -i $did python2 setup.py install --force
   elif [ $job == "py3" ]; then
      docker exec -i $did python3 setup.py install --force
   else
      echo "Internal problem!"
      exit 1
   fi

   echo ""
   echo "--------------------------"
   echo "- Writing default config -"
   echo "--------------------------"
   docker exec -i $did /bin/bash -c "rename '.dist' '' /etc/fuglu/*.dist"
   docker exec -i $did /bin/bash -c "mkdir -p /var/log/fuglu"
   docker exec -i $did /bin/bash -c "chown -R nobody /var/log/fuglu"
   docker exec -i $did /bin/bash -c "chmod -R u=rwx,g=rwx,o=rwx /var/log/fuglu"
   docker exec -i $did /bin/bash -c "mkdir -p /dev/log"
   docker exec -i $did /bin/bash -c "chmod -R u=rwx,g=rwx,o=rwx /dev/log"
   docker exec -i $did fuglu --lint

   docker exec -ti $did /bin/bash

   if yesno --timeout 3 --default yes "Do you want to remove the container? (default: yes, timeout: 3s)"; then
      echo ""
      echo "timeout..."
      echo ""
      docker kill $did
      docker rm -v $did
   else
      echo ""
      echo "For cleanup run:"
      echo "docker kill $did "
      echo "docker rm -v $did "
      echo ""
   fi
done
