#!/bin/bash

display_help(){
   echo ""
   echo "----------------------------------#"
   echo "- Local gitlab testing framework -#"
   echo "----------------------------------#"
   echo ""
   echo " Hosting this repo on gitlab automatic testing can be defined .gitlab-ci.yml"
   echo " in the main directory. It is also possible to run these test locally (which"
   echo " I would recommend before submitting)."
   echo ""
   echo " This scripts runs all the tests which will also run on gitlab. Plesae not"
   echo " changes have to be commited to be tested."
   echo ""
   echo " Requirements:"
   echo " 1) docker repo on local host running containing fuglu testing image"
   echo "     - install docker"
   echo " 2) install gitlab-runner (https://docs.gitlab.com/runner/install/linux-repository.html)"
   echo ""
}

# no arguments needed, print help if there are any...
if [ $# -ne 0 ]; then
   display_help
   exit 0
fi

maindir=$(cd "$(dirname "$0")/../../"; pwd)

echo "maindir: $maindir"
cd $maindir

alljobs=(buildfuglu_py3 buildfuglu isolated_py3 isolated unittests_py3 unittests integrationtests_py3 integrationtests)

for job in "${alljobs[@]}"
do
   echo ""
   echo ""
   echo "--------------------------------"
   echo "Running job $job"
   echo "--------------------------------"
   echo ""
   gitlab-runner exec docker $job
   # check return
   rc=$?; if [[ $rc != 0 ]]; then exit $rc; fi
done

cd -
exit 0
