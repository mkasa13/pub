#! /bin/bash

script_dir=$(cd $(dirname ${BASH_SOURCE:-$0}); pwd)
cd $script_dir

git add --all .
git commit -m "auto commit"
git push -u origin master -f

