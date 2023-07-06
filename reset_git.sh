#! /bin/bash

script_dir=$(cd $(dirname ${BASH_SOURCE:-$0}); pwd)
cd $script_dir

URL=$(git config --local remote.origin.url)
if [ "$URL" == "" ] ; then
	echo "Can't get URL"
	exit 1 
fi

rm -rf .git
git init
git remote add origin $URL
git add .
git commit -m "initial commit"
git push -u origin master -f

