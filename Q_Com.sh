#!/bin/bash
#v.020523
# I use this script to speed up my git commands you can ignore it.
git add *
date_time="$(date +"%m.%d.%y %I:%M%p")"

echo "*"
git commit -m "$date_time"
echo "*  *"
echo "*  *  *"
sleep 1
echo "Script v.020523 Complete"
#git push
