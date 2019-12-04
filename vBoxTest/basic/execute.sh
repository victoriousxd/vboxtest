#utility/biutility/bash
time=20

utility/start.sh $1
echo "sleeping " $time " seconds"
sleep $time
echo "and we're back..."
utility/clean.sh $1
utility/runExe.sh $1 $2 $3
utility/readlog.sh $1 $2
utility/poweroff.sh $1