#utility/biutility/bash


VMNAME=$1
EXE=$2
TIME=$3
utility/start.sh $VMNAME
echo "sleeping 20 seconds"
sleep 20
echo "and we're back..."
utility/clean.sh $VMNAME
utility/runExe.sh $VMNAME $EXE $TIME
utility/readlog.sh $VMNAME $EXE
utility/poweroff.sh $VMNAME
initializer/restoreSnapshot.sh $VMNAME
