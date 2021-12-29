# set BMC User
# find the first empty slot in user list
user_num=$(ipmitool user list 1 | sed -n '2,$p' |awk '{if ($2=="true" || $2=="false") print NR}' | tail -n 1)
if [ "x$user_num" = "x" ]; then
    echo "No BMC user slot left, exiting.."
    exit
fi
# set the debug user BMC user if it not exsits
user_debug=$(ipmitool user list 1 | sed -n '2,$p' |awk '{if ($2=="debuguser") print $2}')
if [ -z $user_debug ]; then
    echo -e "No debuguser user found in BMC, now setting..."
    ipmitool user set name $user_num debuguser
    ipmitool user set password $user_num 0penBmc1
else
    echo -e "Already have debuguser for BMC, using exsiting one..."
    user_num=$(ipmitool user list 1 | sed -n '2,$p' |awk '{if ($2=="debuguser") print NR}')
fi
ipmitool user enable $user_num

temp_ip=$(ipmitool lan print 3 | grep "IP Address" | sed -n '2p' | awk '{print $4}')
if [ $temp_ip == '0.0.0.0' ]; then
    echo "Invalid IP, please check BMC lan"
else
    ipmitool channel setaccess 3 $user_num ipmi=on privilege=4
    echo $temp_ip
fi

