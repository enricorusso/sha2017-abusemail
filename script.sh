declare -i pos
pos=5

tshark -r file2.pcap -T fields -e usb.capdata | cut -d: -f1,3 |
while read a
do
 if [ "$a" != "" ]; then
     h1=`echo $a | cut -d: -f1`
     h2=`echo $a | cut -d: -f2`

     if [ "$h2" == "38" ]; then
         echo -n "/"
     fi

     if [ "$h2" != "00" ]; then
       	IFS="/"
    	tokens=( `grep 0x$h2 keycodes  | grep -i keyboard` )
 	ret=`echo ${tokens[2]} | cut -b11-`
	if [[ $ret == *"and"* ]]; then
	    r1=`echo $ret | cut -b1`
	    r2=`echo $ret | rev | cut -b1`
 	     if [ "$h1" == "02" ]; then 
	   	echo -n "$r2"
	     else
	 	echo -n "$r1"
	     fi
        else
            case $h2 in
		"28")
		  echo
		  ;;
	         "2c")
	          echo -n " " 
		  ;;
		 "*")
	          echo -n "?$h2"
		  ;;
	    esac
  	    #if [ "$h2" == "28" ]; then
	#	echo
	#    else
  	#         if [ "$h2" == "2c" ]; then
	#   	     echo -n " "
	#     else
	#    fi
	fi
    fi
 fi
done
