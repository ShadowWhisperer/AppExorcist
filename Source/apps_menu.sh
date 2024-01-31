#!/bin/bash

clear

if [ ! -f '/tmp/source' ]; then echo; echo ' /tmp/source  does not exist'; echo; exit; fi


echo >> /tmp/source
rm -f /tmp/results

function Info
{
echo
read -p ' Info: ' Info </dev/tty
}
function Issues
{
echo
read -p ' Issue: ' Issues </dev/tty
}

function SetOptions
{
clear

echo "
          Name: $Name
   1.     Info: $Info
   2.     Hide: $Hide
   3.   Issues: $Issues
   4.   Native: $Native
   5.    Bloat: $Bloat

   0. Save
"
read -p ' > ' Opt </dev/tty

  if [[ "$Opt" == '1' ]]; then Info  #Info
elif [[ "$Opt" == '2' ]]; then if [[ "$Hide" == 'yes' ]]; then Hide='no'; else Hide='yes'; fi       #Hide
elif [[ "$Opt" == '3' ]]; then Issues #Issues
elif [[ "$Opt" == '4' ]]; then if [[ "$Native" == 'yes' ]]; then Native='no'; else Native='yes'; fi #Native
elif [[ "$Opt" == '5' ]]; then if [[ "$Bloat" == 'yes' ]]; then Bloat='no'; else Bloat='yes'; fi    #Bloatware
  fi

if [[ "$Opt" != '0' ]]; then SetOptions; else return; fi
}



IFS=; while read -r Line; do
Name="$(awk '{print $1;}' <<< "$Line" | cut -f1 -d ',')"
if [[ -z "$Name" ]]; then exit; fi
Info="$(cut -d, -f2- <<< "$Line")"

Issues='none'
Hide='no'
Native='no'
Bloat='no'
SetOptions

echo '  {' >> /tmp/results
echo "   \"name\": \"$Name\"," >> /tmp/results
echo "   \"info\": \"$Info\"," >> /tmp/results
echo "   \"issues\": \"$Issues\"," >> /tmp/results
echo "   \"hide\": \"$Hide\"," >> /tmp/results
echo "   \"native\": \"$Native\"," >> /tmp/results
echo "   \"bloat\": \"$Bloat\"" >> /tmp/results
echo '  },' >> /tmp/results
chmod 777 /tmp/results


done < /tmp/source

