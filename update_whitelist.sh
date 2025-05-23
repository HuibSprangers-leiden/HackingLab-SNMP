#!/bin/bash

# To obtain more ip adresses, open the console on the censys platform, then run the following javascript to obtain more 
# var collect = document.getElementsByClassName('apoUv')
# var arr = [];
# for(var x=0; x<collect.length; x++){
#   arr.push(collect[x].innerHTML);
# }
# console.log(arr.toString().replace(new RegExp(',', 'g'), '\n'));

# Add the addresses obtained like that to the ip_whitelist file, then run this shell script to remove duplicate ips

sort -u ip_whitelist -o ip_whitelist