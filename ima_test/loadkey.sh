#!/bin/bash

pid=$1
key=$2

ring_name=`cat /proc/$pid/ima_keyring | grep ima | mawk '{print $2}'`
ring_id=`keyctl show | grep $ring_name | mawk '{print $1}'`
#echo $ring_id

key_id=`evmctl import $key $ring_id`
