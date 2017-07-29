#! /bin/bash

f=$1

if ! [ -d /usr/include/my_dev ];
then 
	sudo mkdir /usr/include/my_dev
fi

if [ "$f" = "debug" ] 
then 
	echo "Установлена дебажная версия <my_dev/threefish>"
	sudo cp ./debug/threefish.hpp /usr/include/my_dev/threefish
else
	echo "Установлена релизная версия <my_dev/threefish>"
	sudo cp ./include/threefish.hpp /usr/include/my_dev/threefish
fi

