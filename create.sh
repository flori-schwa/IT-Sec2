#!/bin/bash

if [ -n $1 ]; then
    if [ -d $1 ]; then
        echo "Application $1 already exists"
        exit
    fi
    
    mkdir $1
    cp -r .template/* $1/
    sed -i -e "s/{{appname}}/$1/g" $1/Makefile
    echo "Created Application $1"
else
    echo "Syntax: $0 <name>"
fi