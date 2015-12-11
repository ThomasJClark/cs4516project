#!/bin/bash
go fmt *.go
for d in $(ls);
  do
    if [ -d $d ];
      then
        cd $d;
        go fmt;
        cd ../;
    fi
done
