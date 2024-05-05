#!/bin/bash


for CONTRACT in ./contracts/*/
do
  (cd $CONTRACT && cargo schema)
done
