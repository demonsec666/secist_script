#!/bin/bash
./avet/sh_format $1 | tr -d "\n" | tr -d "x" | tr -d "\\" | tr -d "\"" | tr -d ";"

