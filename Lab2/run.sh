#!/usr/local/bin/bash
/opt/ns3/v3.26/waf --run "Lab2 \
                          --name=mcrp \
                          --mean=1.00 \
                          --duration=60.00 \
                          --distance=100.00 \
                          --sensors=30 \
                          --power=20.00 \
                          --policy=mcrp \
                          --mals='3,20' \
                          "
