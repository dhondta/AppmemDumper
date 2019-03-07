#!/bin/bash
pyclean .
sudo rm -rf build
sudo rm -rf dist
sudo rm -rf appmemdumper.egg-info
sudo pip2 uninstall tinyscript -y
sudo pip3 uninstall tinyscript -y
sudo python2 setup.py install
sudo python3 setup.py install
