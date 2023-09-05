#!/bin/sh

#alias ledger_env='sudo docker run --rm -ti --user "$(id -u):$(id -g)" --privileged -v "/dev/bus/usb:/dev/bus/usb" -v "$(realpath .):/app" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest'
# For manual update of ~/.bashrc with ledger_env, just append the above line without the leading # character

# Add ledger_env to ~/.bashrc, alias for the command that is needed to connect to docker
DEVTOOLSET="alias ledger_env='sudo docker run --rm -ti --user \"\$(id -u):\$(id -g)\" --privileged -v \"/dev/bus/usb:/dev/bus/usb\" -v \"\$(realpath .):/app\" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest'"
FILENAME="$HOME/.bashrc"
# Search file
if grep "$DEVTOOLSET" $FILENAME > /dev/null
then
    echo "ledger_env present"
else
    # Add ledger_env ~/.bashrc if not present into the file
    echo $DEVTOOLSET >> $FILENAME
fi
