#!/bin/bash

PLATFORM=
ARCH=
TEMP_DOWNLOAD_FOLDER=


case "$(uname -s)" in
 Linux) PLATFORM='unknown-linux-gnu';;
 Darwin) PLATFORM='apple-darwin';;
 *)
   echo "Your platform doesn't seem to be of type darwin, linux"
   echo "Your architecture is $(uname -m) and your platform is $(uname -s)"
   exit 1
   ;;
esac

if [[ "$(uname -m)" == 'x86_64' || "$(uname -m)" == "amd64" ]]; then
  ARCH="x86_64"
elif [[ "$(uname -m)" == 'arm64' || "$(uname -m)" == 'aarch64' ]]; then
  ARCH="aarch64"
else
  echo >&2 "Your architecture doesn't seem to supported. Your architecture is $(uname -m) and your platform is $(uname -s)"
  exit 1
fi
URL="https://github.com/CremitHQ/nebula/releases/download/cli%2Flatest/latest-${ARCH}-${PLATFORM}.tar.gz"

mkdir -p tmp_nebula
cd tmp_nebula

TEMP_DOWNLOAD_FOLDER=$(pwd)

curl -s -o nebula-cli.tar.gz -L $URL
tar -xzf nebula-cli.tar.gz

if [ "$PLATFORM" == "apple-darwin" ]  ; then
  if [[ -d /usr/local/bin ]]; then
    chmod +x nebula
    sudo mv nebula /usr/local/bin/nebula
    echo "Nebula CLI ${LATEST_RELEASE_VERSION} has been installed in /usr/local/bin."
  else
    echo >&2 "Error: /usr/local/bin does not exist. You must create it before reinstalling"
    rm -rf $TEMP_DOWNLOAD_FOLDER 2> /dev/null
    exit 1
  fi
else
  chmod +x nebula
  sudo mv nebula /usr/local/bin/nebula
  echo "Nebula CLI ${LATEST_RELEASE_VERSION} has been installed in /usr/local/bin."
fi

rm -rf $TEMP_DOWNLOAD_FOLDER 2> /dev/null
