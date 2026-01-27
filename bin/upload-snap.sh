#!/bin/bash

for snap in certbot-dns-domainchief_*.snap; do
  snapcraft upload --release=stable $snap
done
