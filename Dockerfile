#
# IPwatchD Dockerfile
#
# https://github.com/jariq/IPwatchD
#

# Pull base image.
FROM debian:jessie

# Install IPwatchd.
RUN \
  apt-get update && \
  apt-get install -y ipwatchd && \
  rm -rf /var/lib/apt/lists/* && \
  mkdir -p /etc/ipwatchd

# Define mountable directories.
# ipwatchd-script, and ipwatchd.conf should place here.
VOLUME ["/etc/ipwatchd"]

# Define working directory.
WORKDIR /etc/ipwatchd

# Define default command.
CMD ["ipwatchd"]
