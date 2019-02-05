FROM alpine:3.8
RUN apk add --no-cache openssh && \
    rm -f /etc/ssh/*_key
RUN addgroup testuser && \
    adduser -D --gecos "" -G testuser -s /bin/sh testuser && \
    echo 'testuser:password' | chpasswd && \
    mkdir /home/testuser/.ssh
COPY ./testdata/ssh_host_rsa_key /etc/ssh/ssh_host_rsa_key
COPY ./testdata/ssh_host_rsa_key.pub /home/testuser/.ssh/authorized_keys
RUN chmod 700 -R /home/testuser/.ssh && \
    chown -R testuser:testuser /home/testuser/.ssh
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
