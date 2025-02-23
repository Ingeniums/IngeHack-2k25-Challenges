FROM ubuntu:24.04

RUN apt-get update && apt-get install -y socat libseccomp-dev

RUN useradd -m ctf

WORKDIR /home/ctf

COPY ./challenge/flag.txt /home/ctf/flag
COPY ./challenge/out_patched /home/ctf/out
COPY ./challenge/libc.so.6 /home/ctf/libc.so.6
COPY ./challenge/ld-2.39.so /home/ctf/ld-2.39.so

RUN chown -R root:ctf /home/ctf && \
    chmod -R 750 /home/ctf && \
    chmod 740 /home/ctf/flag

EXPOSE 1337

CMD ["socat", "-T60", "TCP-LISTEN:1337,reuseaddr,fork,su=ctf", "EXEC:/home/ctf/out,pty,echo=0,rawer"]