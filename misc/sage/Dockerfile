FROM sagemath/sagemath:latest

RUN sudo apt-get update && \
    sudo apt-get install -y socat 

COPY ./dist /dist

WORKDIR /dist

RUN sudo chmod +x entrypoint.sh server.py

EXPOSE 2020

ENTRYPOINT ["./entrypoint.sh"]
