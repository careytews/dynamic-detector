FROM fedora:26

RUN dnf install -y libgo

COPY dynamic-detector /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/dynamic-detector"]
CMD [ "/queue/input", "output:/queue/output" ]
