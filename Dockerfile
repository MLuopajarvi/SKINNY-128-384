FROM gcc:4.9

COPY . /usr/src/myapp

WORKDIR /usr/src/myapp

RUN gcc -o myapp driver_skinny.c skinny.c

CMD ["./myapp"]

