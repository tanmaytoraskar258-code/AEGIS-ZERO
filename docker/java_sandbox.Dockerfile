FROM maven:3.9.6-eclipse-temurin-17

WORKDIR /workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

CMD ["/bin/bash"]
