FROM ubuntu:22.10

# Ubuntu 22.10 también es EOL
RUN sed -i -re 's/([a-z]{2}.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

# Instalar Cliente (para ser C4) y Servidor (para ser S1)
RUN apt-get update && apt-get install -y openssh-client openssh-server tcpdump net-tools iputils-ping nano

# Configuración requerida para SSHD
RUN mkdir -p /var/run/sshd
# Crear usuario 'prueba' con password 'prueba'
RUN useradd -m -s /bin/bash prueba && \
    echo 'prueba:prueba' | chpasswd

# Permitir acceso por password (a veces viene deshabilitado por defecto en versiones nuevas)
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22