int sd_listen_fds(int unset_environment) {
    return 0; // No file descriptors from systemd
}

int sd_is_socket(int fd, int family, int type, int listening) {
    return 0; // Not a systemd socket
}
