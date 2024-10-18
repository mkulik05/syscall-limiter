class SocketBridge {
    public:
        SocketBridge();
        ~SocketBridge();

        int send_fd(int n);
        int recv_fd();

        int send_int(int n);
        int recv_int();

    private:
        int sockPair[2];
};