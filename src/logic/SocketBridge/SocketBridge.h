#pragma once
#include <string>

struct Strings {
    std::string str1;
    std::string str2;
};

class SocketBridge {
    public:
        SocketBridge();
        ~SocketBridge();

        int send_fd(int n);
        int recv_fd();

        int send_int(int n);
        int recv_int();

        int send_strings(const Strings& strings);
        int recv_strings(Strings& strings);
        

    private:
        int sockPair[2];
};