Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
    onEnter: function (args) {
        this.sock = args[0];
        this.addr = args[1];
        this.addrlen = args[2].toInt32();
    },
    onLeave: function (retval) {
        console.log("[*] connect called. Socket: " + this.sock);
    }
});
