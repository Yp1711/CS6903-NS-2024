@load base/protocols/ssl

event ssl_established(c: connection) {
    if (c$ssl?$cert_chain && |c$ssl$cert_chain| > 0) {
        local leaf_cert = c$ssl$cert_chain[|c$ssl$cert_chain| - 1];

        # Check if the leaf certificate is self-signed
        if (leaf_cert$x509$certificate$subject == leaf_cert$x509$certificate$issuer) {
            print fmt("Its a self-signed certificate: %s", leaf_cert$x509$certificate$subject);
        } else {
            print "Its not a self-signed certificate";
        }
    } else {
        print "Connection has no certificate information";
    }
}

