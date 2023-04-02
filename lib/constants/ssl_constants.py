EXPIRED = {
    True: {
        "error":
        True,
        "message":
        "Certificate is expired",
        "solution":
        "Renew the certificate or use a different one SSL/TLS certificate to avoid MITM attacks"
    },
    False: {
        "error": False,
        "message": "Certificate is up to date"
    }
}
