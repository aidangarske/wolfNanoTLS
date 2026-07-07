#!/usr/bin/env bash
# renewcerts.sh
#
# renews the following wolfNanoTLS test certs from their committed keys:
#                       server/ec-cert.pem    server/ec-cert.der
#                       server/ecdsa-cert.pem server/ecdsa-cert.der
#                       server/ed-cert.pem    server/ed-cert.der
#                       server/rsa-cert.pem   server/rsa-cert.der
#                       chain/root-cert.pem   chain/root-cert.der
#                       chain/inter-cert.pem  chain/inter-cert.der
#                       chain/leaf-cert.pem   chain/leaf-cert.der
#                       chain/fullchain.pem   (leaf + inter)
#
# Keys are reused, so SubjectPublicKeyInfo, SKI/AKI and any SPKI pin are
# unchanged. Subjects, serials and validity are fixed, so reruns are stable;
# only the signatures vary (ECDSA/RSA nonces are randomized).
###############################################################################
######################## FUNCTIONS SECTION ####################################
###############################################################################

NOT_BEFORE=20250101000000Z
NOT_AFTER=20450101000000Z
CNF=./renewcerts.cnf

check_result(){
    if [ $1 -ne 0 ]; then
        echo "Failed at \"$2\", Abort"
        exit 1
    else
        echo "$2 Succeeded!"
    fi
}

# selfsign <key> <cn> <serial> <out-base>
selfsign(){
    openssl req -new -key "$1-key.pem" -config "$CNF" -subj "/CN=$2" -out "$1.csr"
    check_result $? "$2 CSR"
    openssl x509 -req -in "$1.csr" -signkey "$1-key.pem" -set_serial "$3" \
        -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" \
        -extfile "$CNF" -extensions v3_ca ${5:+-$5} -out "$4-cert.pem"
    check_result $? "$2 cert"
    openssl x509 -in "$4-cert.pem" -outform der -out "$4-cert.der"
    check_result $? "$2 der"
    rm -f "$1.csr"
}

# casign <key> <cn> <serial> <ca-base> <ext> <out-base>
casign(){
    openssl req -new -key "$1-key.pem" -config "$CNF" -subj "/CN=$2" -out "$1.csr"
    check_result $? "$2 CSR"
    openssl x509 -req -in "$1.csr" -CA "$4-cert.pem" -CAkey "$4-key.pem" \
        -set_serial "$3" -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" \
        -extfile "$CNF" -extensions "$5" -out "$6-cert.pem"
    check_result $? "$2 cert"
    openssl x509 -in "$6-cert.pem" -outform der -out "$6-cert.der"
    check_result $? "$2 der"
    rm -f "$1.csr"
}

run_renewcerts(){

    ############################################################
    #### self-signed server certs (CN=wolfNanoTLS-test)        #
    ############################################################
    echo "Updating server/ec-cert"
    selfsign server/ec    wolfNanoTLS-test 10 server/ec
    echo "Updating server/ecdsa-cert"
    selfsign server/ecdsa wolfNanoTLS-test 11 server/ecdsa
    echo "Updating server/ed-cert"
    selfsign server/ed    wolfNanoTLS-test 12 server/ed
    echo "Updating server/rsa-cert"
    selfsign server/rsa   wolfNanoTLS-test 13 server/rsa
    echo "Updating server/p384-cert"
    selfsign server/p384  wolfNanoTLS-test 14 server/p384 sha384
    echo "Updating server/rsa4096-cert"
    selfsign server/rsa4096 wolfNanoTLS-test 15 server/rsa4096
    echo "Updating server DER private keys (wn_Accept_Cert)"
    openssl ec   -in server/ec-key.pem  -outform DER -out server/ec-key-sec1.der
    openssl pkey -in server/ed-key.pem  -outform DER -out server/ed-key.der
    openssl rsa  -in server/rsa-key.pem -outform DER -out server/rsa-key-trad.der
    echo "---------------------------------------------------------------------"

    ############################################################
    #### chain: root -> inter -> leaf                          #
    ############################################################
    echo "Updating chain/root-cert"
    selfsign chain/root wolfNanoTLS-root  1 chain/root
    echo "Updating chain/inter-cert"
    casign chain/inter wolfNanoTLS-inter 2 chain/root v3_ca   chain/inter
    echo "Updating chain/leaf-cert"
    casign chain/leaf  wolfNanoTLS-leaf  3 chain/inter v3_leaf chain/leaf

    cat chain/leaf-cert.pem chain/inter-cert.pem > chain/fullchain.pem
    check_result $? "chain/fullchain.pem"
    echo "---------------------------------------------------------------------"

    echo "End of Updates. Everything was successfully updated!"
    echo "---------------------------------------------------------------------"
}

###############################################################################
##################### THE EXECUTABLE BODY #####################################
###############################################################################

# start in tests/pki, regardless of the caller's working directory.
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

if [ ! -z "$1" ]; then
    echo "No arguments expected"
    exit 1
fi

run_renewcerts
rm -f chain/*.srl

exit 0
