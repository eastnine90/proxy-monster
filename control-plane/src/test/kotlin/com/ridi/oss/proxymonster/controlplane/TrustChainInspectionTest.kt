package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.grpc.inspectTrustChain
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * [inspectTrustChain] REPORTS on trust material; it never gates. Registration and the download route both log its
 * reason and proceed regardless: the CLIENT performs the real verification and is the only party that can
 * report a meaningful error about its own trust store. Refusing centrally would trade one client's TLS error
 * for a datasource that never registers at all.
 *
 * A smuggled trust anchor is still the case worth detecting: appending a CA to a real leaf adds a
 * trust anchor while leaving the leaf unchanged, so it is reported — but the registering proxy is
 * authenticated and picks the address to go with it, so this is a signal to an operator, not a boundary.
 */
class TrustChainInspectionTest {
    @Test
    fun `a self-signed certificate is its own anchor`() {
        assertNull(inspectTrustChain(SELF_SIGNED), "the ordinary self-signed proxy case must be accepted")
    }

    @Test
    fun `a leaf with its issuer is a valid chain`() {
        assertNull(inspectTrustChain(CA_LEAF + ISSUING_CA))
    }

    @Test
    fun `a CA-issued leaf alone is reported because nothing anchors it`() {
        // A client given only this gets "unable to get local issuer certificate" no matter what it does.
        assertNotNull(inspectTrustChain(CA_LEAF))
    }

    @Test
    fun `a smuggled trust anchor is reported`() {
        // real leaf + its issuer + an UNRELATED self-signed CA. The leaf verifies, the chain does not: the
        // extra certificate issues nothing, so it cannot ride along as a trust anchor.
        assertNotNull(inspectTrustChain(CA_LEAF + ISSUING_CA + SELF_SIGNED))
        // And the shorter form: a real leaf with an unrelated CA appended instead of its own issuer.
        assertNotNull(inspectTrustChain(CA_LEAF + SELF_SIGNED))
    }

    @Test
    fun `a certificate that only CLAIMS to be its own issuer is reported`() {
        // Names itself as issuer but was signed by a different key. Issuance is checked by SIGNATURE, so a
        // name-only test would accept this and the download would hand out an unusable anchor.
        assertNotNull(inspectTrustChain(FORGED_SELF_ISSUER))
    }

    @Test
    fun `a chain whose issuer is not a CA is reported`() {
        // A signature alone does not make something an issuer. Clients enforce basicConstraints: OpenSSL
        // rejects this exact chain with "error 79 at 1 depth lookup: invalid CA certificate", so accepting
        // it would store a chain no client could use -- and would let any certificate holding a key be
        // presented as an issuer. Verified against openssl before this test was written.
        assertNotNull(inspectTrustChain(LEAF_ISSUED_BY_A_NON_CA + NON_CA_ISSUER))
    }

    @Test
    fun `unparseable or empty input is reported`() {
        assertNotNull(inspectTrustChain(""))
        assertNotNull(inspectTrustChain("not a certificate"))
        assertNotNull(inspectTrustChain("-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n"))
    }

    private companion object {
        val SELF_SIGNED =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIDPTCCAiWgAwIBAgIUJeAynTaX/TJdfCHpPYqljxv5BJ0wDQYJKoZIhvcNAQEL\n" +
        "BQAwHzEdMBsGA1UEAwwUcG0tcHJveHkuZXhhbXBsZS5jb20wHhcNMjYwNzI3MTIy\n" +
        "MDIzWhcNMjcwNzI3MTIyMDIzWjAfMR0wGwYDVQQDDBRwbS1wcm94eS5leGFtcGxl\n" +
        "LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALAPb/6x5fTqssbH\n" +
        "0jKzOI90/MnENRaAfb4As4e5yse0Xrir2Kz/10O6GSH49lhdRa/csLqeH122m9gj\n" +
        "C4vCIvDJRTqz81s3yaLN7/4PnTbS1WOwp+PTwRajHXC8Xp5MPBEyZVNj+WjzCYE4\n" +
        "inlXuSJSFaTUB1Md1F91UaD/q+eOt/Rocg5Erq65Z6tWnAs03t3Sp8ZfBs/YlA5u\n" +
        "TP5BPgE3NQq6uwU1kBfQQpPiem+B/9NATbY094YH3cJwOFMF1Z69t80LO2ZvZ7u8\n" +
        "fQs0GHPpIE8n7mkGjleOwFypoDM9N+ZDtSeAQBGAk5ulV59lni2/xV1pQ0YDx8H6\n" +
        "t1ekfI8CAwEAAaNxMG8wHQYDVR0OBBYEFCUm5743U+xa/Rqr4rlRqDt/qJ8SMB8G\n" +
        "A1UdIwQYMBaAFCUm5743U+xa/Rqr4rlRqDt/qJ8SMAwGA1UdEwEB/wQCMAAwHwYD\n" +
        "VR0RBBgwFoIUcG0tcHJveHkuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEB\n" +
        "AKbyz1Vu4MhL49dXoCQPdyXj+m332HIAMtQDDRJubbFTm+x0KQLOCgb3ZBvi6x1k\n" +
        "WertFs3Mqs4g/72BvfU96aCmCYJ4iZi0XT3ZC/1j36dJjxpk1EDM75pW5KLnfDDo\n" +
        "qWF7gtahB3uGqKM4uRpkodGE7OIelf/Hs/m/iSnnX6VEGCQIe9Ew87B2xtj4u891\n" +
        "ghWojgBCelZxEmN31Og6VFRYTZYLk/Xb4ya2Xq6g8jjwGKKYHZCs1gQ1vvZm4eof\n" +
        "GrFvts/fga0akW6kpc3vBLP1gMZFirHQ6WZnemsdEcXG1GKyM40O4KkPBYcnypT0\n" +
        "3lp9W8du2aYfDic7uDfw0Gg=\n" +
        "-----END CERTIFICATE-----\n"
        val CA_LEAF =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIDODCCAiCgAwIBAgIUCMlJHsWQYF9aDuby/9E5L6bOjrUwDQYJKoZIhvcNAQEL\n" +
        "BQAwGjEYMBYGA1UEAwwPVGVzdCBQcml2YXRlIENBMB4XDTI2MDcyNzA5MDUwOFoX\n" +
        "DTI3MDcyNzA5MDUwOFowHzEdMBsGA1UEAwwUcG0tcHJveHkuZXhhbXBsZS5jb20w\n" +
        "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDc265GclVN6fROXzi+yxYz\n" +
        "PyWp/0DuoV6VZBIxjoPAYZE5iMpLqz4COlr/y+0sRZ8fy3/3v3VF+AkR+Nreeznd\n" +
        "WNNBdnDkYg48vgy6Og4V7riU2uFL6SEGqCsM3Thcj3TffNmfRd2+OebD8CMg91Hs\n" +
        "Hn6ddmCVT0yUrJstLasuS4yNd0JVrX8FrxxaljQjlVX7H+kSLVn+x/qLLga1wWRd\n" +
        "wEHd7LObrk06WvPsMP+qbyQTA9CP7GJtbv7vEloECE3sS2l3QjWUQGp4YFrnMWl5\n" +
        "wdZSuThXz9sub/y0c51vLvzDJVVbNYdshMBrpZWbp6cALVS+qzCt35drj6WOnkUt\n" +
        "AgMBAAGjcTBvMAwGA1UdEwEB/wQCMAAwHwYDVR0RBBgwFoIUcG0tcHJveHkuZXhh\n" +
        "bXBsZS5jb20wHQYDVR0OBBYEFBj09SNWr+0aRPR3d2yu+D71Ne9QMB8GA1UdIwQY\n" +
        "MBaAFPLbxOH+O1GK8v0GeivzFC4vXMp+MA0GCSqGSIb3DQEBCwUAA4IBAQBVsgMq\n" +
        "MBK2K1hwcDWlMDxRAnXjxlBlTFOAYUqHPj3Ldxqwma753kPcXaikfS4NJ9+ykHkh\n" +
        "0tr+UhYe7GzW28pEz2qzkh1uBqYi2gQHgFMyIkjCECFSE8YVFXaVWFdVI9NEeRdp\n" +
        "KzWxd4PrudQ1Rz9AN2OTD1O/HXlvZ5McWltira59nLZKmKt27Z10qq3vBrjHapoX\n" +
        "0m9jVxpnAquar42WJTlKcs7xp8Z6uKVqCURu4csrWDalAWprdHHKaxLazVjh1L2w\n" +
        "qAv8gJuOTmYouD/hcFK0SCNtT3Rq4f9HFQlo7mYjXs02LK/IIYTxUwmJzW2W06vF\n" +
        "TBtfh2tHAcUTxjLG\n" +
        "-----END CERTIFICATE-----\n"
        val ISSUING_CA =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIDFTCCAf2gAwIBAgIUUgWMsQi5dszsgUyVMRAvICNT6jswDQYJKoZIhvcNAQEL\n" +
        "BQAwGjEYMBYGA1UEAwwPVGVzdCBQcml2YXRlIENBMB4XDTI2MDcyNzA5MDUwN1oX\n" +
        "DTI3MDcyNzA5MDUwN1owGjEYMBYGA1UEAwwPVGVzdCBQcml2YXRlIENBMIIBIjAN\n" +
        "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjpMm4TxsR6lr96BsZZNXg4FS5u6n\n" +
        "/4B4EsOVSr0HzN0w8+HVNKtFDn1OozhXsYgZhrR2xTbpETx/+W/D8MUeYw8mW9N4\n" +
        "P68hj7ueSs6R1PGwVBqm0/O2C4cDiKtBTNMwdYjlBejVlQ7mS2PhuzDEQCmi8S3B\n" +
        "77poEOjBo2s/BlID14MqTrqs9/6xs1akR5duC0ZUywxhUGsWDIsRhQ1wKtny+s/2\n" +
        "1IWi7vP3XuXjcHS7mitYzfq5OsqgUeiZrN2AtBxj3+u2ym4BFXx+tFFJtbV+G/dS\n" +
        "YGOI3mCC1JPm5Qc3COIeNCdLzd3H794R8d1FquY4ChV0p3daDLHOJXtS5wIDAQAB\n" +
        "o1MwUTAdBgNVHQ4EFgQU8tvE4f47UYry/QZ6K/MULi9cyn4wHwYDVR0jBBgwFoAU\n" +
        "8tvE4f47UYry/QZ6K/MULi9cyn4wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B\n" +
        "AQsFAAOCAQEAcRIDy5Pf2lUTQy7xNg07vBFXhbON2uquwDGqQzGZvEr+luZ31isc\n" +
        "B+HTqwDNTBgQ4pZWwJLY3VjiKPJ1JOJir0IUdgHnJoVbqfwchM6hW1iGx+yOwUs2\n" +
        "HHpK4dAKd9nOY4gsJmie8Y9wMCvGW3/SmSs1q3gDZAK85qqyH+0/gbO6wfCAJtaV\n" +
        "5LgRd68Ep9FBedpdkCX99rakRXsNIL+NotjL1XhivdXmsljdNr/Euy7rbLmfXXLB\n" +
        "uwRCZPDbOUJGzXW3gdUJpeFtpUQHgiGHo6mbElgEBbjemnmebhNY92yHg365UjMH\n" +
        "TH5ujWUrKFM8MwihwokXf1RocDNA2CQWMA==\n" +
        "-----END CERTIFICATE-----\n"
        val LEAF_ISSUED_BY_A_NON_CA =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIDOTCCAiGgAwIBAgIUDsIVk8fGLgwQx8hGTLRvA8uU1BowDQYJKoZIhvcNAQEL\n" +
        "BQAwHzEdMBsGA1UEAwwUcG0tcHJveHkuZXhhbXBsZS5jb20wHhcNMjYwNzI3MTQx\n" +
        "MDI3WhcNMjcwNzI3MTQxMDI3WjAdMRswGQYDVQQDDBJ2aWN0aW0uZXhhbXBsZS5j\n" +
        "b20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0o7awsWLzXzTp7Pdd\n" +
        "rQwRrH9Moav8+w7YnANYWGRcT2FOmWive1rH8VqEXnHn3uNB/i2CwroEvqLMIgQN\n" +
        "gNp2xVEm7nEkATlz6/qzG7/shdos/wq5zSsaFNfB+mQ40NOa1aHlVkNXF+lQ+bpk\n" +
        "N78iFr9/YhBEOC4BDQAQq52SQHxDLh5wjsAWUWiAdAEMc0eYEU5EfGLMck9OgU1m\n" +
        "4D+ZrDYJBDvSB94iOoF5I9zHB6q94LyOI0O1OxUmDIbhd+quJnk+tGzGbRCGK+Oj\n" +
        "yknplRhibp98Uya1DnkpOB4eloHl9FmIjEi+bGlnEy10V2vtXb+zt9B3SbrR0GYq\n" +
        "nURXAgMBAAGjbzBtMAwGA1UdEwEB/wQCMAAwHQYDVR0RBBYwFIISdmljdGltLmV4\n" +
        "YW1wbGUuY29tMB0GA1UdDgQWBBTQtzkryLLUxop1gYEfJ4jvEoR5FDAfBgNVHSME\n" +
        "GDAWgBQlJue+N1PsWv0aq+K5Uag7f6ifEjANBgkqhkiG9w0BAQsFAAOCAQEAJsGQ\n" +
        "KWD9KAYsx7q0HvbLpWheedl6R+xOL/9mTBJVVOHII3HGvIQdf+z/B4y9gj4cgZj4\n" +
        "IDa2mXg/vVWYFw/D/uzKEQjWMSWc01NwiGrDyMUzfhtKA1e2VJIYF/o6Kd8+xVTz\n" +
        "DO+oKHoADa/qxp61KrIi0qkVPIH7ghHVDH54AJ+9E8f1RFT3+3823kMdi9uj9Rwg\n" +
        "rMJh6qm6x598y6rCdncoRq8lzSMlhikIIHIxxgKENFrl956OEob7lpnheX3hKODA\n" +
        "QDsFJbqUvbTm12jK63AYPd/eHONBB/tywRGgf1JZMEWqyNJhRetSQYM0NF7fyfQw\n" +
        "AOlngNqVcl9J2KE0kg==\n" +
        "-----END CERTIFICATE-----\n"
        val NON_CA_ISSUER =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIDPTCCAiWgAwIBAgIUJeAynTaX/TJdfCHpPYqljxv5BJ0wDQYJKoZIhvcNAQEL\n" +
        "BQAwHzEdMBsGA1UEAwwUcG0tcHJveHkuZXhhbXBsZS5jb20wHhcNMjYwNzI3MTIy\n" +
        "MDIzWhcNMjcwNzI3MTIyMDIzWjAfMR0wGwYDVQQDDBRwbS1wcm94eS5leGFtcGxl\n" +
        "LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALAPb/6x5fTqssbH\n" +
        "0jKzOI90/MnENRaAfb4As4e5yse0Xrir2Kz/10O6GSH49lhdRa/csLqeH122m9gj\n" +
        "C4vCIvDJRTqz81s3yaLN7/4PnTbS1WOwp+PTwRajHXC8Xp5MPBEyZVNj+WjzCYE4\n" +
        "inlXuSJSFaTUB1Md1F91UaD/q+eOt/Rocg5Erq65Z6tWnAs03t3Sp8ZfBs/YlA5u\n" +
        "TP5BPgE3NQq6uwU1kBfQQpPiem+B/9NATbY094YH3cJwOFMF1Z69t80LO2ZvZ7u8\n" +
        "fQs0GHPpIE8n7mkGjleOwFypoDM9N+ZDtSeAQBGAk5ulV59lni2/xV1pQ0YDx8H6\n" +
        "t1ekfI8CAwEAAaNxMG8wHQYDVR0OBBYEFCUm5743U+xa/Rqr4rlRqDt/qJ8SMB8G\n" +
        "A1UdIwQYMBaAFCUm5743U+xa/Rqr4rlRqDt/qJ8SMAwGA1UdEwEB/wQCMAAwHwYD\n" +
        "VR0RBBgwFoIUcG0tcHJveHkuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEB\n" +
        "AKbyz1Vu4MhL49dXoCQPdyXj+m332HIAMtQDDRJubbFTm+x0KQLOCgb3ZBvi6x1k\n" +
        "WertFs3Mqs4g/72BvfU96aCmCYJ4iZi0XT3ZC/1j36dJjxpk1EDM75pW5KLnfDDo\n" +
        "qWF7gtahB3uGqKM4uRpkodGE7OIelf/Hs/m/iSnnX6VEGCQIe9Ew87B2xtj4u891\n" +
        "ghWojgBCelZxEmN31Og6VFRYTZYLk/Xb4ya2Xq6g8jjwGKKYHZCs1gQ1vvZm4eof\n" +
        "GrFvts/fga0akW6kpc3vBLP1gMZFirHQ6WZnemsdEcXG1GKyM40O4KkPBYcnypT0\n" +
        "3lp9W8du2aYfDic7uDfw0Gg=\n" +
        "-----END CERTIFICATE-----\n"
        val FORGED_SELF_ISSUER =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIDPTCCAiWgAwIBAgIUaOLIp1a0IjqqUa3rcq96FjkCnckwDQYJKoZIhvcNAQEL\n" +
        "BQAwHzEdMBsGA1UEAwwUcG0tcHJveHkuZXhhbXBsZS5jb20wHhcNMjYwNzI3MTIy\n" +
        "OTEzWhcNMjcwNzI3MTIyOTEzWjAfMR0wGwYDVQQDDBRwbS1wcm94eS5leGFtcGxl\n" +
        "LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnoSdkhOkOC/yn9\n" +
        "kXurlalVTBiq6Ehlbi1W/54YtQEEpVoRyxvxn3kPRxYBUw7D/+56/xPv3Tyoc1d+\n" +
        "bjT6LDSm9h+XvHYTOjv19BngDiCa4zWPJlM4eOids1Q++0i2/30qsOloKsg7jx2B\n" +
        "zqDgylS9GZeED6Kfhg6radiM4L3WRxegxC5DtsfVm1UgvleMOuBEGBHwgQZUjzcL\n" +
        "9tm6ctttAnjzl5/GM1+zvoS+78u2uvBH/q7A3mYHgm5BSd9ePM0/2ETuY80PtcCv\n" +
        "oa2GrbISlIbxXOVtf5T2BJcnuzcDPchqn/M3OVbhffCtdJs9EtDvUzkbS62NRpHe\n" +
        "SgPhHPUCAwEAAaNxMG8wDAYDVR0TAQH/BAIwADAfBgNVHREEGDAWghRwbS1wcm94\n" +
        "eS5leGFtcGxlLmNvbTAdBgNVHQ4EFgQUSz6ZZVLaCCNB7lb8q+EcNKNERuUwHwYD\n" +
        "VR0jBBgwFoAU0ElnM9xIbtVQ6tFCFdVpnCNlu4AwDQYJKoZIhvcNAQELBQADggEB\n" +
        "AGZk/S06rvOsIbLimjcHimr48llXdWvhIG7V38YlBTOCVG2L0Dt6S0FAuto5b/hd\n" +
        "LhgvNyvt+iUkywX/L8aR9LmQ05yU4g/6n4aGBQdEZDl7rTjgiJhfnxEINNwwX2IY\n" +
        "7BCy27oLdI0zRG7EVB1gT0ABkYUiD97ioadNoPcnTquTAsCKFXCYxR59tlR2JEbe\n" +
        "NNbe2Dqo4yQISUnZ8avZtFpYQsY8zO7CA68ipBp+AgZ0mBoCLGTngqWr4B8ezrmy\n" +
        "Lpe1XUpnzAUGW5vTCDWXux0uD19x/Cnf6TrQxSLCMVvYCPeOLS+DHiB4vosAHth2\n" +
        "EM9ft42Cnf06jKZdGfV5HOg=\n" +
        "-----END CERTIFICATE-----\n"
    }
}
