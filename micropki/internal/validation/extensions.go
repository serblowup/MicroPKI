package validation

import (
    "crypto/x509"
    "encoding/asn1"
    "fmt"
    "net/url"
)

// OID для AIA
var (
    oidAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
    oidOCSP                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
    oidCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}
)

// ExtractOCSPURL извлекает URL OCSP ответчика из AIA расширения
func ExtractOCSPURL(cert *x509.Certificate) (string, error) {
    for _, ext := range cert.Extensions {
        if ext.Id.Equal(oidAuthorityInfoAccess) {
            var aia []struct {
                Method   asn1.ObjectIdentifier
                Location asn1.RawValue
            }
            
            if _, err := asn1.Unmarshal(ext.Value, &aia); err != nil {
                continue
            }
            
            for _, access := range aia {
                if access.Method.Equal(oidOCSP) {
                    var urlStr string
                    if _, err := asn1.Unmarshal(access.Location.Bytes, &urlStr); err == nil {
                        return urlStr, nil
                    }
                }
            }
        }
    }
    
    return "", fmt.Errorf("OCSP URL не найден в AIA")
}

// ExtractCRLURLs извлекает URL CRL из CDP расширения
func ExtractCRLURLs(cert *x509.Certificate) ([]string, error) {
    var urls []string
    
    for _, ext := range cert.Extensions {
        if ext.Id.Equal(oidCRLDistributionPoints) {
            var crlDP []struct {
                DistributionPoint struct {
                    FullName []asn1.RawValue `asn1:"optional,tag:0"`
                } `asn1:"optional"`
            }
            
            if _, err := asn1.Unmarshal(ext.Value, &crlDP); err != nil {
                continue
            }
            
            for _, dp := range crlDP {
                for _, name := range dp.DistributionPoint.FullName {
                    if name.Tag == 6 {
                        var urlStr string
                        if _, err := asn1.Unmarshal(name.Bytes, &urlStr); err == nil {
                            if _, err := url.Parse(urlStr); err == nil {
                                urls = append(urls, urlStr)
                            }
                        }
                    }
                }
            }
        }
    }
    
    return urls, nil
}