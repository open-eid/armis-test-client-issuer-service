package ee.ria.armis.issuer.service.model;

import lombok.NonNull;
import lombok.Value;

import java.security.cert.X509Certificate;

@Value
public class StartResponse {
    @NonNull
    X509Certificate issuerCertificate;
    StoreDataCommand storeDataCommand;
}
