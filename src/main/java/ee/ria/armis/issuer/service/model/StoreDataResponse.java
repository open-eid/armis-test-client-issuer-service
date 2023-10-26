package ee.ria.armis.issuer.service.model;

import com.google.protobuf.ByteString;
import lombok.NonNull;
import lombok.Value;

@Value
public class StoreDataResponse {
    int statusWord;
    @NonNull
    ByteString data;
}
