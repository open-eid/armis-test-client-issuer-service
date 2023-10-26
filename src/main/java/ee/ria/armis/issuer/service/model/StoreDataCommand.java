package ee.ria.armis.issuer.service.model;

import com.google.protobuf.ByteString;
import lombok.NonNull;
import lombok.Value;

@Value
public class StoreDataCommand {
    boolean last;
    boolean responseExpected;
    @NonNull
    ByteString data;
}
