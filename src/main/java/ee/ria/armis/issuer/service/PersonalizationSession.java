package ee.ria.armis.issuer.service;

import com.google.protobuf.ByteString;
import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.HexUtil;
import ee.ria.armis.issuer.service.helpers.Bytes;
import ee.ria.armis.issuer.service.model.StoreDataCommand;
import ee.ria.armis.issuer.service.model.StoreDataResponse;
import ee.ria.armis.issuer.service.securemessaging.SecureMessagingChannel;
import ee.ria.armis.issuer.service.securemessaging.SecureMessagingKeyStore;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.Arrays;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.OptionalInt;

@Slf4j
public class PersonalizationSession {

    private static final byte INS_GET_DATA = (byte) 0xCA;
    private static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;
    private static final byte INS_PUT_DATA = (byte) 0xDA;

    private static final BerTag TAG_TEXT = new BerTag(0x7F, 0x82);

    private static final String TEST_TEXT = "Lorem ipsum gravida.";

    private final SecureMessagingKeyStore secureMessagingKeyStore;
    private final SecureRandom secureRandom;
    private final X509Certificate cardHolderCertificate;
    private final SecureMessagingChannel smChannel;

    private int personalizationCounter = 0;

    public PersonalizationSession(@NonNull SecureMessagingKeyStore secureMessagingKeyStore,
                                  @NonNull SecureRandom secureRandom,
                                  @NonNull X509Certificate cardHolderCertificate) {
        this.secureMessagingKeyStore = secureMessagingKeyStore;
        this.secureRandom = secureRandom;
        this.cardHolderCertificate = cardHolderCertificate;

        // ARMIS server starts personalization session only when cardHolderCertificate is issued by ARMIS CA,
        // cardHolderCertificate's validFrom is not in the future, cardHolderCertificate's validUtil is not in the past,
        // cardHolderCertificate's OCSP check is good (ID-card has not been stolen etc.). Issuer may perform checks of
        // its own if desired.

        // Issuer must take into account that although (cardHolderCertificate's validUtil - currentTime > 0 seconds) was
        // true when ARMIS server started "POST /personalization/start" request, it may become false during that
        // request or subsequent "POST /personalization/continue" requests.

        // Note that cardHolderCertificate's validUntil is the same value as the card's Estonian authentication
        // certificate's validUntil and the card's Estonian signing certificate's validUntil. (This has the same value
        // as card's physical valid until date + 20:59:59 GMT or 21:59:59 GMT.)

        // cardHolderCertificate contains:
        // * Card holder's personal code (e.g. PNOEE-38001085718).
        // * Document number (e.g. NS0010071).
        // * Document type (ID-card / digital-ID / residence permit card / e-resident digi-ID). Although this can
        //   currently be derived from document number, issuer should not duplicate derivation logic themselves and this
        //   may change in the future.

        smChannel = new SecureMessagingChannel(secureMessagingKeyStore, secureRandom, cardHolderCertificate);
    }

    public Optional<StoreDataCommand> startPersonalization() {
        byte[] data = smChannel.internalAuthenticate();
        // Wrap ephemeral public key and signature into a command with INS INTERNAL_AUTHENTICATE
        byte[] appletCommand = buildAppletCommand(INS_INTERNAL_AUTHENTICATE, 0, 0, data);
        log.info("Initial command from issuer {}", HexUtil.toHexString(appletCommand));
        return buildStoreDataCommand(false, true, appletCommand);
    }

    @SneakyThrows
    public Optional<StoreDataCommand> continuePersonalization(StoreDataResponse previousStoreDataResponse) {
        byte[] encryptedResponseData = previousStoreDataResponse.getData().toByteArray();
        int responseSw = previousStoreDataResponse.getStatusWord();

        switch (++personalizationCounter) {
            case 1: {
                log.info("Initial response from applet {}", HexUtil.toHexString(encryptedResponseData));
                assertResponseSuccessful(previousStoreDataResponse);
                smChannel.parseInternalAuthenticateResponseAndPerformKeyAgreement(encryptedResponseData);

                byte[] data = TEST_TEXT.getBytes(StandardCharsets.UTF_8);
                // Wrap data into secure messaging
                byte[] encryptedData = smChannel.wrap(INS_PUT_DATA, data, OptionalInt.empty());
                // Wrap encrypted data into a command with INS PUT_DATA, to store test text in the applet
                byte[] appletCommand = buildAppletCommand(INS_PUT_DATA, TAG_TEXT, encryptedData);
                log.info("Put text command from issuer {}", HexUtil.toHexString(encryptedData));
                return buildStoreDataCommand(false, true, appletCommand);
            }
            case 2: {
                log.info("Put text response from applet {}", HexUtil.toHexString(encryptedResponseData));
                assertResponseSuccessful(previousStoreDataResponse);
                // Unwrap data from secure messaging
                byte[] responseData = smChannel.unwrap(encryptedResponseData, responseSw);
                assertResponseDataEquals(new byte[0], responseData);

                byte[] data = new byte[0];
                // Wrap data into secure messaging
                byte[] encryptedData = smChannel.wrap(INS_GET_DATA, data, OptionalInt.of(0));
                // Wrap encrypted data into a command with INS INS_GET_DATA, to retrieve test text from the applet
                byte[] appletCommand = buildAppletCommand(INS_GET_DATA, TAG_TEXT, encryptedData);
                log.info("Get text command from issuer {}", HexUtil.toHexString(appletCommand));
                return buildStoreDataCommand(true, true, appletCommand);
            }
            case 3: {
                log.info("Get text response from applet {}", HexUtil.toHexString(encryptedResponseData));
                assertResponseSuccessful(previousStoreDataResponse);
                // Unwrap data from secure messaging
                byte[] responseData = smChannel.unwrap(encryptedResponseData, responseSw);
                assertResponseDataEquals(TEST_TEXT.getBytes(StandardCharsets.UTF_8), responseData);

                return Optional.empty();
            }
            default:
                throw new RuntimeException("Issuer finished personalization session, but ARMIS server tried to continue");
        }
    }

    private static byte[] buildAppletCommand(byte ins, int p1, int p2, byte[] data) {
        return buildAppletCommand(ins, (byte) p1, (byte) p2, data);
    }

    private static byte[] buildAppletCommand(byte ins, BerTag p1p2, byte[] data) {
        if (p1p2.bytes.length != 2) {
            throw new IllegalArgumentException("TLV tag with length 2 expected");
        }
        return buildAppletCommand(ins, p1p2.bytes[0], p1p2.bytes[1], data);
    }

    private static byte[] buildAppletCommand(byte ins, byte p1, byte p2, byte[] data) {
        byte[] command = Bytes.asArrayOfLength(4 + data.length, ins, p1, p2, (byte) data.length);
        Bytes.copyIntoArray(command, 4, data);
        return command;
    }

    private static void assertResponseSuccessful(StoreDataResponse storeDataResponse) {
        // If ARMIS server returns StoreDataResponse with statusWord!=0x9000, then issuer service must abort
        // personalization.
        if (storeDataResponse.getStatusWord() != 0x9000) {
            // If issuer service knows why this error might have occurred, it may return a reasonCode which can provide
            // more information to the user.
            Integer reasonCode = null;
            throw new IssuerAbortedPersonalizationException(reasonCode);
        }
    }

    private static void assertResponseDataEquals(byte[] expected, byte[] actual) {
        if (!Arrays.areEqual(expected, actual)) {
            throw new RuntimeException(String.format(
                    "Response mismatch - expected '%s', actual '%s'",
                    HexUtil.toHexString(expected),
                    HexUtil.toHexString(actual)
            ));
        }
    }

    private static Optional<StoreDataCommand> buildStoreDataCommand(boolean last,
                                                                    boolean responseExpected,
                                                                    byte[] appletCommand) {
        return Optional.of(new StoreDataCommand(last, responseExpected, ByteString.copyFrom(appletCommand)));
    }

}
