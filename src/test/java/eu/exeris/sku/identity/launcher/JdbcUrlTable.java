package eu.exeris.sku.identity.launcher;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * The table of "The JDBC URL rule" in the configuration reference, as data: each row has the parameter names
 * it covers, a grammar written here without any help from {@link JdbcUrl}, values the grammar accepts and
 * values just outside it. The tests read the rule from this table, not from the implementation.
 */
final class JdbcUrlTable {

    /** One row of the table. */
    record Row(List<String> names, Predicate<String> grammar, List<String> valid, List<String> invalid) {
    }

    private static final String NON_ASCII_DIGITS = "١٢";
    private static final String FULL_WIDTH_DIGITS = "１２";
    private static final String THIRTY_DIGITS = "123456789012345678901234567890";

    static final List<Row> ROWS = rows();

    private JdbcUrlTable() {
    }

    /** Every parameter name of the table, in the order of the table. */
    static List<String> names() {
        List<String> names = new ArrayList<>();
        ROWS.forEach(row -> names.addAll(row.names()));
        return names;
    }

    static Map<String, Row> byName() {
        Map<String, Row> map = new LinkedHashMap<>();
        for (Row row : ROWS) {
            row.names().forEach(name -> map.put(name, row));
        }
        return map;
    }

    static boolean asciiDigits(String text) {
        if (text.isEmpty()) {
            return false;
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }

    private static boolean onlyFrom(String text, String allowed) {
        for (int i = 0; i < text.length(); i++) {
            if (allowed.indexOf(text.charAt(i)) < 0) {
                return false;
            }
        }
        return true;
    }

    private static final String LETTERS_DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private static Predicate<String> words(List<String> accepted) {
        return accepted::contains;
    }

    private static Predicate<String> upTo(long maximum) {
        BigInteger limit = BigInteger.valueOf(maximum);
        return value -> asciiDigits(value) && new BigInteger(value).compareTo(limit) <= 0;
    }

    private static List<String> outsideAnInteger(long maximum) {
        return List.of(Long.toString(maximum + 1), Long.toString(maximum * 10), "-1", "-0", "+1", "+0",
                "+" + maximum, "", " ", "1 ", " 1", "1.0", "1e3", "0x10", "0x0", "1_0", "1,0", "--1",
                NON_ASCII_DIGITS, "1" + NON_ASCII_DIGITS, FULL_WIDTH_DIGITS, "ff", "FF", "a", "true", "NaN",
                THIRTY_DIGITS, "9".repeat(30), "999999999", "2147483648", "4294967296", "9223372036854775808");
    }

    private static List<String> integers(long maximum) {
        List<String> valid = new ArrayList<>(List.of("0", "1", "7", "10", "00", "000", "007", "0000001",
                Long.toString(maximum), Long.toString(maximum - 1), "0" + maximum));
        return valid;
    }

    private static List<String> caseVariants(List<String> words) {
        List<String> variants = new ArrayList<>();
        for (String word : words) {
            variants.add(word.toUpperCase(java.util.Locale.ROOT));
            variants.add(Character.toUpperCase(word.charAt(0)) + word.substring(1));
            if (!word.equals(word.toLowerCase(java.util.Locale.ROOT))) {
                variants.add(word.toLowerCase(java.util.Locale.ROOT));
            }
            variants.add(word + " ");
            variants.add(" " + word);
        }
        return variants;
    }

    private static Row words(List<String> names, List<String> accepted, List<String> others) {
        List<String> invalid = new ArrayList<>(caseVariants(accepted));
        invalid.addAll(others);
        invalid.add("");
        invalid.removeIf(accepted::contains);
        return new Row(names, words(accepted), accepted, invalid);
    }

    private static List<Row> rows() {
        List<Row> rows = new ArrayList<>();
        rows.add(words(List.of("ssl", "tcpKeepAlive", "loadBalanceHosts", "reWriteBatchedInserts"),
                List.of("true", "false"),
                List.of("yes", "no", "1", "0", "on", "off", "t", "f", "truee", "tru", "TrUe", "fAlSe", "null")));
        rows.add(words(List.of("sslmode"),
                List.of("disable", "allow", "prefer", "require", "verify-ca", "verify-full"),
                List.of("verify_full", "verifyfull", "verify", "full", "ca", "none", "true", "unknown", "VERIFY-FULL",
                        "Verify-Full", "verify-fullx", "xverify-full", "require,prefer")));
        rows.add(new Row(List.of("connectTimeout", "socketTimeout", "loginTimeout", "cancelSignalTimeout",
                "hostRecheckSeconds"), upTo(86_400), integers(86_400), outsideAnInteger(86_400)));
        rows.add(new Row(List.of("prepareThreshold"), upTo(10_000), integers(10_000), outsideAnInteger(10_000)));
        rows.add(new Row(List.of("defaultRowFetchSize"), upTo(1_000_000), integers(1_000_000),
                outsideAnInteger(1_000_000)));
        rows.add(words(List.of("targetServerType"),
                List.of("any", "primary", "master", "slave", "secondary", "preferSlave", "preferSecondary",
                        "preferPrimary"),
                List.of("prefer_primary", "prefer-primary", "preferprimary", "PREFERPRIMARY", "none", "all",
                        "standby", "replica", "primary,slave")));
        rows.add(new Row(List.of("ApplicationName"), JdbcUrlTable::applicationName,
                List.of("a", "A", "0", ".", "_", "-", "identity-1", "My.App_v-2", "a".repeat(62), "a".repeat(63),
                        "A".repeat(63), "-".repeat(63)),
                applicationNameOutside()));
        rows.add(new Row(List.of("currentSchema"), JdbcUrlTable::currentSchema,
                List.of("public", "a", "_", "1", "123", "A_b9", "a,b", "a,b,c", "_x,Y_,9", "a".repeat(255),
                        ("a".repeat(9) + ",").repeat(25) + "a".repeat(5), "a,".repeat(127) + "a"),
                currentSchemaOutside()));
        rows.add(words(List.of("stringtype"), List.of("unspecified", "varchar"),
                List.of("text", "string", "char", "VARCHAR", "Varchar", "varchar2", "unspecified,varchar")));
        rows.add(new Row(List.of("assumeMinServerVersion"), JdbcUrlTable::version,
                List.of("0", "9", "12", "14.2", "9.6.1", "10.0.0", "012.002", "000000", "999999",
                        "999999.999999.999999", "1.0", "0.0.0"),
                versionOutside()));
        rows.add(words(List.of("gssEncMode"), List.of("disable", "allow", "prefer", "require"),
                List.of("verify-full", "verify-ca", "any", "true", "none")));
        rows.add(words(List.of("channelBinding"), List.of("disable", "prefer", "require"),
                List.of("allow", "verify-full", "any", "true", "none")));
        return List.copyOf(rows);
    }

    private static boolean applicationName(String value) {
        return value.length() >= 1 && value.length() <= 63 && onlyFrom(value, LETTERS_DIGITS + "._-");
    }

    private static List<String> applicationNameOutside() {
        List<String> invalid = new ArrayList<>(List.of("", "a".repeat(64), "a".repeat(65), "a".repeat(200)));
        // one refused character, between allowed ones, of each class
        for (String refused : List.of(" ", "\t", "\n", "\r", "\u0000", "\u0001", "\u001f", "\u007f", "\u0085",
                " ", " ", "　", "/", "\\", ":", ";", "=", "?", "#", "&", "+", "@", "%", "%41", "%2",
                "'", "\"", "`", "<", ">", ",", "*", "!", "$", "(", ")", "[", "]", "{", "}", "|", "^", "~",
                "é", "ß", "日", "١", "Ａ", "😀")) {
            invalid.add("a" + refused + "b");
            invalid.add(refused);
        }
        invalid.add("a ");
        invalid.add(" a");
        invalid.add("a".repeat(62) + "é");
        invalid.add("a".repeat(63) + " ");
        return invalid;
    }

    private static boolean currentSchema(String value) {
        if (value.length() > 255) {
            return false;
        }
        for (String identifier : value.split(",", -1)) {
            if (identifier.isEmpty() || !onlyFrom(identifier, LETTERS_DIGITS + "_")) {
                return false;
            }
        }
        return true;
    }

    private static List<String> currentSchemaOutside() {
        return List.of("", ",", ",,", "a,", ",a", "a,,b", "a,b,", ",a,b", "a, b", "a ,b", " a", "a ", "a b",
                "a-b", "a.b", "a:b", "a;b", "a=b", "a/b", "a\\b", "a'b", "\"public\"", "\"a\"", "$user", "public,$user",
                "a$", "a@b", "a%2Cb", "a%41", "%", "a\tb", "a\nb", "a\u0000b", "é", "café", "日",
                "a b", "a".repeat(256), "a".repeat(300), ("a,").repeat(128) + "a", "a".repeat(255) + ",b",
                "a".repeat(254) + ",", "*", "a*");
    }

    private static boolean version(String value) {
        String[] groups = value.split("\\.", -1);
        if (groups.length < 1 || groups.length > 3) {
            return false;
        }
        for (String group : groups) {
            if (!asciiDigits(group) || group.length() > 6) {
                return false;
            }
        }
        return true;
    }

    private static List<String> versionOutside() {
        return List.of("", ".", "..", "12.", ".12", "1..2", "1.2.", "1.2.3.4", "1.2.3.4.5", "1234567",
                "1234567.1", "1.1234567", "1.2.1234567", "12a", "a12", "v12", "14.2-beta", "14.2beta", "-1", "+1",
                "-1.2", "1.-2", "12 ", " 12", "1. 2", "1,2", "1:2", "1_2", "0x0C", "1e2", NON_ASCII_DIGITS,
                "1." + NON_ASCII_DIGITS, FULL_WIDTH_DIGITS, THIRTY_DIGITS, THIRTY_DIGITS + ".1", "1.2.3a",
                "9".repeat(7), "%31", "1%2E2", "1·2");
    }
}
