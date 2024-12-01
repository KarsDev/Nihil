package me.kuwg.nihil;

import me.kuwg.nihil.cypher.NihilCypher;
import me.kuwg.nihil.cypher.NihilKey;
import me.kuwg.nihil.cypher.SimpleNihilKey;
import me.kuwg.nihil.cyphers.dshift.SecureDoubleShiftCypher;

public class Test {
    public static void main(final String[] args) {
        final NihilKey key = SimpleNihilKey.random(5000);
        final NihilCypher cypher = new SecureDoubleShiftCypher(key);

        final String input = "x";

        final byte[] output = cypher.encrypt(input);

        System.out.printf("lengths (i/o): %d/%d, output: %s\n", input.getBytes().length, output.length, cypher.decrypt(output, String.class));
    }

}
/*
final NihilKey shiftKey = SimpleNihilKey.random(15);
final NihilKey dshiftKey = SimpleNihilKey.random(15);

final NihilCypher shift = new ShiftCypher(shiftKey);
final NihilCypher dshift = new SecureDoubleShiftCypher(dshiftKey);

final String input = "This is the input!";

final byte[] shiftBytes = shift.encrypt(input);
final byte[] dshiftBytes = dshift.encrypt(shiftBytes);

final byte[] dshiftDBytes = dshift.decrypt(dshiftBytes, byte[].class);
final byte[] shiftDBytes = shift.decrypt(dshiftDBytes, byte[].class);

System.out.println(new String(shiftDBytes)); // BTW this works
*/